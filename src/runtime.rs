use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock as SyncRwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arcrelay_peer::{
    AuthorizationService, CapabilityId, DeviceId, DevicePublicKey, DeviceSignature, Grant,
    GrantConstraints, GrantDirection, PeerRecord, PeerRepository, PeerService, SigningContext,
    TrustState,
};
use arcrelay_transport::{read_frame, write_frame};
use arcrelay_wire::common;
use bytes::Bytes;
use prost::Message;
use quinn::crypto::rustls::QuicClientConfig;
use rand::RngCore;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, Mutex, OwnedMutexGuard, Semaphore};

use crate::identity::transport_config;
use crate::{
    endpoint::default_endpoint_repository, verify_signature, DeviceIdentity, DeviceMetadata,
    DiscoveryService, EndpointRepository, EndpointSource, NetworkError, PeerAdvertisement,
};

mod diagnostics;
mod dial;
mod protocol;
mod relay;
mod scan;
mod session;

pub use protocol::reserve_udp_socket;
use protocol::*;
pub use scan::LanScanReport;
pub use session::{FeatureStream, Session, SessionPeer};

type SessionKey = (DeviceId, SessionKind);
type SessionDialGate = Arc<Mutex<()>>;

const HANDSHAKE_FRAME_LIMIT: usize = 64 * 1024;
const MAX_RETIRED_PEER_INSTANCES: usize = 32;
const FEATURE_HEADER_LIMIT: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);
const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-ArcRelay-v1-session";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionKind {
    Pairing,
    Control,
    RealtimeInput,
    FileTransfer,
    Print,
    DiscoveryProbe,
}

impl SessionKind {
    fn encode(self) -> i32 {
        match self {
            Self::Pairing => common::SessionKind::Pairing as i32,
            Self::Control => common::SessionKind::Control as i32,
            Self::RealtimeInput => common::SessionKind::RealtimeInput as i32,
            Self::FileTransfer => common::SessionKind::FileTransfer as i32,
            Self::Print => common::SessionKind::Print as i32,
            Self::DiscoveryProbe => common::SessionKind::DiscoveryProbe as i32,
        }
    }

    fn decode(value: i32) -> Result<Self, NetworkError> {
        match common::SessionKind::try_from(value) {
            Ok(common::SessionKind::Pairing) => Ok(Self::Pairing),
            Ok(common::SessionKind::Control) => Ok(Self::Control),
            Ok(common::SessionKind::RealtimeInput) => Ok(Self::RealtimeInput),
            Ok(common::SessionKind::FileTransfer) => Ok(Self::FileTransfer),
            Ok(common::SessionKind::Print) => Ok(Self::Print),
            Ok(common::SessionKind::DiscoveryProbe) => Ok(Self::DiscoveryProbe),
            _ => Err(NetworkError::Protocol("invalid session kind".into())),
        }
    }
}

pub struct NetworkRuntimeConfig {
    pub identity_directory: PathBuf,
    pub metadata: DeviceMetadata,
    pub listen_address: IpAddr,
    pub listen_port: u16,
    pub repository: Arc<dyn PeerRepository>,
    pub endpoint_repository: Arc<dyn EndpointRepository>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingGrantRequest {
    pub capability: CapabilityId,
    /// Direction in the initiating device's local grant repository.
    pub direction: GrantDirection,
    pub constraints: arcrelay_peer::GrantConstraints,
}

impl PairingGrantRequest {
    pub fn outbound(capability: CapabilityId) -> Self {
        Self {
            capability,
            direction: GrantDirection::Outbound,
            constraints: arcrelay_peer::GrantConstraints::None,
        }
    }

    pub fn inbound(capability: CapabilityId) -> Self {
        Self {
            capability,
            direction: GrantDirection::Inbound,
            constraints: arcrelay_peer::GrantConstraints::None,
        }
    }
}

/// An authenticated pairing exchange waiting for the user-visible SAS to be
/// approved on the remote device. It is created and consumed only by the
/// process-wide runtime so features cannot implement private trust stores.
pub struct PendingPairing {
    session: Arc<Session>,
    stream: FeatureStream,
    requested: BTreeMap<(CapabilityId, GrantDirection), arcrelay_peer::GrantConstraints>,
}

impl PendingPairing {
    pub fn peer(&self) -> &SessionPeer {
        self.session.peer()
    }

    pub fn verification_code(&self) -> &str {
        self.session.verification_code()
    }

    pub fn cancel(self, reason: &str) {
        self.session.close(reason);
    }
}

#[derive(Debug, Clone)]
pub struct PairingOutcome {
    pub peer: SessionPeer,
    pub granted: Vec<Grant>,
}

impl NetworkRuntimeConfig {
    pub fn new(
        identity_directory: PathBuf,
        metadata: DeviceMetadata,
        repository: Arc<dyn PeerRepository>,
    ) -> Self {
        Self {
            identity_directory,
            metadata,
            listen_address: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            listen_port: 0,
            repository,
            endpoint_repository: default_endpoint_repository(),
        }
    }
}

/// The process-wide LAN runtime. It owns the advertised QUIC listener,
/// recovery sockets, identity, discovery, trust and live-session registry.
pub struct NetworkRuntime {
    process_instance_id: [u8; 16],
    endpoint: quinn::Endpoint,
    recovery_endpoints: SyncRwLock<Vec<Weak<quinn::Endpoint>>>,
    stopped: AtomicBool,
    relay_capacity: Arc<Semaphore>,
    identity: Arc<DeviceIdentity>,
    metadata: SyncRwLock<DeviceMetadata>,
    repository: Arc<dyn PeerRepository>,
    endpoints: Arc<dyn EndpointRepository>,
    authorization: AuthorizationService,
    peers: PeerService,
    discovery: Arc<DiscoveryService>,
    incoming: broadcast::Sender<Arc<Session>>,
    sessions: Mutex<BTreeMap<SessionKey, ActiveSession>>,
    session_dials: Mutex<HashMap<SessionKey, SessionDialGate>>,
    probe_gate: Arc<Semaphore>,
    handshake_gate: Arc<Semaphore>,
    probe_rates: Mutex<HashMap<IpAddr, ProbeRate>>,
    discoverable: AtomicBool,
    scan_cancelled: AtomicBool,
    scan_state: Mutex<scan::ScanState>,
}

struct ActiveSession {
    peer_process_instance_id: Option<[u8; 16]>,
    retired_peer_instances: VecDeque<[u8; 16]>,
    rank: SessionRank,
    session: Weak<Session>,
    connection: quinn::Connection,
    // Raw transport adapters can outlive the public Session handle. Keep its
    // recovery endpoint registered for process-wide shutdown as well.
    _recovery_endpoint: Option<Arc<quinn::Endpoint>>,
    _relay_tunnel: Option<Arc<relay::RelayTunnel>>,
}

struct ProbeRate {
    window_started: Instant,
    attempts: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SessionRank {
    initiator_id: DeviceId,
    initiator_nonce: Vec<u8>,
}

impl NetworkRuntime {
    pub async fn bind(config: NetworkRuntimeConfig) -> Result<Arc<Self>, NetworkError> {
        let socket = bind_socket(config.listen_address, config.listen_port)?;
        Self::bind_on_socket(config, socket).await
    }

    pub async fn bind_on_socket(
        config: NetworkRuntimeConfig,
        socket: std::net::UdpSocket,
    ) -> Result<Arc<Self>, NetworkError> {
        tokio::runtime::Handle::try_current().map_err(|_| NetworkError::RuntimeUnavailable)?;
        socket.set_nonblocking(true)?;
        let identity = DeviceIdentity::load_or_create(&config.identity_directory)?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(identity.server_config()),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| NetworkError::Quic(error.to_string()))?;
        endpoint.set_default_client_config(client_config()?);
        let port = endpoint
            .local_addr()
            .map_err(|error| NetworkError::Quic(error.to_string()))?
            .port();
        let discovery = DiscoveryService::start(&identity, config.metadata.clone(), port)?;
        let (incoming, _) = broadcast::channel(128);
        let runtime = Arc::new(Self {
            process_instance_id: rand::random(),
            endpoint,
            recovery_endpoints: SyncRwLock::new(Vec::new()),
            stopped: AtomicBool::new(false),
            relay_capacity: Arc::new(Semaphore::new(8)),
            identity,
            metadata: SyncRwLock::new(config.metadata),
            authorization: AuthorizationService::new(config.repository.clone()),
            peers: PeerService::new(config.repository.clone()),
            repository: config.repository,
            endpoints: config.endpoint_repository,
            discovery,
            incoming,
            sessions: Mutex::new(BTreeMap::new()),
            session_dials: Mutex::new(HashMap::new()),
            probe_gate: Arc::new(Semaphore::new(16)),
            handshake_gate: Arc::new(Semaphore::new(32)),
            probe_rates: Mutex::new(HashMap::new()),
            discoverable: AtomicBool::new(true),
            scan_cancelled: AtomicBool::new(false),
            scan_state: Mutex::new(scan::ScanState::default()),
        });
        runtime.start_accept_loop();
        Ok(runtime)
    }

    pub fn device_id(&self) -> DeviceId {
        self.identity.device_id()
    }

    pub fn public_key(&self) -> DevicePublicKey {
        self.identity.public_key_value()
    }

    pub fn certificate_sha256(&self) -> [u8; 32] {
        self.identity.certificate_sha256()
    }

    pub fn sign_feature_payload(&self, message: &[u8]) -> DeviceSignature {
        self.identity.sign(SigningContext::FeaturePayload, message)
    }

    pub fn local_port(&self) -> Result<u16, NetworkError> {
        self.endpoint
            .local_addr()
            .map(|address| address.port())
            .map_err(|error| NetworkError::Quic(error.to_string()))
    }

    pub fn discovery(&self) -> &Arc<DiscoveryService> {
        &self.discovery
    }

    pub fn metadata(&self) -> DeviceMetadata {
        self.metadata
            .read()
            .expect("network metadata lock poisoned")
            .clone()
    }

    /// Updates the metadata attached to this stable device identity and
    /// re-announces the existing unified discovery record.
    pub fn update_metadata(&self, metadata: DeviceMetadata) -> Result<(), NetworkError> {
        self.discovery
            .update_local_metadata(&self.identity, &metadata, self.local_port()?)?;
        *self
            .metadata
            .write()
            .expect("network metadata lock poisoned") = metadata;
        Ok(())
    }

    pub fn set_discoverable(&self, discoverable: bool) {
        self.discoverable.store(discoverable, Ordering::Release);
        if let Err(error) = self.discovery.set_local_published(
            &self.identity,
            &self.metadata(),
            self.local_port().unwrap_or_default(),
            discoverable,
        ) {
            tracing::warn!(%error, "failed to update ArcRelay discovery visibility");
        }
    }

    pub fn is_discoverable(&self) -> bool {
        self.discoverable.load(Ordering::Acquire)
    }

    pub fn cancel_lan_scan(&self) {
        self.scan_cancelled.store(true, Ordering::Release);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Session>> {
        self.incoming.subscribe()
    }

    pub async fn connect(
        self: &Arc<Self>,
        peer: &PeerAdvertisement,
        kind: SessionKind,
    ) -> Result<Arc<Session>, NetworkError> {
        if peer.device_id == self.device_id() {
            return Err(NetworkError::SelfConnection);
        }
        if !matches!(
            kind,
            SessionKind::Pairing | SessionKind::FileTransfer | SessionKind::DiscoveryProbe
        ) {
            self.require_paired(&peer.device_id, Some(&peer.public_key))
                .await?;
        }
        let _dial_guard = self.acquire_session_dial(&peer.device_id, kind).await;
        if let Some(session) = self.active(&peer.device_id, kind).await {
            return Ok(session);
        }
        let fallback_addresses;
        let connection_addresses = if peer.connection_addresses.is_empty() {
            fallback_addresses = peer
                .addresses
                .iter()
                .map(|address| SocketAddr::new(*address, peer.port))
                .collect::<Vec<_>>();
            fallback_addresses.as_slice()
        } else {
            peer.connection_addresses.as_slice()
        };
        self.race_endpoints(
            connection_addresses.to_vec(),
            dial::ExpectedPeer::Advertised(peer.clone()),
            kind,
            EndpointSource::Mdns,
        )
        .await
    }

    pub async fn connect_discovered(
        self: &Arc<Self>,
        peer_id: &DeviceId,
        kind: SessionKind,
    ) -> Result<Arc<Session>, NetworkError> {
        if let Some(peer) = self.discovery.peer(peer_id) {
            return self.connect(&peer, kind).await;
        }
        self.connect_remembered(peer_id, kind).await
    }

    /// Connects to a paired device using recently authenticated endpoints.
    /// Endpoint certificate rotation is accepted only when the new certificate
    /// remains signed by the already-pinned device root key.
    pub async fn connect_remembered(
        self: &Arc<Self>,
        peer_id: &DeviceId,
        kind: SessionKind,
    ) -> Result<Arc<Session>, NetworkError> {
        let peer = self.require_paired(peer_id, None).await?;
        let _dial_guard = self.acquire_session_dial(peer_id, kind).await;
        if let Some(session) = self.active(peer_id, kind).await {
            return Ok(session);
        }
        let endpoints = self.endpoints.endpoints(peer_id).await?;
        if endpoints.is_empty() {
            return Err(NetworkError::Connect(
                "peer has no remembered authenticated endpoint".into(),
            ));
        }
        self.race_endpoints(
            endpoints
                .into_iter()
                .map(|endpoint| endpoint.address)
                .collect(),
            dial::ExpectedPeer::Paired(peer),
            kind,
            EndpointSource::History,
        )
        .await
    }

    /// Connects to a paired device using routes learned over an already
    /// authenticated feature session rather than local multicast discovery.
    /// The target public key always comes from the local pairing repository.
    /// The observed certificate is accepted only when its endpoint
    /// binding is signed by that pinned root key, allowing safe rotation.
    pub async fn connect_paired_at(
        self: &Arc<Self>,
        peer_id: &DeviceId,
        connection_addresses: Vec<SocketAddr>,
        kind: SessionKind,
    ) -> Result<Arc<Session>, NetworkError> {
        let peer = self.require_paired(peer_id, None).await?;
        if connection_addresses.len() > 16 {
            return Err(NetworkError::Protocol(
                "relayed peer route exceeds endpoint limit".into(),
            ));
        }
        let mut connection_addresses = connection_addresses
            .into_iter()
            .filter(|address| {
                address.port() != 0
                    && (!address.ip().is_loopback() || cfg!(test))
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast()
            })
            .collect::<Vec<_>>();
        connection_addresses.sort();
        connection_addresses.dedup();
        if connection_addresses.is_empty() {
            return Err(NetworkError::Connect(
                "relayed peer route has no dialable address".into(),
            ));
        }
        let _dial_guard = self.acquire_session_dial(peer_id, kind).await;
        if let Some(session) = self.active(peer_id, kind).await {
            return Ok(session);
        }
        self.race_endpoints(
            connection_addresses,
            dial::ExpectedPeer::Paired(peer),
            kind,
            EndpointSource::Relayed,
        )
        .await
    }

    /// Resolves a manually supplied host independently of mDNS. When `port`
    /// is `None`, only this one host is tried across ArcRelay's bounded
    /// preferred range (8765 through 8775).
    pub async fn discover_at(
        self: &Arc<Self>,
        host: &str,
        port: Option<u16>,
    ) -> Result<PeerAdvertisement, NetworkError> {
        let host = host.trim();
        if host.is_empty() || host.len() > 253 || host.chars().any(char::is_whitespace) {
            return Err(NetworkError::Connect("invalid manual host".into()));
        }
        let ports = match port {
            Some(0) => return Err(NetworkError::Connect("endpoint port cannot be zero".into())),
            Some(port) => vec![port],
            None => (8765..=8775).collect(),
        };
        let mut endpoints = Vec::new();
        for port in ports {
            let resolved = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::lookup_host((host, port)),
            )
            .await;
            if let Ok(Ok(addresses)) = resolved {
                endpoints.extend(addresses.filter(|address| is_dialable(*address)));
            }
        }
        endpoints.sort();
        endpoints.dedup();
        endpoints.truncate(32);
        if endpoints.is_empty() {
            return Err(NetworkError::Connect(
                "manual host did not resolve to a dialable address".into(),
            ));
        }

        for endpoint in &endpoints {
            if let Some(peer) = self.discovery.snapshot().iter().find(|peer| {
                peer.connection_addresses.contains(endpoint)
                    || (peer.port == endpoint.port() && peer.addresses.contains(&endpoint.ip()))
            }) {
                // The caller selected this host/port. Keep the cached identity
                // but dial that endpoint, not every interface ever discovered
                // for the same device (which can exceed the bounded race).
                let mut selected = peer.clone();
                selected.addresses = vec![endpoint.ip()];
                selected.connection_addresses = vec![*endpoint];
                selected.port = endpoint.port();
                return Ok(selected);
            }
        }

        let mut failures = Vec::new();
        for endpoint in endpoints {
            match self
                .probe_endpoint(endpoint, EndpointSource::Manual, Duration::from_secs(2))
                .await
            {
                Ok(peer) => return Ok(peer),
                Err(error) => failures.push(format!("{endpoint}: {error}")),
            }
        }
        Err(NetworkError::Connect(failures.join("; ")))
    }

    pub(crate) async fn probe_endpoint(
        self: &Arc<Self>,
        remote: SocketAddr,
        source: EndpointSource,
        timeout: Duration,
    ) -> Result<PeerAdvertisement, NetworkError> {
        if !is_dialable(remote) {
            return Err(NetworkError::Connect("endpoint is not dialable".into()));
        }
        let connecting = self
            .endpoint
            .connect(remote, "localhost")
            .map_err(|error| NetworkError::Connect(error.to_string()))?;
        let connection = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|error| NetworkError::Quic(error.to_string()))?;
        let session = tokio::time::timeout(timeout, self.authenticate_outbound_probe(connection))
            .await
            .map_err(|_| NetworkError::Timeout)??;
        let peer = self.remember_authenticated_session(&session, source).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        session.close("discovery probe completed");
        Ok(peer)
    }

    /// Starts the single product-wide pairing protocol. The returned SAS must
    /// be shown to the user before `complete_pairing` is awaited.
    pub async fn begin_pairing(
        self: &Arc<Self>,
        peer: &PeerAdvertisement,
        requested: impl IntoIterator<Item = PairingGrantRequest>,
    ) -> Result<PendingPairing, NetworkError> {
        let mut requested_grants_by_key = BTreeMap::new();
        for request in requested {
            validate_local_grant_request(request.capability, &request.constraints)?;
            if requested_grants_by_key
                .insert((request.capability, request.direction), request.constraints)
                .is_some()
            {
                return Err(NetworkError::Protocol(
                    "duplicate requested pairing grant".into(),
                ));
            }
            if requested_grants_by_key.len() > 64 {
                return Err(NetworkError::Protocol(
                    "too many requested pairing grants".into(),
                ));
            }
        }
        let requested = requested_grants_by_key;
        let session = self.connect(peer, SessionKind::Pairing).await?;
        let mut requested_grants = Vec::with_capacity(requested.len());
        for ((capability, local_direction), constraints) in &requested {
            requested_grants.push(common::CapabilityGrant {
                capability: capability.token().into(),
                direction: match local_direction {
                    GrantDirection::Outbound => common::GrantDirection::Inbound as i32,
                    GrantDirection::Inbound => common::GrantDirection::Outbound as i32,
                },
                constraints: encode_grant_constraints(constraints),
                granted_at_ms: 0,
            });
        }
        let request = common::PairingRequest { requested_grants };
        let stream = session
            .open_feature_stream("arcrelay.pairing", &request.encode_to_vec())
            .await?;
        Ok(PendingPairing {
            session,
            stream,
            requested,
        })
    }

    /// Completes pairing atomically from the caller's perspective. The remote
    /// side may approve any subset of the requested grants; unrequested or
    /// constraint-modified grants are rejected.
    pub async fn complete_pairing(
        &self,
        mut pending: PendingPairing,
        timeout: Duration,
    ) -> Result<PairingOutcome, NetworkError> {
        let bytes = tokio::time::timeout(
            timeout,
            read_frame(
                &mut pending.stream.receive,
                arcrelay_wire::MAX_CONTROL_FRAME_SIZE,
            ),
        )
        .await
        .map_err(|_| NetworkError::Timeout)??;
        let response = common::PairingResponse::decode(bytes.as_slice())
            .map_err(|error| NetworkError::Protocol(error.to_string()))?;
        let result = response
            .result
            .ok_or_else(|| NetworkError::Protocol("pairing result is missing".into()))?;
        if !result.paired || result.peer_id != pending.session.peer.device_id.as_str() {
            pending.session.close("pairing rejected");
            return Err(NetworkError::Protocol(if result.error.is_empty() {
                "pairing rejected".into()
            } else {
                result.error
            }));
        }

        let mut granted = Vec::with_capacity(response.granted_grants.len());
        let mut seen = std::collections::BTreeSet::new();
        for wire in response.granted_grants {
            let capability = CapabilityId::parse_token(&wire.capability).ok_or_else(|| {
                NetworkError::Protocol(format!("unknown granted capability {}", wire.capability))
            })?;
            let local_direction = match common::GrantDirection::try_from(wire.direction) {
                Ok(common::GrantDirection::Inbound) => GrantDirection::Outbound,
                Ok(common::GrantDirection::Outbound) => GrantDirection::Inbound,
                _ => {
                    return Err(NetworkError::Protocol(
                        "invalid pairing grant direction".into(),
                    ))
                }
            };
            if !seen.insert((capability, local_direction)) {
                return Err(NetworkError::Protocol(
                    "invalid or duplicate pairing grant".into(),
                ));
            }
            let expected = pending
                .requested
                .get(&(capability, local_direction))
                .ok_or_else(|| {
                    NetworkError::Protocol("peer returned an unrequested capability".into())
                })?;
            let constraints = decode_grant_constraints(wire.constraints)?;
            if &constraints != expected {
                return Err(NetworkError::Protocol(
                    "peer changed pairing grant constraints".into(),
                ));
            }
            granted.push(Grant {
                peer_id: pending.session.peer.device_id.clone(),
                capability,
                direction: local_direction,
                constraints,
                granted_at_ms: now_ms(),
            });
        }
        self.confirm_pairing_with_grants(&pending.session, granted.clone())
            .await?;
        let peer = pending.session.peer.clone();
        pending.session.close("pairing completed");
        Ok(PairingOutcome { peer, granted })
    }

    pub async fn confirm_pairing(&self, session: &Session) -> Result<(), NetworkError> {
        self.confirm_pairing_with_grants(session, Vec::new()).await
    }

    pub async fn confirm_pairing_with_grants(
        &self,
        session: &Session,
        grants: Vec<Grant>,
    ) -> Result<(), NetworkError> {
        if session.kind != SessionKind::Pairing {
            return Err(NetworkError::Protocol(
                "only a pairing session can establish device trust".into(),
            ));
        }
        if grants
            .iter()
            .any(|grant| grant.peer_id != session.peer.device_id)
        {
            return Err(NetworkError::Protocol(
                "pairing grant belongs to another peer".into(),
            ));
        }
        for grant in &grants {
            validate_local_grant_request(grant.capability, &grant.constraints)?;
        }
        let now = now_ms();
        let existing = self
            .repository
            .grants(&session.peer.device_id)
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))?;
        let grants = existing
            .into_iter()
            .chain(grants)
            .map(|grant| ((grant.capability, grant.direction), grant))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect();
        self.repository
            .save_pairing(
                PeerRecord {
                    device_id: session.peer.device_id.clone(),
                    public_key: session.peer.public_key.clone(),
                    display_name: session.peer.metadata.name.clone(),
                    platform: session.peer.metadata.platform.clone(),
                    model: session.peer.metadata.model.clone(),
                    trust_state: TrustState::Paired,
                    auto_connect: true,
                    paired_at_ms: now,
                    updated_at_ms: now,
                },
                grants,
            )
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))?;
        self.remember_authenticated_session(session, EndpointSource::Inbound)
            .await;
        self.discovery.refresh().await;
        Ok(())
    }

    /// Forgets identity and every grant transactionally, then tears down all
    /// feature sessions so stale authority cannot survive in memory.
    pub async fn forget(&self, peer_id: &DeviceId) -> Result<bool, NetworkError> {
        let forgotten = self
            .peers
            .forget(peer_id)
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))?;
        self.endpoints.forget(peer_id).await?;
        self.discovery.forget_authenticated(peer_id).await;
        let mut sessions = self.sessions.lock().await;
        let keys = sessions
            .keys()
            .filter(|(id, _)| id == peer_id)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(active) = sessions.remove(&key) {
                active.connection.close(403_u32.into(), b"peer forgotten");
            }
        }
        Ok(forgotten)
    }

    pub async fn disconnect(&self, peer_id: &DeviceId, reason: &str) -> usize {
        let mut sessions = self.sessions.lock().await;
        let keys = sessions
            .keys()
            .filter(|(id, _)| id == peer_id)
            .cloned()
            .collect::<Vec<_>>();
        let count = keys.len();
        for key in keys {
            if let Some(active) = sessions.remove(&key) {
                active.connection.close(0_u32.into(), reason.as_bytes());
            }
        }
        count
    }

    pub async fn connected_peers(&self) -> Vec<DeviceId> {
        let sessions = self.sessions.lock().await;
        let mut peers = sessions
            .iter()
            .filter(|(_, active)| active.connection.close_reason().is_none())
            .map(|((id, _), _)| id.clone())
            .collect::<Vec<_>>();
        peers.sort();
        peers.dedup();
        peers
    }

    pub fn shutdown(&self, reason: &str) {
        self.stopped.store(true, Ordering::Release);
        self.endpoint.close(0_u32.into(), reason.as_bytes());
        for endpoint in self
            .recovery_endpoints
            .read()
            .expect("recovery endpoint lock poisoned")
            .iter()
            .filter_map(Weak::upgrade)
        {
            endpoint.close(0_u32.into(), reason.as_bytes());
        }
    }

    pub async fn require(
        &self,
        session: &Session,
        capability: CapabilityId,
    ) -> Result<arcrelay_peer::GrantConstraints, NetworkError> {
        self.authorization
            .require(&session.peer.device_id, capability)
            .await
            .map_err(|error| NetworkError::Unauthorized(error.to_string()))
    }

    /// Returns whether this authenticated session belongs to the currently
    /// paired identity. File-transfer sessions may be unpaired so users can
    /// explicitly approve one-off nearby sends.
    pub async fn is_paired_session(&self, session: &Session) -> Result<bool, NetworkError> {
        match self
            .require_paired(&session.peer.device_id, Some(&session.peer.public_key))
            .await
        {
            Ok(_) => Ok(true),
            Err(NetworkError::Unpaired) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub async fn grants(&self, peer_id: &DeviceId) -> Result<Vec<Grant>, NetworkError> {
        self.repository
            .grants(peer_id)
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))
    }

    pub async fn paired_peers(&self) -> Result<Vec<PeerRecord>, NetworkError> {
        self.repository
            .peers()
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))
    }

    /// Updates the local automatic-dial preference for one paired device.
    /// Existing sessions remain connected; the preference applies to future
    /// background connection attempts.
    pub async fn set_peer_auto_connect(
        &self,
        peer_id: &DeviceId,
        enabled: bool,
    ) -> Result<bool, NetworkError> {
        let Some(mut peer) = self
            .repository
            .peer(peer_id)
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))?
        else {
            return Ok(false);
        };
        if peer.trust_state != TrustState::Paired {
            return Ok(false);
        }
        peer.auto_connect = enabled;
        peer.updated_at_ms = now_ms();
        self.repository
            .save_peer(peer)
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))?;
        Ok(true)
    }

    pub async fn remembered_peer(
        &self,
        peer_id: &DeviceId,
    ) -> Result<Option<PeerAdvertisement>, NetworkError> {
        let peer = self.require_paired(peer_id, None).await?;
        let endpoints = self.endpoints.endpoints(peer_id).await?;
        let Some(primary) = endpoints.first() else {
            return Ok(None);
        };
        let connection_addresses = endpoints
            .iter()
            .map(|endpoint| endpoint.address)
            .collect::<Vec<_>>();
        let mut addresses = connection_addresses
            .iter()
            .map(SocketAddr::ip)
            .collect::<Vec<_>>();
        addresses.sort();
        addresses.dedup();
        Ok(Some(PeerAdvertisement {
            device_id: peer.device_id,
            public_key: peer.public_key,
            metadata: DeviceMetadata {
                name: peer.display_name,
                platform: peer.platform,
                model: peer.model,
            },
            addresses,
            connection_addresses,
            port: primary.address.port(),
            certificate_sha256: primary.certificate_sha256,
            last_seen_at_ms: primary.last_seen_at_ms,
        }))
    }

    pub async fn grant(&self, grant: Grant) -> Result<(), NetworkError> {
        validate_local_grant_request(grant.capability, &grant.constraints)?;
        let peer_id = grant.peer_id.clone();
        let capability = grant.capability;
        self.peers
            .grant(grant)
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))?;
        // Existing sessions carry an authorization snapshot from their
        // welcome. Reconnect so both privilege additions and reductions take
        // effect at one well-defined epoch.
        if capability == CapabilityId::CrossScreenInject {
            // Cross-screen authorization is consumed only by RealtimeInput.
            // Enabling a receiver must not interrupt an independent Control
            // connection, including one still completing its welcome.
            if let Some(active) = self
                .sessions
                .lock()
                .await
                .remove(&(peer_id, SessionKind::RealtimeInput))
            {
                active
                    .connection
                    .close(0_u32.into(), b"authorization changed");
            }
        } else {
            self.disconnect(&peer_id, "authorization changed").await;
        }
        Ok(())
    }

    pub async fn revoke(
        &self,
        peer_id: &DeviceId,
        capability: CapabilityId,
        direction: GrantDirection,
    ) -> Result<bool, NetworkError> {
        let revoked = self
            .repository
            .revoke_grant(peer_id, capability, direction)
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))?;
        if revoked {
            // Session-level authorization is snapshotted during feature
            // negotiation. Tear down every peer session so a revoked grant
            // cannot remain usable until an arbitrary reconnect.
            self.disconnect(peer_id, "authorization changed").await;
        }
        Ok(revoked)
    }

    async fn remember_authenticated_session(
        &self,
        session: &Session,
        source: EndpointSource,
    ) -> PeerAdvertisement {
        let remote = session.connection.remote_address();
        let advertised_port = session.peer.listen_port;
        let dial_address = SocketAddr::new(
            remote.ip(),
            if advertised_port == 0 {
                remote.port()
            } else {
                advertised_port
            },
        );
        let peer = PeerAdvertisement {
            device_id: session.peer.device_id.clone(),
            public_key: session.peer.public_key.clone(),
            metadata: session.peer.metadata.clone(),
            addresses: vec![remote.ip()],
            connection_addresses: vec![dial_address],
            port: dial_address.port(),
            certificate_sha256: session.peer.certificate_sha256,
            last_seen_at_ms: now_ms(),
        };
        self.discovery.observe_authenticated(peer.clone()).await;
        if self
            .require_paired(&session.peer.device_id, Some(&session.peer.public_key))
            .await
            .is_ok()
        {
            if let Err(error) = self
                .endpoints
                .record_authenticated(
                    &session.peer.device_id,
                    dial_address,
                    session.peer.certificate_sha256,
                    source,
                )
                .await
            {
                tracing::warn!(
                    event = "network.endpoint_remember_failed",
                    address_family = if remote.is_ipv4() { "ipv4" } else { "ipv6" },
                    %error,
                    "failed to remember authenticated peer endpoint"
                );
            }
        }
        peer
    }

    async fn admit_discovery_probe(&self, source: IpAddr) -> Result<(), NetworkError> {
        const WINDOW: Duration = Duration::from_secs(10);
        const MAX_ATTEMPTS: u8 = 4;
        let now = Instant::now();
        let mut rates = self.probe_rates.lock().await;
        if rates.len() > 512 {
            rates.retain(|_, rate| {
                now.duration_since(rate.window_started) < Duration::from_secs(60)
            });
        }
        let rate = rates.entry(source).or_insert(ProbeRate {
            window_started: now,
            attempts: 0,
        });
        if now.duration_since(rate.window_started) >= WINDOW {
            rate.window_started = now;
            rate.attempts = 0;
        }
        if rate.attempts >= MAX_ATTEMPTS {
            return Err(NetworkError::Busy(
                "discovery probe source is rate limited".into(),
            ));
        }
        rate.attempts += 1;
        Ok(())
    }

    async fn active(&self, id: &DeviceId, kind: SessionKind) -> Option<Arc<Session>> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get(&(id.clone(), kind))
            .and_then(|active| active.session.upgrade())
            .filter(|session| session.connection.close_reason().is_none());
        if session.is_none() {
            sessions.remove(&(id.clone(), kind));
        }
        session
    }

    async fn acquire_session_dial(&self, id: &DeviceId, kind: SessionKind) -> OwnedMutexGuard<()> {
        let gate = {
            let mut gates = self.session_dials.lock().await;
            gates
                .entry((id.clone(), kind))
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        gate.lock_owned().await
    }

    fn start_accept_loop(self: &Arc<Self>) {
        let runtime = Arc::downgrade(self);
        let endpoint = self.endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Some(runtime) = runtime.upgrade() else {
                    break;
                };
                let attempt_id = rand::random::<u64>();
                let remote = incoming.remote_address();
                let remote_id = diagnostics::endpoint_id(remote);
                tracing::debug!(event = "network.accept.started", attempt_id,
                    endpoint_id = %remote_id, address_family = diagnostics::address_family(remote),
                    scope_id = diagnostics::scope_id(remote),
                    "received inbound QUIC attempt");
                let Ok(handshake_permit) = runtime.handshake_gate.clone().try_acquire_owned()
                else {
                    tracing::warn!(
                        event = "network.handshake_overloaded",
                        attempt_id, endpoint_id = %remote_id,
                        "rejected inbound handshake at capacity"
                    );
                    continue;
                };
                tokio::spawn(async move {
                    let _handshake_permit = handshake_permit;
                    let started = Instant::now();
                    let mut phase = "quic_handshake";
                    let mut quic_failure = None;
                    let result = async {
                        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming)
                            .await
                            .map_err(|_| NetworkError::Timeout)?
                            .map_err(|error| {
                                quic_failure = Some(diagnostics::quic_failure_kind(&error));
                                NetworkError::Quic(error.to_string())
                            })?;
                        tracing::debug!(event = "network.accept.quic_established", attempt_id,
                            endpoint_id = %remote_id,
                            local_address_id = ?connection.local_ip().map(|ip| diagnostics::diagnostic_id(&ip.to_canonical().to_string())),
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "inbound QUIC handshake completed");
                        phase = "peer_authentication";
                        let inbound = tokio::time::timeout(
                            HANDSHAKE_TIMEOUT,
                            runtime.authenticate_inbound(connection),
                        )
                        .await
                        .map_err(|_| NetworkError::Timeout)??;
                        tracing::debug!(event = "network.accept.authenticated", attempt_id,
                            endpoint_id = %remote_id, session_id = inbound.id(),
                            session_kind = ?inbound.kind(),
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "inbound peer authentication completed");
                        phase = "session_registration";
                        runtime
                            .remember_authenticated_session(&inbound, EndpointSource::Inbound)
                            .await;
                        if inbound.kind() == SessionKind::DiscoveryProbe {
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                inbound.close("discovery probe completed");
                            });
                            return Ok(());
                        }
                        let session = runtime.register_session(inbound.clone()).await?;
                        // A simultaneous outbound session may already have won
                        // deterministic de-duplication. Do not publish that
                        // locally initiated winner as a new inbound session.
                        if Arc::ptr_eq(&session, &inbound)
                            && runtime.incoming.send(session.clone()).is_err()
                        {
                            tracing::warn!(
                                event = "network.session_unhandled",
                                session_kind = ?session.kind(),
                                "closing authenticated session because no feature service is subscribed"
                            );
                            session.close("feature service unavailable");
                        }
                        Ok::<_, NetworkError>(())
                    }
                    .await;
                    if let Err(error) = result {
                        tracing::warn!(event = "network.accept.failed", attempt_id,
                            endpoint_id = %remote_id, phase, quic_failure, error_code = error.code(),
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "rejected ArcRelay v1 session");
                    }
                });
            }
        });
    }

    async fn authenticate_outbound(
        self: &Arc<Self>,
        connection: quinn::Connection,
        expected: &PeerAdvertisement,
        kind: SessionKind,
        selection: Arc<Semaphore>,
    ) -> Result<Arc<Session>, NetworkError> {
        let observed = observed_certificate_sha256(&connection)?;
        if observed != expected.certificate_sha256 {
            return Err(NetworkError::InvalidIdentity(
                "TLS certificate differs from discovery advertisement".into(),
            ));
        }
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::Quic(error.to_string()))?;
        let local = self.local_hello(kind);
        send_message(&mut send, &local).await?;
        let remote: common::SessionHello = receive_message(&mut receive).await?;
        let remote_identity = validate_hello(&remote, Some(kind))?;
        if remote_identity.certificate_sha256 != observed {
            return Err(NetworkError::InvalidIdentity(
                "TLS certificate differs from authenticated endpoint binding".into(),
            ));
        }
        if remote_identity.device_id != expected.device_id
            || remote_identity.public_key != expected.public_key
            || remote_identity.certificate_sha256 != expected.certificate_sha256
        {
            return Err(NetworkError::InvalidIdentity(
                "authenticated identity differs from discovery advertisement".into(),
            ));
        }
        self.finish_authentication(
            connection,
            send,
            receive,
            local,
            remote,
            remote_identity,
            Direction::Outbound,
            Some(selection),
        )
        .await
    }

    async fn authenticate_outbound_paired(
        self: &Arc<Self>,
        connection: quinn::Connection,
        expected: &PeerRecord,
        kind: SessionKind,
        selection: Arc<Semaphore>,
    ) -> Result<Arc<Session>, NetworkError> {
        let observed = observed_certificate_sha256(&connection)?;
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::Quic(error.to_string()))?;
        let local = self.local_hello(kind);
        send_message(&mut send, &local).await?;
        let remote: common::SessionHello = receive_message(&mut receive).await?;
        let remote_identity = validate_hello(&remote, Some(kind))?;
        if remote_identity.certificate_sha256 != observed
            || remote_identity.device_id != expected.device_id
            || remote_identity.public_key != expected.public_key
        {
            return Err(NetworkError::InvalidIdentity(
                "remembered endpoint belongs to another device".into(),
            ));
        }
        self.finish_authentication(
            connection,
            send,
            receive,
            local,
            remote,
            remote_identity,
            Direction::Outbound,
            Some(selection),
        )
        .await
    }

    async fn authenticate_outbound_probe(
        self: &Arc<Self>,
        connection: quinn::Connection,
    ) -> Result<Arc<Session>, NetworkError> {
        let observed = observed_certificate_sha256(&connection)?;
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::Quic(error.to_string()))?;
        let local = self.local_hello(SessionKind::DiscoveryProbe);
        send_message(&mut send, &local).await?;
        let remote: common::SessionHello = receive_message(&mut receive).await?;
        let remote_identity = validate_hello(&remote, Some(SessionKind::DiscoveryProbe))?;
        if remote_identity.certificate_sha256 != observed {
            return Err(NetworkError::InvalidIdentity(
                "TLS certificate differs from authenticated endpoint binding".into(),
            ));
        }
        self.finish_authentication(
            connection,
            send,
            receive,
            local,
            remote,
            remote_identity,
            Direction::Outbound,
            None,
        )
        .await
    }

    async fn authenticate_inbound(
        self: &Arc<Self>,
        connection: quinn::Connection,
    ) -> Result<Arc<Session>, NetworkError> {
        let remote_address = connection.remote_address();
        let (mut send, mut receive) = connection
            .accept_bi()
            .await
            .map_err(|error| NetworkError::Quic(error.to_string()))?;
        let remote: common::SessionHello = receive_message(&mut receive).await?;
        let kind = SessionKind::decode(remote.session_kind)?;
        let remote_identity = validate_hello(&remote, Some(kind))?;
        let paired = self
            .require_paired(
                &remote_identity.device_id,
                Some(&remote_identity.public_key),
            )
            .await
            .is_ok();
        if !self.is_discoverable()
            && !paired
            && matches!(
                kind,
                SessionKind::Pairing | SessionKind::FileTransfer | SessionKind::DiscoveryProbe
            )
        {
            return Err(NetworkError::Unauthorized(
                "device is not accepting new nearby connections".into(),
            ));
        }
        let _probe_permit = if kind == SessionKind::DiscoveryProbe {
            self.admit_discovery_probe(remote_address.ip()).await?;
            let permit = self
                .probe_gate
                .clone()
                .try_acquire_owned()
                .map_err(|_| NetworkError::Busy("discovery probe limit reached".into()))?;
            Some(permit)
        } else {
            None
        };
        let local = self.local_hello(kind);
        send_message(&mut send, &local).await?;
        self.finish_authentication(
            connection,
            send,
            receive,
            local,
            remote,
            remote_identity,
            Direction::Inbound,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_authentication(
        self: &Arc<Self>,
        connection: quinn::Connection,
        mut send: quinn::SendStream,
        mut receive: quinn::RecvStream,
        local: common::SessionHello,
        remote: common::SessionHello,
        mut peer: SessionPeer,
        direction: Direction,
        selection: Option<Arc<Semaphore>>,
    ) -> Result<Arc<Session>, NetworkError> {
        if peer.device_id == self.device_id() {
            return Err(NetworkError::SelfConnection);
        }
        let kind = SessionKind::decode(remote.session_kind)?;
        let protocol_minor = negotiate_protocol_minor(&local, &remote)?;
        let transcript = session_transcript(&connection, &local, &remote)?;
        let signature = self
            .identity
            .sign(SigningContext::SessionAuthentication, &transcript);
        send_message(
            &mut send,
            &common::SessionAuth {
                device_id: self.device_id().to_string(),
                signature: signature.as_bytes().to_vec().into(),
            },
        )
        .await?;
        let remote_auth: common::SessionAuth = receive_message(&mut receive).await?;
        if remote_auth.device_id != peer.device_id.as_str() {
            return Err(NetworkError::InvalidIdentity(
                "session auth device id mismatch".into(),
            ));
        }
        let signature = DeviceSignature::from_bytes(remote_auth.signature.to_vec())
            .map_err(|error| NetworkError::InvalidIdentity(error.to_string()))?;
        verify_signature(
            &peer.public_key,
            SigningContext::SessionAuthentication,
            &transcript,
            &signature,
        )?;
        if !matches!(
            kind,
            SessionKind::Pairing | SessionKind::FileTransfer | SessionKind::DiscoveryProbe
        ) {
            self.require_paired(&peer.device_id, Some(&peer.public_key))
                .await?;
        }
        // Candidates race through cryptographic verification. Only one may
        // confirm a session, so remote duplicate arbitration cannot replace the
        // winner with a slower candidate which the dialer is about to cancel.
        let dial_selection = match selection {
            Some(selection) => Some(
                selection
                    .acquire_owned()
                    .await
                    .map_err(|_| NetworkError::Timeout)?,
            ),
            None => None,
        };
        let accepted = common::SessionAccepted {
            session_id: random_nonzero_u64(),
            accepted_at_ms: now_ms(),
            listen_port: self.local_port().unwrap_or_default() as u32,
            protocol_minor,
            process_instance_id: self.process_instance_id.to_vec(),
        };
        send_message(&mut send, &accepted).await?;
        let remote_accepted: common::SessionAccepted = receive_message(&mut receive).await?;
        if remote_accepted.session_id == 0 || remote_accepted.accepted_at_ms <= 0 {
            return Err(NetworkError::Protocol("invalid remote session id".into()));
        }
        if remote_accepted.protocol_minor != protocol_minor {
            return Err(NetworkError::Protocol(
                "peer selected a different protocol minor version".into(),
            ));
        }
        let peer_process_instance_id =
            validate_process_instance_id(&remote_accepted.process_instance_id)?;
        peer.listen_port = u16::try_from(remote_accepted.listen_port).unwrap_or_default();
        send.finish()
            .map_err(|error| NetworkError::Quic(error.to_string()))?;
        let code = verification_code(&transcript);
        let rank = match direction {
            Direction::Outbound => SessionRank {
                initiator_id: self.device_id(),
                initiator_nonce: local.nonce.to_vec(),
            },
            Direction::Inbound => SessionRank {
                initiator_id: peer.device_id.clone(),
                initiator_nonce: remote.nonce.to_vec(),
            },
        };
        Ok(Arc::new(Session {
            peer_process_instance_id,
            pending_headers: tokio::sync::Mutex::new(tokio::task::JoinSet::new()),
            recovery_endpoint: std::sync::OnceLock::new(),
            relay_tunnel: std::sync::OnceLock::new(),
            _dial_selection: dial_selection,
            id: accepted.session_id,
            kind,
            peer,
            verification_code: code,
            rank,
            connection,
            protocol_minor,
        }))
    }

    async fn require_paired(
        &self,
        id: &DeviceId,
        key: Option<&DevicePublicKey>,
    ) -> Result<PeerRecord, NetworkError> {
        let peer = self
            .repository
            .peer(id)
            .await
            .map_err(|error| NetworkError::Repository(error.to_string()))?
            .filter(|peer| peer.trust_state == TrustState::Paired)
            .ok_or(NetworkError::Unpaired)?;
        if key.is_some_and(|key| key != &peer.public_key) {
            return Err(NetworkError::InvalidIdentity(
                "paired device key changed".into(),
            ));
        }
        Ok(peer)
    }

    async fn register_session(&self, session: Arc<Session>) -> Result<Arc<Session>, NetworkError> {
        let mut sessions = self.sessions.lock().await;
        let key = (session.peer.device_id.clone(), session.kind);
        let mut retired_peer_instances = VecDeque::new();
        if let Some(current) = sessions.get(&key) {
            retired_peer_instances = current.retired_peer_instances.clone();
            if session
                .peer_process_instance_id
                .is_some_and(|instance| retired_peer_instances.contains(&instance))
            {
                session
                    .connection
                    .close(409_u32.into(), b"obsolete peer process instance");
                return current
                    .session
                    .upgrade()
                    .filter(|active| active.connection.close_reason().is_none())
                    .ok_or_else(|| NetworkError::Connect("obsolete peer process instance".into()));
            }
            if let (Some(previous), Some(incoming)) = (
                current.peer_process_instance_id,
                session.peer_process_instance_id,
            ) {
                if previous != incoming {
                    // An authenticated new process cannot use the retained
                    // transport, regardless of who originally initiated it.
                    // Remember retired processes so a delayed old handshake
                    // cannot take the replacement session back.
                    retired_peer_instances.push_back(previous);
                    while retired_peer_instances.len() > MAX_RETIRED_PEER_INSTANCES {
                        retired_peer_instances.pop_front();
                    }
                    current
                        .connection
                        .close(409_u32.into(), b"peer process restarted");
                    tracing::info!(event = "network.session_peer_restarted",
                        peer_id = %diagnostics::diagnostic_id(session.peer.device_id.as_str()),
                        session_kind = ?session.kind,
                        "retired an old peer process session after authenticated restart");
                }
            }
            if let Some(active) = current.session.upgrade() {
                if Arc::ptr_eq(&active, &session) {
                    return Ok(active);
                }
                // Use deterministic rank only for competing dial directions. A
                // fresh authenticated session from the same initiator is a
                // reconnect: after a crash the old transport may look alive
                // until QUIC times out. Local dial gates and candidate selection
                // already prevent concurrent same-initiator duplicates.
                let same_initiator = current.rank.initiator_id == session.rank.initiator_id;
                // A new connection from the same source remains a reconnect,
                // including a restarted process recovering through a relay.
                let keep_direct = !same_initiator && !active.is_relayed() && session.is_relayed();
                let prefer_direct = active.is_relayed() && !session.is_relayed();
                if active.connection.close_reason().is_none()
                    && (keep_direct
                        || (!prefer_direct && !same_initiator && current.rank <= session.rank))
                {
                    tracing::debug!(
                        event = "network.session_duplicate_rejected",
                        session_kind = ?session.kind,
                        reason = if keep_direct { "prefer_direct" } else { "deterministic_rank" },
                        "kept the deterministic existing session"
                    );
                    session
                        .connection
                        .close(409_u32.into(), b"duplicate session");
                    return Ok(active);
                }
                if active.connection.close_reason().is_none() {
                    tracing::debug!(
                        event = "network.session_replaced",
                        session_kind = ?session.kind,
                        replacement_reason = if prefer_direct {
                            "direct_path_available"
                        } else if same_initiator {
                            "same_initiator_reconnect"
                        } else {
                            "deterministic_rank"
                        },
                        "replaced the existing session with an authenticated successor"
                    );
                    current
                        .connection
                        .close(409_u32.into(), b"session replaced");
                }
            }
        }
        sessions.insert(
            key,
            ActiveSession {
                peer_process_instance_id: session.peer_process_instance_id,
                retired_peer_instances,
                rank: session.rank.clone(),
                session: Arc::downgrade(&session),
                connection: session.connection.clone(),
                _recovery_endpoint: session.recovery_endpoint.get().cloned(),
                _relay_tunnel: session.relay_tunnel.get().cloned(),
            },
        );
        Ok(session)
    }

    fn local_hello(&self, kind: SessionKind) -> common::SessionHello {
        let mut nonce = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let metadata = self.metadata();
        common::SessionHello {
            protocol_major: arcrelay_wire::PROTOCOL_MAJOR,
            session_kind: kind.encode(),
            device_id: self.device_id().to_string(),
            device_name: metadata.name,
            platform: metadata.platform,
            model: metadata.model,
            nonce: nonce.to_vec().into(),
            root_public_key: self.identity.public_key_value().as_bytes().to_vec().into(),
            endpoint_certificate_sha256: self.identity.certificate_sha256().to_vec().into(),
            endpoint_binding_signature: self
                .identity
                .endpoint_binding_signature()
                .as_bytes()
                .to_vec()
                .into(),
            min_protocol_minor: arcrelay_wire::MIN_PROTOCOL_MINOR,
            max_protocol_minor: arcrelay_wire::MAX_PROTOCOL_MINOR,
        }
    }
}

fn encode_grant_constraints(constraints: &GrantConstraints) -> Option<common::GrantConstraints> {
    let kind = match constraints {
        GrantConstraints::None => return None,
        GrantConstraints::RemoteFileShares {
            share_ids,
            writable,
        } => {
            common::grant_constraints::Kind::RemoteFileShares(common::RemoteFileShareConstraints {
                share_ids: share_ids.clone(),
                writable: *writable,
            })
        }
    };
    Some(common::GrantConstraints { kind: Some(kind) })
}

fn validate_local_grant_request(
    capability: CapabilityId,
    constraints: &GrantConstraints,
) -> Result<(), NetworkError> {
    let GrantConstraints::RemoteFileShares {
        share_ids,
        writable,
    } = constraints
    else {
        return Ok(());
    };
    let mut unique = share_ids.clone();
    unique.sort();
    unique.dedup();
    if !matches!(
        capability,
        CapabilityId::RemoteFilesRead | CapabilityId::RemoteFilesWrite
    ) || (capability == CapabilityId::RemoteFilesRead && *writable)
        || (capability == CapabilityId::RemoteFilesWrite && !writable)
        || share_ids.len() > 128
        || unique.len() != share_ids.len()
        || share_ids.iter().any(|id| id.is_empty() || id.len() > 256)
    {
        return Err(NetworkError::Protocol(
            "invalid requested grant constraints".into(),
        ));
    }
    Ok(())
}

fn decode_grant_constraints(
    constraints: Option<common::GrantConstraints>,
) -> Result<GrantConstraints, NetworkError> {
    match constraints {
        None => Ok(GrantConstraints::None),
        Some(common::GrantConstraints { kind: None }) => Err(NetworkError::Protocol(
            "unknown or empty grant constraints".into(),
        )),
        Some(common::GrantConstraints {
            kind: Some(common::grant_constraints::Kind::RemoteFileShares(constraints)),
        }) => {
            if constraints.share_ids.len() > 128
                || constraints
                    .share_ids
                    .iter()
                    .any(|id| id.is_empty() || id.len() > 256)
            {
                return Err(NetworkError::Protocol(
                    "invalid remote-file grant constraints".into(),
                ));
            }
            let mut unique = constraints.share_ids.clone();
            unique.sort();
            unique.dedup();
            if unique.len() != constraints.share_ids.len() {
                return Err(NetworkError::Protocol(
                    "duplicate remote-file share constraint".into(),
                ));
            }
            Ok(GrantConstraints::RemoteFileShares {
                share_ids: constraints.share_ids,
                writable: constraints.writable,
            })
        }
    }
}

fn is_dialable(address: SocketAddr) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && (!address.ip().is_loopback() || cfg!(test))
}

#[cfg(test)]
mod tests;
