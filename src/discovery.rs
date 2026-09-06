use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arcrelay_peer::{DeviceId, DevicePublicKey};
use base64::Engine as _;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::{watch, Mutex, RwLock};

use crate::{DeviceIdentity, NetworkError};

pub const WEB_DISCOVERY_SERVICE_TYPE: &str = "_arcrelay-web._tcp.local.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMetadata {
    pub name: String,
    pub platform: String,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAdvertisement {
    pub device_id: DeviceId,
    pub public_key: DevicePublicKey,
    pub metadata: DeviceMetadata,
    pub addresses: Vec<IpAddr>,
    /// Dialable forms of `addresses`. IPv6 link-local entries retain the
    /// interface index learned from mDNS; an unscoped `fe80::/10` address is
    /// not routable on hosts with more than one network interface.
    pub connection_addresses: Vec<SocketAddr>,
    pub port: u16,
    pub certificate_sha256: [u8; 32],
    pub last_seen_at_ms: i64,
}

/// Process-wide DNS-SD owner. Features only observe this registry and never
/// create their own advertiser or browser.
pub struct DiscoveryService {
    daemon: ServiceDaemon,
    local_id: DeviceId,
    fullname: String,
    hostname: String,
    web_fullname: std::sync::Mutex<Option<String>>,
    local_published: AtomicBool,
    mdns_peers: RwLock<HashMap<DeviceId, PeerAdvertisement>>,
    authenticated_peers: RwLock<HashMap<DeviceId, PeerAdvertisement>>,
    service_ids: Mutex<HashMap<String, DeviceId>>,
    snapshot: watch::Sender<Arc<Vec<PeerAdvertisement>>>,
}

impl DiscoveryService {
    pub fn start(
        identity: &DeviceIdentity,
        metadata: DeviceMetadata,
        port: u16,
    ) -> Result<Arc<Self>, NetworkError> {
        let daemon = ServiceDaemon::new().map_err(discovery_error)?;
        let id = identity.device_id();
        let info = service_info(identity, &metadata, port)?;
        let fullname = info.get_fullname().to_string();
        let hostname = device_hostname(&id);
        daemon.register(info).map_err(discovery_error)?;
        let browser = daemon
            .browse(arcrelay_wire::DISCOVERY_SERVICE_TYPE)
            .map_err(discovery_error)?;
        let (snapshot, _) = watch::channel(Arc::new(Vec::new()));
        let service = Arc::new(Self {
            daemon,
            local_id: id,
            fullname,
            hostname,
            web_fullname: std::sync::Mutex::new(None),
            local_published: AtomicBool::new(true),
            mdns_peers: RwLock::new(HashMap::new()),
            authenticated_peers: RwLock::new(HashMap::new()),
            service_ids: Mutex::new(HashMap::new()),
            snapshot,
        });
        let weak = Arc::downgrade(&service);
        tokio::spawn(async move {
            while let Ok(event) = browser.recv_async().await {
                let Some(service) = weak.upgrade() else { break };
                match event {
                    ServiceEvent::ServiceResolved(info) => service.resolve(&info).await,
                    ServiceEvent::ServiceRemoved(_, fullname) => service.remove(&fullname).await,
                    _ => {}
                }
            }
        });
        Ok(service)
    }

    pub fn subscribe(&self) -> watch::Receiver<Arc<Vec<PeerAdvertisement>>> {
        self.snapshot.subscribe()
    }

    pub fn snapshot(&self) -> Arc<Vec<PeerAdvertisement>> {
        self.snapshot.borrow().clone()
    }

    pub fn local_hostname(&self) -> &str {
        &self.hostname
    }

    /// Publishes the Web Gateway through the process-wide DNS-SD daemon. This
    /// keeps mDNS ownership inside arcrelay-network while the TCP listener stays
    /// isolated from the paired-device QUIC endpoint.
    pub fn publish_web_gateway(&self, site_name: &str, port: u16) -> Result<(), NetworkError> {
        if port == 0 {
            return Err(NetworkError::Discovery(
                "web gateway port cannot be zero".into(),
            ));
        }
        self.unpublish_web_gateway();
        let suffix = self.local_id.as_str().trim_start_matches("arc-");
        let mut properties = HashMap::new();
        properties.insert("feature".to_string(), "files".to_string());
        properties.insert("site_name".to_string(), site_name.to_string());
        properties.insert("version".to_string(), "1".to_string());
        let info = ServiceInfo::new(
            WEB_DISCOVERY_SERVICE_TYPE,
            &format!("arc-web-{}", &suffix[..suffix.len().min(20)]),
            &format!("{}.", self.hostname),
            "",
            port,
            properties,
        )
        .map(ServiceInfo::enable_addr_auto)
        .map_err(discovery_error)?;
        let fullname = info.get_fullname().to_string();
        self.daemon.register(info).map_err(discovery_error)?;
        *self
            .web_fullname
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fullname);
        Ok(())
    }

    pub fn unpublish_web_gateway(&self) {
        if let Some(fullname) = self
            .web_fullname
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = self.daemon.unregister(&fullname);
        }
    }

    pub fn peer(&self, id: &DeviceId) -> Option<PeerAdvertisement> {
        self.snapshot
            .borrow()
            .iter()
            .find(|peer| &peer.device_id == id)
            .cloned()
    }

    /// Adds an endpoint learned from an authenticated QUIC exchange. This is
    /// deliberately separate from mDNS so removing a multicast service record
    /// cannot erase a still-useful direct route.
    pub async fn observe_authenticated(&self, peer: PeerAdvertisement) {
        if peer.device_id == self.local_id {
            return;
        }
        let changed = {
            let mut peers = self.authenticated_peers.write().await;
            merge_observed_peer(&mut peers, peer)
        };
        if changed {
            self.emit().await;
        }
    }

    pub async fn forget_authenticated(&self, id: &DeviceId) {
        if self.authenticated_peers.write().await.remove(id).is_some() {
            self.emit().await;
        }
    }

    /// Re-publishes the current device snapshot after trust metadata changes.
    /// The routes themselves may be unchanged, but consumers such as Nearby
    /// Transfer must re-evaluate whether an observed identity is now paired.
    pub async fn refresh(&self) {
        self.emit().await;
    }

    /// Re-announces the one process-wide service with updated display metadata.
    /// `mdns-sd` replaces an existing registration with the same full name, so
    /// callers never create a second advertiser or change the network identity.
    pub fn update_local_metadata(
        &self,
        identity: &DeviceIdentity,
        metadata: &DeviceMetadata,
        port: u16,
    ) -> Result<(), NetworkError> {
        if self.local_published.load(Ordering::Acquire) {
            self.daemon
                .register(service_info(identity, metadata, port)?)
                .map_err(discovery_error)?;
        }
        Ok(())
    }

    pub fn set_local_published(
        &self,
        identity: &DeviceIdentity,
        metadata: &DeviceMetadata,
        port: u16,
        published: bool,
    ) -> Result<(), NetworkError> {
        let previous = self.local_published.load(Ordering::Acquire);
        if previous == published {
            return Ok(());
        }
        if published {
            self.daemon
                .register(service_info(identity, metadata, port)?)
                .map_err(discovery_error)?;
        } else {
            self.daemon
                .unregister(&self.fullname)
                .map_err(discovery_error)?;
        }
        self.local_published.store(published, Ordering::Release);
        Ok(())
    }

    async fn resolve(&self, info: &mdns_sd::ResolvedService) {
        let Some(peer) = decode_service(info) else {
            return;
        };
        if peer.device_id == self.local_id {
            return;
        }
        self.service_ids
            .lock()
            .await
            .insert(info.get_fullname().to_string(), peer.device_id.clone());
        let changed = {
            let mut peers = self.mdns_peers.write().await;
            merge_observed_peer(&mut peers, peer)
        };
        if changed {
            self.emit().await;
        }
    }

    async fn remove(&self, fullname: &str) {
        let Some(id) = self.service_ids.lock().await.remove(fullname) else {
            return;
        };
        if self.mdns_peers.write().await.remove(&id).is_some() {
            self.emit().await;
        }
    }

    async fn emit(&self) {
        let mut merged = self.authenticated_peers.read().await.clone();
        for (id, mdns) in self.mdns_peers.read().await.iter() {
            merged
                .entry(id.clone())
                .and_modify(|observed| merge_advertisement(observed, mdns))
                .or_insert_with(|| mdns.clone());
        }
        let mut peers = merged.into_values().collect::<Vec<_>>();
        peers.sort_by(|left, right| {
            left.metadata
                .name
                .cmp(&right.metadata.name)
                .then_with(|| left.device_id.cmp(&right.device_id))
        });
        self.snapshot.send_replace(Arc::new(peers));
    }
}

fn merge_observed_peer(
    peers: &mut HashMap<DeviceId, PeerAdvertisement>,
    peer: PeerAdvertisement,
) -> bool {
    let Some(observed) = peers.get_mut(&peer.device_id) else {
        peers.insert(peer.device_id.clone(), peer);
        return true;
    };
    let previous = observed.clone();
    merge_advertisement(observed, &peer);
    !same_discovery_route(&previous, observed)
}

/// `last_seen_at_ms` is persistence metadata, not a routing change. Emitting a
/// discovery update for every successful authentication creates a feedback
/// loop in consumers that react to discovery by opening another session.
fn same_discovery_route(left: &PeerAdvertisement, right: &PeerAdvertisement) -> bool {
    left.device_id == right.device_id
        && left.public_key == right.public_key
        && left.metadata == right.metadata
        && left.addresses == right.addresses
        && left.connection_addresses == right.connection_addresses
        && left.port == right.port
        && left.certificate_sha256 == right.certificate_sha256
}

fn merge_advertisement(target: &mut PeerAdvertisement, newer: &PeerAdvertisement) {
    if newer.last_seen_at_ms >= target.last_seen_at_ms {
        target.metadata = newer.metadata.clone();
        target.public_key = newer.public_key.clone();
        target.port = newer.port;
        target.certificate_sha256 = newer.certificate_sha256;
        target.last_seen_at_ms = newer.last_seen_at_ms;
    }
    target.addresses.extend(newer.addresses.iter().copied());
    target.addresses.sort();
    target.addresses.dedup();
    target
        .connection_addresses
        .extend(newer.connection_addresses.iter().copied());
    target.connection_addresses.sort();
    target.connection_addresses.dedup();
}

impl Drop for DiscoveryService {
    fn drop(&mut self) {
        self.unpublish_web_gateway();
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self
            .daemon
            .stop_browse(arcrelay_wire::DISCOVERY_SERVICE_TYPE);
        let _ = self.daemon.shutdown();
    }
}

pub fn device_hostname(id: &DeviceId) -> String {
    let suffix = id.as_str().trim_start_matches("arc-");
    format!("arcrelay-{}.local", &suffix[..suffix.len().min(32)])
}

fn service_info(
    identity: &DeviceIdentity,
    metadata: &DeviceMetadata,
    port: u16,
) -> Result<ServiceInfo, NetworkError> {
    if port == 0 {
        return Err(NetworkError::Discovery(
            "endpoint port cannot be zero".into(),
        ));
    }
    let id = identity.device_id();
    let mut properties = HashMap::new();
    properties.insert("protocol".into(), arcrelay_wire::DISCOVERY_PROTOCOL.into());
    properties.insert(
        "protocol_minor_min".into(),
        arcrelay_wire::MIN_PROTOCOL_MINOR.to_string(),
    );
    properties.insert(
        "protocol_minor_max".into(),
        arcrelay_wire::MAX_PROTOCOL_MINOR.to_string(),
    );
    properties.insert("device_id".into(), id.to_string());
    properties.insert("device_name".into(), metadata.name.clone());
    properties.insert("platform".into(), metadata.platform.clone());
    properties.insert("model".into(), metadata.model.clone());
    properties.insert(
        "public_key".into(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(identity.public_key_value().as_bytes()),
    );
    properties.insert("port".into(), port.to_string());
    properties.insert("certificate".into(), hex(&identity.certificate_sha256()));
    let suffix = id.as_str().trim_start_matches("arc-");
    ServiceInfo::new(
        arcrelay_wire::DISCOVERY_SERVICE_TYPE,
        &format!("arc-{}", &suffix[..20]),
        &format!("arcrelay-{}.local.", &suffix[..32]),
        "",
        port,
        properties,
    )
    .map(ServiceInfo::enable_addr_auto)
    .map_err(discovery_error)
}

// Keeping both interval bounds explicit makes this remain correct when a later
// v1 release raises the minimum supported minor above zero.
#[allow(clippy::absurd_extreme_comparisons)]
fn decode_service(info: &mdns_sd::ResolvedService) -> Option<PeerAdvertisement> {
    let properties = info.get_properties();
    if property(properties, "protocol") != Some(arcrelay_wire::DISCOVERY_PROTOCOL) {
        return None;
    }
    let remote_min_minor = property(properties, "protocol_minor_min")
        .unwrap_or("0")
        .parse::<u32>()
        .ok()?;
    let remote_max_minor = property(properties, "protocol_minor_max")
        .unwrap_or("0")
        .parse::<u32>()
        .ok()?;
    if remote_min_minor > remote_max_minor
        || remote_max_minor < arcrelay_wire::MIN_PROTOCOL_MINOR
        || remote_min_minor > arcrelay_wire::MAX_PROTOCOL_MINOR
    {
        return None;
    }
    let device_id = DeviceId::parse(property(properties, "device_id")?).ok()?;
    let public_key = DevicePublicKey::from_bytes(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(property(properties, "public_key")?)
            .ok()?,
    )
    .ok()?;
    device_id.verify_key(&public_key).ok()?;
    let port = property(properties, "port")?.parse().ok()?;
    if port == 0 {
        return None;
    }
    let certificate_sha256: [u8; 32] = unhex(property(properties, "certificate")?)
        .ok()?
        .try_into()
        .ok()?;
    let mut addresses = BTreeSet::new();
    let mut connection_addresses = BTreeSet::new();
    for value in info.get_addresses() {
        let ip = value.to_ip_addr();
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        let endpoint = match value {
            mdns_sd::ScopedIp::V4(value) => SocketAddr::new(IpAddr::V4(*value.addr()), port),
            mdns_sd::ScopedIp::V6(value) => SocketAddr::V6(SocketAddrV6::new(
                *value.addr(),
                port,
                0,
                value.scope_id().index,
            )),
            _ => continue,
        };
        addresses.insert(ip);
        connection_addresses.insert(endpoint);
    }
    let addresses = addresses.into_iter().collect::<Vec<_>>();
    if addresses.is_empty() {
        return None;
    }
    let connection_addresses = connection_addresses.into_iter().collect::<Vec<_>>();
    Some(PeerAdvertisement {
        device_id,
        public_key,
        metadata: DeviceMetadata {
            name: property(properties, "device_name")
                .unwrap_or("ArcRelay Device")
                .to_owned(),
            platform: property(properties, "platform")
                .unwrap_or("unknown")
                .to_owned(),
            model: property(properties, "model")
                .unwrap_or("unknown")
                .to_owned(),
        },
        addresses,
        connection_addresses,
        port,
        certificate_sha256,
        last_seen_at_ms: now_ms(),
    })
}

fn property<'a>(properties: &'a mdns_sd::TxtProperties, key: &str) -> Option<&'a str> {
    properties.get_property_val_str(key)
}

fn discovery_error(error: impl std::fmt::Display) -> NetworkError {
    NetworkError::Discovery(error.to_string())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64
}

#[cfg(test)]
mod observation_tests {
    use super::*;

    #[test]
    fn authenticated_refresh_only_notifies_when_the_route_changes() {
        let directory = tempfile::tempdir().unwrap();
        let identity = DeviceIdentity::load_or_create(directory.path()).unwrap();
        let device_id = identity.device_id();
        let mut peers = HashMap::new();
        let mut peer = PeerAdvertisement {
            device_id: device_id.clone(),
            public_key: identity.public_key_value(),
            metadata: DeviceMetadata {
                name: "Peer".into(),
                platform: "test".into(),
                model: "test".into(),
            },
            addresses: vec![IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 54))],
            connection_addresses: vec!["10.1.1.54:8765".parse().unwrap()],
            port: 8765,
            certificate_sha256: identity.certificate_sha256(),
            last_seen_at_ms: 1,
        };

        assert!(merge_observed_peer(&mut peers, peer.clone()));
        peer.last_seen_at_ms = 2;
        assert!(!merge_observed_peer(&mut peers, peer.clone()));
        assert_eq!(peers[&device_id].last_seen_at_ms, 2);

        peer.connection_addresses
            .push("10.1.1.54:8766".parse().unwrap());
        assert!(merge_observed_peer(&mut peers, peer));
        assert_eq!(peers[&device_id].connection_addresses.len(), 2);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| ())?;
            u8::from_str_radix(pair, 16).map_err(|_| ())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_identity_uses_one_v1_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let identity = DeviceIdentity::load_or_create(directory.path()).unwrap();
        let info = service_info(
            &identity,
            &DeviceMetadata {
                name: "Desk".into(),
                platform: "test".into(),
                model: "test".into(),
            },
            4711,
        )
        .unwrap();
        assert_eq!(property(info.get_properties(), "protocol"), Some("1"));
        assert_eq!(
            property(info.get_properties(), "protocol_minor_min"),
            Some("0")
        );
        assert_eq!(
            property(info.get_properties(), "protocol_minor_max"),
            Some("0")
        );
        assert_eq!(property(info.get_properties(), "port"), Some("4711"));
        assert!(property(info.get_properties(), "control_port").is_none());
        assert!(property(info.get_properties(), "transfer_port").is_none());
    }
}
