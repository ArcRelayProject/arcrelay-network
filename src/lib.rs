//! One identity, discovery service and advertised QUIC listener for every
//! ArcRelay LAN feature, with runtime-owned recovery sockets and private input tunnels.

mod discovery;
mod endpoint;
mod identity;
mod repository;
mod runtime;

pub use discovery::{
    device_hostname, DeviceMetadata, DiscoveryService, PeerAdvertisement,
    WEB_DISCOVERY_SERVICE_TYPE,
};
pub use endpoint::{
    EndpointRepository, EndpointSource, InMemoryEndpointRepository, RememberedEndpoint,
};
pub use identity::{verify_signature, DeviceIdentity};
pub use repository::SqlitePeerRepository;
pub use runtime::{
    reserve_udp_socket, FeatureStream, LanScanReport, NetworkRuntime, NetworkRuntimeConfig,
    PairingGrantRequest, PairingOutcome, PendingPairing, Session, SessionKind, SessionPeer,
};

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("network I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS configuration failed: {0}")]
    Tls(String),
    #[error("invalid device identity: {0}")]
    InvalidIdentity(String),
    #[error("discovery failed: {0}")]
    Discovery(String),
    #[error("QUIC failed: {0}")]
    Quic(String),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("peer is not paired")]
    Unpaired,
    #[error("peer is not authorized: {0}")]
    Unauthorized(String),
    #[error("peer repository failed: {0}")]
    Repository(String),
    #[error("operation timed out")]
    Timeout,
    #[error("cannot connect to this device")]
    SelfConnection,
    #[error("network runtime is busy: {0}")]
    Busy(String),
    #[error("an active Tokio runtime is required")]
    RuntimeUnavailable,
    #[error(transparent)]
    Frame(#[from] arcrelay_transport::FrameError),
}

impl NetworkError {
    /// Stable machine-readable category for application adapters.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io(_) | Self::Discovery(_) | Self::Quic(_) | Self::Connect(_) => {
                "network.unavailable"
            }
            Self::Tls(_) => "network.tls_configuration",
            Self::InvalidIdentity(_) => "network.invalid_identity",
            Self::Protocol(_) | Self::Frame(_) => "network.protocol",
            Self::Unpaired => "network.unpaired",
            Self::Unauthorized(_) => "network.permission_denied",
            Self::Repository(_) => "network.repository",
            Self::Timeout => "network.deadline_exceeded",
            Self::SelfConnection => "network.self_connection",
            Self::Busy(_) => "network.busy",
            Self::RuntimeUnavailable => "network.runtime_unavailable",
        }
    }
}
