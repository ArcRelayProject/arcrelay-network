use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arcrelay_peer::DeviceId;
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::NetworkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSource {
    Mdns,
    Inbound,
    History,
    Scan,
    Manual,
    Relayed,
}

impl EndpointSource {
    pub(crate) fn encode(self) -> i64 {
        match self {
            Self::Mdns => 1,
            Self::Inbound => 2,
            Self::History => 3,
            Self::Scan => 4,
            Self::Manual => 5,
            Self::Relayed => 6,
        }
    }

    pub(crate) fn decode(value: i64) -> Result<Self, NetworkError> {
        match value {
            1 => Ok(Self::Mdns),
            2 => Ok(Self::Inbound),
            3 => Ok(Self::History),
            4 => Ok(Self::Scan),
            5 => Ok(Self::Manual),
            6 => Ok(Self::Relayed),
            _ => Err(NetworkError::Repository(
                "unknown remembered endpoint source".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberedEndpoint {
    pub peer_id: DeviceId,
    pub address: SocketAddr,
    pub certificate_sha256: [u8; 32],
    pub source: EndpointSource,
    pub network_scope: String,
    pub first_seen_at_ms: i64,
    pub last_seen_at_ms: i64,
    pub last_success_at_ms: i64,
    pub consecutive_failures: u32,
    pub retry_after_ms: i64,
}

#[async_trait]
pub trait EndpointRepository: Send + Sync {
    async fn endpoints(&self, peer_id: &DeviceId) -> Result<Vec<RememberedEndpoint>, NetworkError>;

    async fn record_authenticated(
        &self,
        peer_id: &DeviceId,
        address: SocketAddr,
        certificate_sha256: [u8; 32],
        source: EndpointSource,
    ) -> Result<(), NetworkError>;

    async fn record_failure(
        &self,
        peer_id: &DeviceId,
        address: SocketAddr,
    ) -> Result<(), NetworkError>;

    async fn forget(&self, peer_id: &DeviceId) -> Result<(), NetworkError>;
}

#[derive(Default)]
pub struct InMemoryEndpointRepository {
    endpoints: RwLock<HashMap<DeviceId, Vec<RememberedEndpoint>>>,
}

#[async_trait]
impl EndpointRepository for InMemoryEndpointRepository {
    async fn endpoints(&self, peer_id: &DeviceId) -> Result<Vec<RememberedEndpoint>, NetworkError> {
        let now = now_ms();
        let mut endpoints = self
            .endpoints
            .read()
            .await
            .get(peer_id)
            .cloned()
            .unwrap_or_default();
        endpoints.retain(|endpoint| endpoint.retry_after_ms <= now);
        endpoints.sort_by(|left, right| {
            right
                .last_success_at_ms
                .cmp(&left.last_success_at_ms)
                .then_with(|| right.last_seen_at_ms.cmp(&left.last_seen_at_ms))
        });
        endpoints.truncate(16);
        Ok(endpoints)
    }

    async fn record_authenticated(
        &self,
        peer_id: &DeviceId,
        address: SocketAddr,
        certificate_sha256: [u8; 32],
        source: EndpointSource,
    ) -> Result<(), NetworkError> {
        let now = now_ms();
        let mut all = self.endpoints.write().await;
        let endpoints = all.entry(peer_id.clone()).or_default();
        if let Some(endpoint) = endpoints.iter_mut().find(|value| value.address == address) {
            endpoint.certificate_sha256 = certificate_sha256;
            endpoint.source = source;
            endpoint.network_scope = network_scope(address);
            endpoint.last_seen_at_ms = now;
            endpoint.last_success_at_ms = now;
            endpoint.consecutive_failures = 0;
            endpoint.retry_after_ms = 0;
        } else {
            endpoints.push(RememberedEndpoint {
                peer_id: peer_id.clone(),
                address,
                certificate_sha256,
                source,
                network_scope: network_scope(address),
                first_seen_at_ms: now,
                last_seen_at_ms: now,
                last_success_at_ms: now,
                consecutive_failures: 0,
                retry_after_ms: 0,
            });
        }
        endpoints.sort_by_key(|endpoint| std::cmp::Reverse(endpoint.last_success_at_ms));
        endpoints.truncate(16);
        Ok(())
    }

    async fn record_failure(
        &self,
        peer_id: &DeviceId,
        address: SocketAddr,
    ) -> Result<(), NetworkError> {
        let now = now_ms();
        if let Some(endpoint) = self
            .endpoints
            .write()
            .await
            .get_mut(peer_id)
            .and_then(|endpoints| endpoints.iter_mut().find(|value| value.address == address))
        {
            endpoint.consecutive_failures = endpoint.consecutive_failures.saturating_add(1);
            let exponent = endpoint.consecutive_failures.min(8);
            endpoint.retry_after_ms = now.saturating_add((1_i64 << exponent) * 1_000);
        }
        Ok(())
    }

    async fn forget(&self, peer_id: &DeviceId) -> Result<(), NetworkError> {
        self.endpoints.write().await.remove(peer_id);
        Ok(())
    }
}

pub(crate) fn default_endpoint_repository() -> Arc<dyn EndpointRepository> {
    Arc::new(InMemoryEndpointRepository::default())
}

pub(crate) fn network_scope(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(address) => {
            let octets = address.ip().octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        SocketAddr::V6(address) => format!("ipv6-if-{}", address.scope_id()),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
