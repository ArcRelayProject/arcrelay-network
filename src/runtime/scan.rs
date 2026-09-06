use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use arcrelay_peer::DeviceId;
use tokio::task::JoinSet;

use super::*;

const SCAN_PORT: u16 = 8765;
const SCAN_CONCURRENCY: usize = 32;
const SCAN_LAUNCH_INTERVAL: Duration = Duration::from_millis(20);
const SCAN_ENDPOINT_TIMEOUT: Duration = Duration::from_millis(900);
const SCAN_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_SUBNETS: usize = 2;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LanScanReport {
    pub attempted_endpoints: usize,
    pub discovered_devices: usize,
    pub scanned_subnets: usize,
    pub throttled: bool,
}

#[derive(Default)]
pub(super) struct ScanState {
    last_started: Option<Instant>,
}

impl NetworkRuntime {
    /// Performs one bounded foreground LAN scan. Regardless of the actual
    /// interface prefix, every selected interface contributes at most its
    /// containing IPv4 /24 and only ArcRelay's primary port is probed.
    pub async fn scan_local_ipv4(self: &Arc<Self>) -> Result<LanScanReport, NetworkError> {
        {
            let mut state = self.scan_state.lock().await;
            if state
                .last_started
                .is_some_and(|started| started.elapsed() < SCAN_COOLDOWN)
            {
                return Ok(LanScanReport {
                    throttled: true,
                    ..LanScanReport::default()
                });
            }
            state.last_started = Some(Instant::now());
        }
        self.scan_cancelled.store(false, Ordering::Release);

        let interfaces = local_scan_interfaces()?;
        let local_addresses = interfaces
            .iter()
            .map(|(_, address)| *address)
            .collect::<BTreeSet<_>>();
        let subnets = interfaces
            .into_iter()
            .map(|(_, address)| subnet_prefix(address))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(MAX_SUBNETS)
            .collect::<Vec<_>>();
        let endpoints = subnets
            .iter()
            .flat_map(|prefix| subnet_hosts(*prefix))
            .filter(|address| !local_addresses.contains(address))
            .map(|address| SocketAddr::new(IpAddr::V4(address), SCAN_PORT))
            .collect::<Vec<_>>();

        let mut tasks: JoinSet<Result<PeerAdvertisement, NetworkError>> = JoinSet::new();
        let mut discovered = BTreeSet::<DeviceId>::new();
        let mut attempted = 0_usize;
        for endpoint in &endpoints {
            if self.scan_cancelled.load(Ordering::Acquire) {
                break;
            }
            while tasks.len() >= SCAN_CONCURRENCY {
                if let Some(Ok(Ok(peer))) = tasks.join_next().await {
                    discovered.insert(peer.device_id);
                }
            }
            let runtime = self.clone();
            let endpoint = *endpoint;
            tasks.spawn(async move {
                runtime
                    .probe_endpoint(endpoint, EndpointSource::Scan, SCAN_ENDPOINT_TIMEOUT)
                    .await
            });
            attempted += 1;
            tokio::time::sleep(SCAN_LAUNCH_INTERVAL).await;
        }
        while let Some(result) = tasks.join_next().await {
            if let Ok(Ok(peer)) = result {
                discovered.insert(peer.device_id);
            }
        }
        Ok(LanScanReport {
            attempted_endpoints: attempted,
            discovered_devices: discovered.len(),
            scanned_subnets: subnets.len(),
            throttled: false,
        })
    }
}

fn local_scan_interfaces() -> Result<Vec<(String, Ipv4Addr)>, NetworkError> {
    let mut interfaces = if_addrs::get_if_addrs()
        .map_err(|error| NetworkError::Io(std::io::Error::other(error)))?
        .into_iter()
        .filter_map(|interface| match interface.ip() {
            IpAddr::V4(address)
                if address.is_private()
                    && !address.is_loopback()
                    && !is_likely_virtual(&interface.name) =>
            {
                Some((interface.name, address))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    interfaces.sort_by(|left, right| {
        interface_priority(&left.0)
            .cmp(&interface_priority(&right.0))
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| left.1.cmp(&right.1))
    });
    Ok(interfaces)
}

fn interface_priority(name: &str) -> u8 {
    let name = name.to_ascii_lowercase();
    if name.starts_with("en")
        || name.starts_with("eth")
        || name.starts_with("wlan")
        || name.contains("wi-fi")
        || name.contains("wifi")
    {
        0
    } else {
        1
    }
}

fn is_likely_virtual(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "lo",
        "utun",
        "tun",
        "tap",
        "docker",
        "veth",
        "br-",
        "virbr",
        "vmnet",
        "tailscale",
        "wg",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn subnet_prefix(address: Ipv4Addr) -> [u8; 3] {
    let octets = address.octets();
    [octets[0], octets[1], octets[2]]
}

fn subnet_hosts(prefix: [u8; 3]) -> impl Iterator<Item = Ipv4Addr> {
    (1_u8..=254).map(move |host| Ipv4Addr::new(prefix[0], prefix[1], prefix[2], host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_scope_is_always_one_slash_24() {
        let prefix = subnet_prefix(Ipv4Addr::new(10, 20, 30, 40));
        let hosts = subnet_hosts(prefix).collect::<Vec<_>>();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts.first(), Some(&Ipv4Addr::new(10, 20, 30, 1)));
        assert_eq!(hosts.last(), Some(&Ipv4Addr::new(10, 20, 30, 254)));
    }

    #[test]
    fn virtual_interfaces_are_excluded() {
        assert!(is_likely_virtual("utun4"));
        assert!(is_likely_virtual("docker0"));
        assert!(!is_likely_virtual("en0"));
        assert!(!is_likely_virtual("Ethernet"));
    }
}
