use super::*;

/// Stable across both peers without writing exact addresses or device identities.
pub(super) fn diagnostic_id(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let suffix: String = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("peer-{suffix}")
}

pub(super) fn address_family(address: SocketAddr) -> &'static str {
    match address.ip() {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

pub(super) fn endpoint_id(address: SocketAddr) -> String {
    let address = match address {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(ip.into(), v6.port()))
            .unwrap_or(address),
        _ => address,
    };
    diagnostic_id(&address.to_string())
}

pub(super) fn scope_id(address: SocketAddr) -> u32 {
    match address {
        SocketAddr::V6(v6) => v6.scope_id(),
        _ => 0,
    }
}

/// This is the OS route selection for a separate UDP socket, not proof of the
/// QUIC socket's actual egress. No packet is sent. Failure never affects dialing.
pub(super) fn log_route_probe(attempt_id: u64, address: SocketAddr) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let result = (|| -> std::io::Result<_> {
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = std::net::UdpSocket::bind(bind)?;
        socket.connect(address)?;
        socket.local_addr()
    })();
    match result {
        Ok(local) => {
            let ip = local.ip().to_canonical();
            let interfaces: Vec<u32> = if_addrs::get_if_addrs()
                .unwrap_or_default()
                .into_iter()
                .filter(|interface| interface.ip().to_canonical() == ip)
                .filter_map(|interface| interface.index)
                .collect();
            tracing::debug!(event = "network.dial.route_probe", attempt_id,
                endpoint_id = %endpoint_id(address), local_address_id = %diagnostic_id(&ip.to_string()),
                interface_indices = ?interfaces, "observed OS UDP route selection");
        }
        Err(error) => tracing::debug!(event = "network.dial.route_probe_failed", attempt_id,
            endpoint_id = %endpoint_id(address), os_error = error.raw_os_error(),
            "could not inspect OS UDP route selection"),
    }
}

pub(super) fn quic_failure_kind(error: &quinn::ConnectionError) -> &'static str {
    match error {
        quinn::ConnectionError::VersionMismatch => "version_mismatch",
        quinn::ConnectionError::TransportError(_) => "transport_error",
        quinn::ConnectionError::ConnectionClosed(_) => "peer_transport_close",
        quinn::ConnectionError::ApplicationClosed(_) => "peer_application_close",
        quinn::ConnectionError::Reset => "peer_reset",
        quinn::ConnectionError::TimedOut => "idle_timeout",
        quinn::ConnectionError::LocallyClosed => "local_close",
        quinn::ConnectionError::CidsExhausted => "connection_ids_exhausted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_diagnostics_correlate_mapped_ipv4_without_exposing_addresses() {
        let ipv4 = "10.1.1.54:8765".parse().unwrap();
        let mapped = "[::ffff:10.1.1.54]:8765".parse().unwrap();
        assert_eq!(endpoint_id(ipv4), endpoint_id(mapped));
        assert!(!endpoint_id(ipv4).contains("10.1.1.54"));
        assert_eq!(address_family(mapped), "ipv4");
        let scoped = "[fe80::1%12]:8765".parse().unwrap();
        assert_eq!(scope_id(scoped), 12);
        assert_eq!(address_family(scoped), "ipv6");
        assert_ne!(
            endpoint_id(scoped),
            endpoint_id("[fe80::1%13]:8765".parse().unwrap())
        );
    }
}
