use super::diagnostics::*;
use super::*;

#[derive(Clone)]
pub(super) enum ExpectedPeer {
    Advertised(PeerAdvertisement),
    Paired(PeerRecord),
}
impl ExpectedPeer {
    fn id(&self) -> &DeviceId {
        match self {
            Self::Advertised(peer) => &peer.device_id,
            Self::Paired(peer) => &peer.device_id,
        }
    }
}

/// Closing an unselected or cancelled candidate must not depend on QUIC's idle
/// timeout. The successful candidate disarms this guard only after registration.
struct CandidateConnection(Option<quinn::Connection>);
impl Drop for CandidateConnection {
    fn drop(&mut self) {
        if let Some(connection) = self.0.take() {
            connection.close(0_u32.into(), b"dial candidate cancelled");
        }
    }
}

impl NetworkRuntime {
    pub(super) async fn race_endpoints(
        self: &Arc<Self>,
        addresses: Vec<SocketAddr>,
        expected: ExpectedPeer,
        kind: SessionKind,
        source: EndpointSource,
    ) -> Result<Arc<Session>, NetworkError> {
        match self
            .race_endpoints_on(addresses.clone(), expected.clone(), kind, source, None)
            .await
        {
            Ok(session) => Ok(session),
            Err((error, retry_source_port)) => {
                // Discovery/pairing probes stay bounded to their original
                // budget. Persistent feature sessions get one fresh path when
                // QUIC receives no answer, never on an authentication failure.
                if !retry_source_port
                    || matches!(kind, SessionKind::DiscoveryProbe | SessionKind::Pairing)
                {
                    return Err(error);
                }
                let endpoint = self.new_recovery_endpoint()?;
                tracing::info!(event = "network.dial.source_port_recovery",
                    peer_id = %diagnostic_id(expected.id().as_str()), session_kind = ?kind,
                    "retrying unresponsive QUIC path from a fresh source port");
                self.race_endpoints_on(addresses, expected, kind, source, Some(endpoint))
                    .await
                    .map_err(|(error, _)| error)
            }
        }
    }

    fn new_recovery_endpoint(&self) -> Result<Arc<quinn::Endpoint>, NetworkError> {
        tokio::runtime::Handle::try_current().map_err(|_| NetworkError::RuntimeUnavailable)?;
        let mut endpoints = self
            .recovery_endpoints
            .write()
            .expect("recovery endpoint lock poisoned");
        if self.stopped.load(Ordering::Acquire) {
            return Err(NetworkError::Connect("network runtime is shut down".into()));
        }
        let address = self.endpoint.local_addr()?.ip();
        let socket = bind_socket(address, 0)?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| NetworkError::Quic(error.to_string()))?;
        endpoint.set_default_client_config(client_config()?);
        let endpoint = Arc::new(endpoint);
        endpoints.retain(|endpoint| endpoint.strong_count() > 0);
        endpoints.push(Arc::downgrade(&endpoint));
        Ok(endpoint)
    }

    async fn race_endpoints_on(
        self: &Arc<Self>,
        addresses: Vec<SocketAddr>,
        expected: ExpectedPeer,
        kind: SessionKind,
        source: EndpointSource,
        recovery_endpoint: Option<Arc<quinn::Endpoint>>,
    ) -> Result<Arc<Session>, (NetworkError, bool)> {
        let attempt_id = rand::random::<u64>();
        let peer_id = diagnostic_id(expected.id().as_str());
        let started = Instant::now();
        let mut unique = Vec::new();
        for address in addresses {
            let address = canonical_endpoint(address);
            if !unique.contains(&address) {
                unique.push(address);
                // Discovery can accumulate interfaces and scoped IPv6 routes.
                // Bound the race without rejecting an otherwise valid peer.
                if unique.len() == 16 {
                    break;
                }
            }
        }
        if unique.is_empty() {
            return Err((NetworkError::Connect("no dial endpoints".into()), false));
        }
        let socket_role = if recovery_endpoint.is_some() {
            "recovery"
        } else {
            "listener"
        };
        tracing::debug!(event = "network.dial.started", attempt_id, peer_id,
            session_kind = ?kind, source = ?source, socket_role, candidate_count = unique.len(),
            "starting endpoint race");
        let capacity = Arc::new(Semaphore::new(3));
        let selection = Arc::new(Semaphore::new(1));
        let mut candidates = tokio::task::JoinSet::new();
        for (index, address) in unique.into_iter().enumerate() {
            let runtime = self.clone();
            let endpoint = recovery_endpoint
                .as_deref()
                .unwrap_or(&self.endpoint)
                .clone();
            let expected = expected.clone();
            let capacity = capacity.clone();
            let selection = selection.clone();
            candidates.spawn(async move {
                tokio::time::sleep(Duration::from_millis(index as u64 * 200)).await;
                let started = Instant::now();
                let mut phase = "candidate_capacity_wait";
                let mut quic_failure = None;
                tracing::debug!(event = "network.dial.candidate_started", attempt_id,
                    candidate_index = index, endpoint_id = %endpoint_id(address),
                    address_family = address_family(address), port = address.port(),
                    scope_id = scope_id(address),
                    "starting dial candidate");
                log_route_probe(attempt_id, address);
                let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
                    let _capacity = capacity
                        .acquire()
                        .await
                        .map_err(|_| NetworkError::Timeout)?;
                    phase = "global_capacity_wait";
                    let _global = runtime
                        .handshake_gate
                        .acquire()
                        .await
                        .map_err(|_| NetworkError::Timeout)?;
                    phase = "quic_handshake";
                    let connection = endpoint
                        .connect(address, "localhost")
                        .map_err(|e| NetworkError::Connect(e.to_string()))?
                        .await
                        .map_err(|e| {
                            quic_failure = Some(quic_failure_kind(&e));
                            NetworkError::Quic(e.to_string())
                        })?;
                    tracing::debug!(event = "network.dial.quic_established", attempt_id,
                        endpoint_id = %endpoint_id(address),
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "QUIC handshake completed");
                    phase = "peer_authentication";
                    let guard = CandidateConnection(Some(connection.clone()));
                    let session = match expected {
                        ExpectedPeer::Advertised(peer) => {
                            runtime
                                .authenticate_outbound(connection, &peer, kind, selection)
                                .await?
                        }
                        ExpectedPeer::Paired(peer) => {
                            runtime
                                .authenticate_outbound_paired(connection, &peer, kind, selection)
                                .await?
                        }
                    };
                    Ok::<_, NetworkError>((session, guard))
                })
                .await
                .unwrap_or(Err(NetworkError::Timeout));
                if let Err(error) = &result {
                    tracing::debug!(event = "network.dial.candidate_failed", attempt_id,
                        endpoint_id = %endpoint_id(address), phase, quic_failure,
                        error_code = error.code(), elapsed_ms = started.elapsed().as_millis() as u64,
                        "dial candidate failed");
                }
                (address, phase, quic_failure, result)
            });
        }
        let mut failures = Vec::new();
        let mut failure_details = Vec::new();
        let mut path_timed_out = false;
        let mut authentication_failed = false;
        while let Some(candidate) = candidates.join_next().await {
            match candidate {
                Ok((address, _, _, Ok((session, mut guard)))) => {
                    candidates.shutdown().await;
                    if let Some(endpoint) = &recovery_endpoint {
                        let _ = session.recovery_endpoint.set(endpoint.clone());
                    }
                    let session = self
                        .register_session(session)
                        .await
                        .map_err(|error| (error, false))?;
                    guard.0.take();
                    self.remember_authenticated_session(&session, source).await;
                    tracing::info!(event = "network.dial.succeeded", attempt_id, peer_id,
                        endpoint_id = %endpoint_id(address), session_kind = ?kind, socket_role,
                        session_id = session.id(), elapsed_ms = started.elapsed().as_millis() as u64,
                        "authenticated endpoint race completed");
                    return Ok(session);
                }
                Ok((address, phase, quic_failure, Err(error))) => {
                    path_timed_out |= phase == "quic_handshake"
                        && (matches!(error, NetworkError::Timeout)
                            || quic_failure == Some("idle_timeout"));
                    authentication_failed |= phase == "peer_authentication";
                    failure_details.push(format!(
                        "{} {} port={} scope={} phase={} code={} quic={}",
                        endpoint_id(address),
                        address_family(address),
                        address.port(),
                        scope_id(address),
                        phase,
                        error.code(),
                        quic_failure.unwrap_or("none")
                    ));
                    if source == EndpointSource::History {
                        let _ = self.endpoints.record_failure(expected.id(), address).await;
                    }
                    failures.push(format!("{address}: {error}"));
                }
                Err(error) => failures.push(error.to_string()),
            }
        }
        // Keep actionable failures in default logs without flooding LAN scans.
        if kind != SessionKind::DiscoveryProbe {
            tracing::info!(event = "network.dial.failed", attempt_id, peer_id,
                session_kind = ?kind, source = ?source, socket_role, failures = ?failure_details,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "all dial candidates failed");
        }
        tracing::debug!(
            event = "network.dial.race_finished",
            attempt_id,
            peer_id,
            failure_count = failures.len(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "all dial candidates failed"
        );
        Err((
            NetworkError::Connect(failures.join("; ")),
            path_timed_out && !authentication_failed,
        ))
    }
}

fn canonical_endpoint(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => address
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), address.port()))
            .unwrap_or(SocketAddr::V6(address)),
        address => address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_ipv4_does_not_consume_two_dial_slots() {
        assert_eq!(
            canonical_endpoint("[::ffff:192.0.2.1]:8765".parse().unwrap()),
            "192.0.2.1:8765".parse().unwrap()
        );
        assert_eq!(
            canonical_endpoint("[fe80::1%4]:8765".parse().unwrap()),
            "[fe80::1%4]:8765".parse().unwrap()
        );
    }

    #[test]
    fn recovery_socket_requires_the_live_runtime_context() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let network = runtime.block_on(super::super::tests::runtime(
            directory.path(),
            "recovery-context",
        ));
        assert!(matches!(
            network.new_recovery_endpoint(),
            Err(NetworkError::RuntimeUnavailable)
        ));
        network.shutdown("test complete");
    }
}
