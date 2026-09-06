use super::*;

/// Owns a private loopback QUIC endpoint and its stream bridge. The bridge
/// carries ciphertext only. Its addresses must never enter LAN discovery or
/// remembered endpoint history.
pub(super) struct RelayTunnel {
    endpoint: Arc<quinn::Endpoint>,
    proxy_address: SocketAddr,
    bridge: tokio::task::AbortHandle,
    _capacity: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for RelayTunnel {
    fn drop(&mut self) {
        self.endpoint.close(0_u32.into(), b"input relay released");
        self.bridge.abort();
    }
}

impl NetworkRuntime {
    /// Establishes an end-to-end input session through an already negotiated
    /// stream tunnel. The middle peer never supplies the expected public key.
    pub async fn connect_input_relay(
        self: &Arc<Self>,
        target: &DeviceId,
        send: quinn::SendStream,
        receive: quinn::RecvStream,
    ) -> Result<Arc<Session>, NetworkError> {
        let peer = self.require_paired(target, None).await?;
        if let Some(session) = self.active(target, SessionKind::RealtimeInput).await {
            return Ok(session);
        }
        let tunnel = self.new_input_relay_tunnel(send, receive, false)?;
        let _permit = self
            .handshake_gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| NetworkError::Busy("input relay handshake limit reached".into()))?;
        let session = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let connection = tunnel
                .endpoint
                .connect(tunnel.proxy_address, "localhost")
                .map_err(|error| NetworkError::Connect(error.to_string()))?
                .await
                .map_err(|error| NetworkError::Quic(error.to_string()))?;
            self.authenticate_outbound_paired(
                connection,
                &peer,
                SessionKind::RealtimeInput,
                Arc::new(Semaphore::new(1)),
            )
            .await
        })
        .await
        .map_err(|_| NetworkError::Timeout)??;
        self.register_input_relay(session, tunnel).await
    }

    /// Accepts only the requested paired source and only realtime input. The
    /// authenticated source's inbound grant is checked again at this endpoint.
    pub async fn accept_input_relay(
        self: &Arc<Self>,
        source: &DeviceId,
        send: quinn::SendStream,
        receive: quinn::RecvStream,
    ) -> Result<Arc<Session>, NetworkError> {
        let expected = self.require_paired(source, None).await?;
        let tunnel = self.new_input_relay_tunnel(send, receive, true)?;
        let _permit = self
            .handshake_gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| NetworkError::Busy("input relay handshake limit reached".into()))?;
        let session = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let incoming = tunnel
                .endpoint
                .accept()
                .await
                .ok_or_else(|| NetworkError::Connect("input relay endpoint closed".into()))?;
            let connection = incoming
                .await
                .map_err(|error| NetworkError::Quic(error.to_string()))?;
            let session = self.authenticate_inbound(connection).await?;
            if session.kind() != SessionKind::RealtimeInput
                || session.peer.device_id != expected.device_id
                || session.peer.public_key != expected.public_key
            {
                session.close("input relay identity mismatch");
                return Err(NetworkError::InvalidIdentity(
                    "input relay authenticated an unexpected source".into(),
                ));
            }
            self.require(&session, CapabilityId::CrossScreenInject)
                .await?;
            Ok(session)
        })
        .await
        .map_err(|_| NetworkError::Timeout)??;
        let session = self.register_input_relay(session, tunnel).await?;
        let _ = self.incoming.send(session.clone());
        Ok(session)
    }

    async fn register_input_relay(
        self: &Arc<Self>,
        session: Arc<Session>,
        tunnel: Arc<RelayTunnel>,
    ) -> Result<Arc<Session>, NetworkError> {
        let _ = session.relay_tunnel.set(tunnel.clone());
        let registered = self.register_session(session.clone()).await?;
        if Arc::ptr_eq(&registered, &session) {
            let runtime = Arc::downgrade(self);
            let connection = session.connection.clone();
            let key = (session.peer.device_id.clone(), session.kind);
            let bridge = tunnel.bridge.clone();
            tokio::spawn(async move {
                connection.closed().await;
                // Closing either inner QUIC connection also closes both outer
                // streams, so a relay never stays alive after its input token.
                bridge.abort();
                if let Some(runtime) = runtime.upgrade() {
                    let mut sessions = runtime.sessions.lock().await;
                    if sessions.get(&key).is_some_and(|active| {
                        active.connection.stable_id() == connection.stable_id()
                    }) {
                        sessions.remove(&key);
                    }
                }
            });
            tracing::info!(event = "network.input_relay.authenticated",
                peer_id = %diagnostics::diagnostic_id(session.peer.device_id.as_str()),
                session_id = session.id(), "authenticated end-to-end input relay session");
        }
        Ok(registered)
    }

    fn new_input_relay_tunnel(
        &self,
        mut send: quinn::SendStream,
        mut receive: quinn::RecvStream,
        server: bool,
    ) -> Result<Arc<RelayTunnel>, NetworkError> {
        tokio::runtime::Handle::try_current().map_err(|_| NetworkError::RuntimeUnavailable)?;
        let capacity = self
            .relay_capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| NetworkError::Busy("input relay tunnel limit reached".into()))?;
        let mut endpoints = self
            .recovery_endpoints
            .write()
            .expect("recovery endpoint lock poisoned");
        if self.stopped.load(Ordering::Acquire) {
            return Err(NetworkError::Connect("network runtime is shut down".into()));
        }
        let loopback = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let proxy = tokio::net::UdpSocket::from_std(bind_socket(loopback, 0)?)?;
        let proxy_address = proxy.local_addr()?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            server.then(|| self.identity.server_config()),
            bind_socket(loopback, 0)?,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| NetworkError::Quic(error.to_string()))?;
        endpoint.set_default_client_config(client_config()?);
        let endpoint = Arc::new(endpoint);
        let local = endpoint.local_addr()?;
        let bridge_endpoint = endpoint.clone();
        let bridge = tokio::spawn(async move {
            let inbound = async {
                loop {
                    let packet =
                        read_frame(&mut receive, arcrelay_wire::MAX_INPUT_RELAY_PACKET_SIZE)
                            .await?;
                    if packet.is_empty() {
                        return Err(NetworkError::Protocol("empty input relay packet".into()));
                    }
                    proxy.send_to(&packet, local).await?;
                }
                #[allow(unreachable_code)]
                Ok::<(), NetworkError>(())
            };
            let outbound = async {
                let mut packet = vec![0; arcrelay_wire::MAX_INPUT_RELAY_PACKET_SIZE];
                loop {
                    let (length, source) = proxy.recv_from(&mut packet).await?;
                    if source != local || length == 0 {
                        continue;
                    }
                    write_frame(
                        &mut send,
                        &packet[..length],
                        arcrelay_wire::MAX_INPUT_RELAY_PACKET_SIZE,
                    )
                    .await?;
                }
                #[allow(unreachable_code)]
                Ok::<(), NetworkError>(())
            };
            let result = tokio::select! {
                result = inbound => result,
                result = outbound => result,
            };
            tracing::debug!(
                event = "network.input_relay.stream_closed",
                ?result,
                "input relay stream bridge stopped"
            );
            bridge_endpoint.close(0_u32.into(), b"input relay stream closed");
        });
        endpoints.retain(|endpoint| endpoint.strong_count() > 0);
        endpoints.push(Arc::downgrade(&endpoint));
        Ok(Arc::new(RelayTunnel {
            endpoint,
            proxy_address,
            bridge: bridge.abort_handle(),
            _capacity: capacity,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{advertisement, runtime};
    use super::*;

    async fn pair(left: &Arc<NetworkRuntime>, right: &Arc<NetworkRuntime>) {
        let mut incoming = right.subscribe();
        let local = left
            .connect(&advertisement(right), SessionKind::Pairing)
            .await
            .unwrap();
        let remote = incoming.recv().await.unwrap();
        left.confirm_pairing(&local).await.unwrap();
        right.confirm_pairing(&remote).await.unwrap();
        right
            .grant(Grant {
                peer_id: left.device_id(),
                capability: CapabilityId::CrossScreenInject,
                direction: GrantDirection::Inbound,
                constraints: GrantConstraints::None,
                granted_at_ms: 1,
            })
            .await
            .unwrap();
        local.close("pairing complete");
    }

    async fn parent(
        left: &Arc<NetworkRuntime>,
        right: &Arc<NetworkRuntime>,
    ) -> (Arc<Session>, Arc<Session>) {
        let mut incoming = right.subscribe();
        let source = left
            .connect(&advertisement(right), SessionKind::Control)
            .await
            .unwrap();
        let target = incoming.recv().await.unwrap();
        (source, target)
    }

    async fn streams(left: &Session, right: &Session) -> (FeatureStream, FeatureStream) {
        let source = left
            .open_feature_stream("arcrelay.input-relay-test", b"")
            .await
            .unwrap();
        let target = right.accept_feature_stream().await.unwrap();
        (source, target)
    }

    #[test]
    fn input_relay_endpoint_requires_a_current_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (left, right, outbound, _inbound) = executor.block_on(async {
            let left = runtime(&directory.path().join("left"), "Left").await;
            let right = runtime(&directory.path().join("right"), "Right").await;
            pair(&left, &right).await;
            let (local, remote) = parent(&left, &right).await;
            let (outbound, inbound) = streams(&local, &remote).await;
            (left, right, outbound, inbound)
        });
        assert!(matches!(
            left.new_input_relay_tunnel(outbound.send, outbound.receive, false),
            Err(NetworkError::RuntimeUnavailable)
        ));
        left.shutdown("test complete");
        right.shutdown("test complete");
    }

    #[tokio::test]
    async fn input_relay_keeps_identity_history_and_shutdown_bound_to_endpoints() {
        let directory = tempfile::tempdir().unwrap();
        let left = runtime(&directory.path().join("left"), "Left").await;
        let right = runtime(&directory.path().join("right"), "Right").await;
        pair(&left, &right).await;
        let (local, remote) = parent(&left, &right).await;
        let before = left
            .endpoints
            .endpoints(&right.device_id())
            .await
            .unwrap()
            .into_iter()
            .map(|endpoint| endpoint.address)
            .collect::<Vec<_>>();
        let (outbound, inbound) = streams(&local, &remote).await;
        let left_id = left.device_id();
        let right_id = right.device_id();
        let (source, target) = tokio::join!(
            left.connect_input_relay(&right_id, outbound.send, outbound.receive),
            right.accept_input_relay(&left_id, inbound.send, inbound.receive)
        );
        let source = source.unwrap();
        let target = target.unwrap();
        assert!(source.is_relayed() && target.is_relayed());
        assert_eq!(target.peer().device_id, left.device_id());
        assert_eq!(target.peer().public_key, left.public_key());
        assert_eq!(source.peer().listen_port, right.local_port().unwrap());
        assert_eq!(
            before,
            left.endpoints
                .endpoints(&right.device_id())
                .await
                .unwrap()
                .into_iter()
                .map(|endpoint| endpoint.address)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            left.discovery().peer(&right.device_id()).unwrap().port,
            right.local_port().unwrap()
        );
        let _stream = source
            .open_feature_stream("arcrelay.input", b"original source")
            .await
            .unwrap();
        assert_eq!(
            target
                .accept_feature_stream()
                .await
                .unwrap()
                .opening_payload,
            b"original source".as_slice()
        );
        left.shutdown("shutdown relayed sessions too");
        tokio::time::timeout(Duration::from_secs(2), target.transport_handle().closed())
            .await
            .unwrap();
        right.shutdown("test complete");
    }

    #[tokio::test]
    async fn input_relay_cannot_substitute_the_middle_devices_identity() {
        let directory = tempfile::tempdir().unwrap();
        let source = runtime(&directory.path().join("source"), "Source").await;
        let middle = runtime(&directory.path().join("middle"), "Middle").await;
        let target = runtime(&directory.path().join("target"), "Target").await;
        pair(&source, &target).await;
        pair(&middle, &target).await;
        let (local, remote) = parent(&middle, &target).await;
        let (outbound, inbound) = streams(&local, &remote).await;
        let source_id = source.device_id();
        let target_id = target.device_id();
        let (_, accepted) = tokio::join!(
            middle.connect_input_relay(&target_id, outbound.send, outbound.receive),
            target.accept_input_relay(&source_id, inbound.send, inbound.receive)
        );
        assert!(matches!(accepted, Err(NetworkError::InvalidIdentity(_))));
        assert!(target
            .active(&source.device_id(), SessionKind::RealtimeInput)
            .await
            .is_none());
        for network in [source, middle, target] {
            network.shutdown("test complete");
        }
    }

    #[tokio::test]
    async fn input_relay_does_not_delegate_the_middle_peers_injection_grant() {
        let directory = tempfile::tempdir().unwrap();
        let source = runtime(&directory.path().join("source"), "Source").await;
        let target = runtime(&directory.path().join("target"), "Target").await;
        pair(&source, &target).await;
        target
            .revoke(
                &source.device_id(),
                CapabilityId::CrossScreenInject,
                GrantDirection::Inbound,
            )
            .await
            .unwrap();
        let (local, remote) = parent(&source, &target).await;
        let (outbound, inbound) = streams(&local, &remote).await;
        let source_id = source.device_id();
        let target_id = target.device_id();
        let (_, accepted) = tokio::join!(
            source.connect_input_relay(&target_id, outbound.send, outbound.receive),
            target.accept_input_relay(&source_id, inbound.send, inbound.receive)
        );
        assert!(matches!(accepted, Err(NetworkError::Unauthorized(_))));
        assert!(target
            .active(&source_id, SessionKind::RealtimeInput)
            .await
            .is_none());
        assert!(local.transport_handle().close_reason().is_none());
        source.shutdown("test complete");
        target.shutdown("test complete");
    }

    #[tokio::test]
    async fn restarted_source_can_replace_a_retained_direct_session_with_a_relay() {
        check_restarted_relay(false).await;
    }

    #[tokio::test]
    async fn restarted_listener_can_replace_an_opposite_direct_session_with_a_relay() {
        check_restarted_relay(true).await;
    }

    async fn check_restarted_relay(reverse_original_dial: bool) {
        let directory = tempfile::tempdir().unwrap();
        let identity_path = directory.path().join("source");
        let source = runtime(&identity_path, "Source").await;
        let target = runtime(&directory.path().join("target"), "Target").await;
        pair(&source, &target).await;
        let mut incoming = target.subscribe();
        let (_old_source, old_target) = if reverse_original_dial {
            let mut source_incoming = source.subscribe();
            let old_target = target
                .connect(&advertisement(&source), SessionKind::RealtimeInput)
                .await
                .unwrap();
            (source_incoming.recv().await.unwrap(), old_target)
        } else {
            let old_source = source
                .connect(&advertisement(&target), SessionKind::RealtimeInput)
                .await
                .unwrap();
            (old_source, incoming.recv().await.unwrap())
        };
        let mut config =
            NetworkRuntimeConfig::new(identity_path, source.metadata(), source.repository.clone());
        config.listen_address = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let restarted = NetworkRuntime::bind(config).await.unwrap();
        let (local, remote) = parent(&restarted, &target).await;
        let (outbound, inbound) = streams(&local, &remote).await;
        let source_id = restarted.device_id();
        let target_id = target.device_id();
        let (fresh_source, fresh_target) = tokio::join!(
            restarted.connect_input_relay(&target_id, outbound.send, outbound.receive),
            target.accept_input_relay(&source_id, inbound.send, inbound.receive)
        );
        let fresh_source = fresh_source.unwrap();
        let fresh_target = fresh_target.unwrap();
        assert!(fresh_source.is_relayed() && fresh_target.is_relayed());
        assert!(old_target.transport_handle().close_reason().is_some());
        assert!(fresh_target.transport_handle().close_reason().is_none());
        assert_ne!(old_target.id(), fresh_target.id());
        assert_eq!(
            fresh_target.peer_process_instance_id,
            Some(restarted.process_instance_id)
        );
        let _stream = fresh_source
            .open_feature_stream("arcrelay.input", b"restarted through relay")
            .await
            .unwrap();
        let feature =
            tokio::time::timeout(Duration::from_secs(2), fresh_target.accept_feature_stream())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            feature.opening_payload,
            b"restarted through relay".as_slice()
        );
        for network in [source, restarted, target] {
            network.shutdown("test complete");
        }
    }
}
