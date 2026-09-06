use super::*;
use arcrelay_peer::InMemoryPeerRepository;

#[tokio::test]
async fn reconnect_recovers_a_blocked_source_port_without_disrupting_other_sessions() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("source-port-left"), "Left").await;
    let right = runtime(&root.path().join("source-port-right"), "Right").await;
    let mut incoming = right.subscribe();
    let pair = left
        .connect(&advertisement(&right), SessionKind::Pairing)
        .await
        .unwrap();
    let remote_pair = incoming.recv().await.unwrap();
    left.confirm_pairing(&pair).await.unwrap();
    right.confirm_pairing(&remote_pair).await.unwrap();
    let retained = left
        .connect(&advertisement(&right), SessionKind::Print)
        .await
        .unwrap();
    let remote_retained = incoming.recv().await.unwrap();

    // Model the incident: the listener-to-listener UDP tuple is blackholed,
    // while the same destination accepts a fresh client source port.
    let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let server_address = advertisement(&right).connection_addresses[0];
    let blocked_port = left.local_port().unwrap();
    let blocked_packets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let blocked = blocked_packets.clone();
    let forwarder = tokio::spawn(async move {
        let mut client = None;
        let mut buffer = vec![0; 65_536];
        loop {
            let (length, source) = proxy.recv_from(&mut buffer).await.unwrap();
            if source == server_address {
                if let Some(client) = client {
                    proxy.send_to(&buffer[..length], client).await.unwrap();
                }
            } else if source.port() == blocked_port {
                blocked.fetch_add(1, Ordering::Relaxed);
            } else {
                client = Some(source);
                proxy
                    .send_to(&buffer[..length], server_address)
                    .await
                    .unwrap();
            }
        }
    });
    let mut peer = advertisement(&right);
    peer.connection_addresses = vec![proxy_address];
    peer.port = proxy_address.port();
    let recovered = tokio::time::timeout(
        Duration::from_secs(18),
        left.connect(&peer, SessionKind::RealtimeInput),
    )
    .await
    .expect("source-port recovery must be bounded")
    .expect("a fresh UDP source port must recover the authenticated session");
    let remote_recovered = incoming.recv().await.unwrap();
    assert!(blocked_packets.load(Ordering::Relaxed) > 0);
    assert_eq!(left.local_port().unwrap(), blocked_port);
    assert_eq!(remote_recovered.peer().listen_port, blocked_port);
    assert!(retained.transport_handle().close_reason().is_none());
    let _sent = retained
        .open_feature_stream("arcrelay.print", b"alive")
        .await
        .unwrap();
    assert_eq!(
        remote_retained
            .accept_feature_stream()
            .await
            .unwrap()
            .opening_payload,
        b"alive".as_slice()
    );
    assert_eq!(recovered.peer().device_id, right.device_id());
    drop(recovered);
    left.shutdown("test complete");
    tokio::time::timeout(
        Duration::from_secs(2),
        remote_recovered.transport_handle().closed(),
    )
    .await
    .expect("shutdown must also close recovered sessions");
    right.shutdown("test complete");
    forwarder.abort();
}

pub(super) async fn runtime(directory: &std::path::Path, name: &str) -> Arc<NetworkRuntime> {
    let repository: Arc<dyn PeerRepository> = Arc::new(InMemoryPeerRepository::default());
    let mut config = NetworkRuntimeConfig::new(
        directory.to_path_buf(),
        DeviceMetadata {
            name: name.into(),
            platform: "test".into(),
            model: "test".into(),
        },
        repository,
    );
    config.listen_address = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    NetworkRuntime::bind(config).await.unwrap()
}

#[tokio::test]
async fn closed_session_is_not_reported_online_while_registry_cleanup_is_pending() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("left-online"), "Left").await;
    let right = runtime(&root.path().join("right-online"), "Right").await;
    let mut incoming = right.subscribe();
    let session = left
        .connect(&advertisement(&right), SessionKind::Pairing)
        .await
        .unwrap();
    let _remote = incoming.recv().await.unwrap();
    assert_eq!(left.connected_peers().await, vec![right.device_id()]);
    session.close("transport lost");
    assert!(left.connected_peers().await.is_empty());
    left.shutdown("test complete");
    right.shutdown("test complete");
}

pub(super) fn advertisement(runtime: &NetworkRuntime) -> PeerAdvertisement {
    PeerAdvertisement {
        device_id: runtime.device_id(),
        public_key: runtime.identity.public_key_value(),
        metadata: runtime.metadata(),
        addresses: vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
        connection_addresses: vec![SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            runtime.local_port().unwrap(),
        )],
        port: runtime.local_port().unwrap(),
        certificate_sha256: runtime.identity.certificate_sha256(),
        last_seen_at_ms: now_ms(),
    }
}

#[tokio::test]
async fn direct_probe_authenticates_and_is_learned_in_both_directions() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("left-probe"), "Left Probe").await;
    let right = runtime(&root.path().join("right-probe"), "Right Probe").await;
    let mut right_incoming = right.subscribe();

    let discovered = left
        .discover_at("127.0.0.1", Some(right.local_port().unwrap()))
        .await
        .unwrap();
    assert_eq!(discovered.device_id, right.device_id());
    assert!(left.discovery().peer(&right.device_id()).is_some());

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if right.discovery().peer(&left.device_id()).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), right_incoming.recv())
            .await
            .is_err()
    );
    assert!(left.paired_peers().await.unwrap().is_empty());
    assert!(right.paired_peers().await.unwrap().is_empty());
}

#[tokio::test]
async fn disabled_discovery_rejects_an_unknown_probe() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("left-hidden"), "Left Hidden").await;
    let right = runtime(&root.path().join("right-hidden"), "Right Hidden").await;
    right.set_discoverable(false);

    let result = left
        .discover_at("127.0.0.1", Some(right.local_port().unwrap()))
        .await;
    assert!(result.is_err());
    assert!(right.discovery().peer(&left.device_id()).is_none());
}

#[tokio::test]
async fn pair_once_then_open_independent_feature_sessions() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("left"), "Left").await;
    let right = runtime(&root.path().join("right"), "Right").await;
    let mut right_incoming = right.subscribe();
    let right_before_pairing = advertisement(&right);
    let unpaired = left
        .connect_paired_at(
            &right_before_pairing.device_id,
            right_before_pairing.connection_addresses,
            SessionKind::RealtimeInput,
        )
        .await;
    assert!(matches!(unpaired, Err(NetworkError::Unpaired)));

    let left_pairing = left
        .connect(&advertisement(&right), SessionKind::Pairing)
        .await
        .unwrap();
    let right_pairing = tokio::time::timeout(Duration::from_secs(2), right_incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        left_pairing.verification_code(),
        right_pairing.verification_code()
    );
    left.confirm_pairing(&left_pairing).await.unwrap();
    right.confirm_pairing(&right_pairing).await.unwrap();
    assert_eq!(
        left.endpoints
            .endpoints(&right.device_id())
            .await
            .unwrap()
            .len(),
        1
    );

    let left_control = left
        .connect(&advertisement(&right), SessionKind::Control)
        .await
        .unwrap();
    let right_control = tokio::time::timeout(Duration::from_secs(2), right_incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(left_control.peer().listen_port, right.local_port().unwrap());
    assert_eq!(right_control.peer().listen_port, left.local_port().unwrap());
    assert_eq!(
        right.discovery().peer(&left.device_id()).unwrap().port,
        left.local_port().unwrap()
    );
    let opened = left_control
        .open_feature_stream("arcrelay.clipboard", b"subscribe")
        .await
        .unwrap();
    drop(opened);
    let accepted = right_control.accept_feature_stream().await.unwrap();
    assert_eq!(accepted.feature_id, "arcrelay.clipboard");
    assert_eq!(accepted.feature_major, 1);
    assert_eq!(accepted.min_feature_minor, 0);
    assert_eq!(accepted.max_feature_minor, 0);
    assert_eq!(accepted.negotiate_minor(1, 0, 0).unwrap(), 0);
    assert_ne!(accepted.stream_id, 0);
    assert_eq!(accepted.opening_payload, b"subscribe".as_slice());

    let right_advertisement = advertisement(&right);
    let left_realtime = left
        .connect_paired_at(
            &right_advertisement.device_id,
            right_advertisement.connection_addresses,
            SessionKind::RealtimeInput,
        )
        .await
        .unwrap();
    let right_realtime = tokio::time::timeout(Duration::from_secs(2), right_incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(left_realtime.peer().device_id, right.device_id());
    assert_eq!(right_realtime.peer().device_id, left.device_id());

    left_control.close("verify remembered reconnect");
    let remembered = left
        .connect_remembered(&right.device_id(), SessionKind::Print)
        .await
        .unwrap();
    assert_eq!(remembered.peer().device_id, right.device_id());
}

#[tokio::test]
async fn cross_screen_grant_preserves_control_and_reauthorizes_realtime_input() {
    let root = tempfile::tempdir().unwrap();
    let desktop = runtime(&root.path().join("desktop"), "Desktop").await;
    let phone = runtime(&root.path().join("phone"), "Phone").await;
    let mut incoming = phone.subscribe();
    let pairing = desktop
        .connect(&advertisement(&phone), SessionKind::Pairing)
        .await
        .unwrap();
    let paired = incoming.recv().await.unwrap();
    desktop.confirm_pairing(&pairing).await.unwrap();
    phone.confirm_pairing(&paired).await.unwrap();
    let control = desktop
        .connect(&advertisement(&phone), SessionKind::Control)
        .await
        .unwrap();
    let control_receiver = incoming.recv().await.unwrap();
    let realtime = desktop
        .connect(&advertisement(&phone), SessionKind::RealtimeInput)
        .await
        .unwrap();
    let realtime_receiver = incoming.recv().await.unwrap();
    assert!(phone
        .require(&realtime_receiver, CapabilityId::CrossScreenInject)
        .await
        .is_err());
    phone
        .grant(Grant {
            peer_id: desktop.device_id(),
            capability: CapabilityId::CrossScreenInject,
            direction: GrantDirection::Inbound,
            constraints: GrantConstraints::None,
            granted_at_ms: now_ms(),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), realtime.transport_handle().closed())
        .await
        .unwrap();
    assert!(phone
        .active(&desktop.device_id(), SessionKind::Control)
        .await
        .is_some());
    let _stream = control
        .open_feature_stream("arcrelay.control", b"still connected")
        .await
        .unwrap();
    let received = tokio::time::timeout(
        Duration::from_secs(2),
        control_receiver.accept_feature_stream(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received.opening_payload, b"still connected".as_slice());
    let _reconnected = desktop
        .connect(&advertisement(&phone), SessionKind::RealtimeInput)
        .await
        .unwrap();
    let authorized = incoming.recv().await.unwrap();
    phone
        .require(&authorized, CapabilityId::CrossScreenInject)
        .await
        .unwrap();
    desktop.shutdown("test complete");
    phone.shutdown("test complete");
}

#[tokio::test]
async fn many_discovered_interfaces_do_not_prevent_connecting_to_a_selected_host() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("left"), "Left").await;
    let right = runtime(&root.path().join("right"), "Right").await;
    let mut incoming = right.subscribe();
    let mut peer = advertisement(&right);
    let selected = peer.connection_addresses[0];
    // The selected address is deliberately beyond the dial budget in the
    // cached advertisement. Manual host selection must still reach it.
    peer.connection_addresses = (1..=20)
        .map(|n| {
            SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, n)),
                selected.port(),
            )
        })
        .collect();
    peer.connection_addresses.push(selected);
    left.discovery.observe_authenticated(peer).await;
    let direct = left
        .discover_at("127.0.0.1", Some(selected.port()))
        .await
        .unwrap();
    assert_eq!(direct.connection_addresses, vec![selected]);
    let session = tokio::time::timeout(
        Duration::from_secs(3),
        left.connect(&direct, SessionKind::Pairing),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(session.peer().device_id, right.device_id());
    let _remote = incoming.recv().await.unwrap();
    session.close("verify discovery dial budget");
    let mut broad = direct;
    broad.connection_addresses.extend((1..=20).map(|n| {
        SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, n)),
            selected.port(),
        )
    }));
    let session = tokio::time::timeout(
        Duration::from_secs(3),
        left.connect(&broad, SessionKind::Pairing),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(session.peer().device_id, right.device_id());
    left.shutdown("test complete");
    right.shutdown("test complete");
}

#[tokio::test]
async fn unpaired_file_transfer_session_is_allowed_but_control_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("left-nearby"), "Left Nearby").await;
    let right = runtime(&root.path().join("right-nearby"), "Right Nearby").await;
    let mut right_incoming = right.subscribe();
    let peer = advertisement(&right);

    let file_transfer = left
        .connect(&peer, SessionKind::FileTransfer)
        .await
        .unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(2), right_incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_transfer.kind(), SessionKind::FileTransfer);
    assert_eq!(incoming.kind(), SessionKind::FileTransfer);
    assert!(!right.is_paired_session(&incoming).await.unwrap());
    file_transfer.close("unpaired transfer test complete");

    let control = left.connect(&peer, SessionKind::Control).await;
    assert!(matches!(control, Err(NetworkError::Unpaired)));
}

#[tokio::test]
async fn concurrent_outbound_dials_share_one_active_session() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("left-concurrent"), "Left Concurrent").await;
    let right = runtime(&root.path().join("right-concurrent"), "Right Concurrent").await;
    let mut right_incoming = right.subscribe();

    let left_pairing = left
        .connect(&advertisement(&right), SessionKind::Pairing)
        .await
        .unwrap();
    let right_pairing = tokio::time::timeout(Duration::from_secs(2), right_incoming.recv())
        .await
        .unwrap()
        .unwrap();
    left.confirm_pairing(&left_pairing).await.unwrap();
    right.confirm_pairing(&right_pairing).await.unwrap();

    let peer = advertisement(&right);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let left = left.clone();
        let peer = peer.clone();
        tasks.push(tokio::spawn(async move {
            left.connect(&peer, SessionKind::Control).await.unwrap()
        }));
    }
    let mut sessions = Vec::new();
    for task in tasks {
        sessions.push(task.await.unwrap());
    }
    assert!(sessions
        .windows(2)
        .all(|pair| Arc::ptr_eq(&pair[0], &pair[1])));

    let inbound = tokio::time::timeout(Duration::from_secs(2), right_incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inbound.kind(), SessionKind::Control);
    assert!(
        tokio::time::timeout(Duration::from_millis(250), right_incoming.recv())
            .await
            .is_err()
    );

    let closed_session_id = sessions[0].id();
    sessions[0].close("test reconnect");
    let reconnected = left.connect(&peer, SessionKind::Control).await.unwrap();
    assert_ne!(reconnected.id(), closed_session_id);
    let reconnected_inbound = tokio::time::timeout(Duration::from_secs(2), right_incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reconnected_inbound.kind(), SessionKind::Control);
}

#[tokio::test]
async fn restarted_dialer_replaces_a_retained_control_session_without_waiting_for_timeout() {
    check_restarted_control_session(false).await;
}

#[tokio::test]
async fn restarted_listener_replaces_the_old_opposite_direction_before_quic_timeout() {
    check_restarted_control_session(true).await;
}

async fn check_restarted_control_session(reverse_original_dial: bool) {
    let root = tempfile::tempdir().unwrap();
    let left_directory = root.path().join("restart-left");
    let right_directory = root.path().join("restart-right");
    let left = runtime(&left_directory, "Left").await;
    let right = runtime(&right_directory, "Right").await;
    // Keep the surviving peer's original dial direction preferred by rank.
    let (left, left_directory, right) =
        if reverse_original_dial && left.device_id() < right.device_id() {
            (right, right_directory, left)
        } else {
            (left, left_directory, right)
        };
    let mut incoming = right.subscribe();
    let peer = advertisement(&right);
    let pairing = left.connect(&peer, SessionKind::Pairing).await.unwrap();
    let inbound_pairing = incoming.recv().await.unwrap();
    left.confirm_pairing(&pairing).await.unwrap();
    right.confirm_pairing(&inbound_pairing).await.unwrap();

    let (old_left, old_right) = if reverse_original_dial {
        let mut left_incoming = left.subscribe();
        let old_right = right
            .connect(&advertisement(&left), SessionKind::Control)
            .await
            .unwrap();
        (left_incoming.recv().await.unwrap(), old_right)
    } else {
        let old_left = left.connect(&peer, SessionKind::Control).await.unwrap();
        (old_left, incoming.recv().await.unwrap())
    };
    // Keep the old transport alive to model the server's view after an abrupt
    // client restart: it has not received a close and QUIC has not timed out.
    // Force the old random rank to win so the regression is deterministic.
    right
        .sessions
        .lock()
        .await
        .get_mut(&(left.device_id(), SessionKind::Control))
        .unwrap()
        .rank
        .initiator_nonce = vec![0; 32];

    let mut config =
        NetworkRuntimeConfig::new(left_directory, left.metadata(), left.repository.clone());
    config.listen_address = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let restarted = NetworkRuntime::bind(config).await.unwrap();
    assert_eq!(restarted.device_id(), left.device_id());
    let fresh_outbound = restarted
        .connect(&peer, SessionKind::Control)
        .await
        .unwrap();
    let fresh_inbound = tokio::time::timeout(Duration::from_secs(2), incoming.recv())
        .await
        .expect("restarted client must be published before the old session times out")
        .unwrap();
    assert_ne!(fresh_inbound.id(), old_right.id());
    assert!(old_right.connection.close_reason().is_some());
    assert!(fresh_inbound.connection.close_reason().is_none());
    assert_ne!(left.process_instance_id, restarted.process_instance_id);
    assert_eq!(
        fresh_inbound.peer_process_instance_id,
        Some(restarted.process_instance_id)
    );

    let _stream = fresh_outbound
        .open_feature_stream("arcrelay.control", b"restarted")
        .await
        .unwrap();
    let accepted = tokio::time::timeout(
        Duration::from_secs(2),
        fresh_inbound.accept_feature_stream(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(accepted.opening_payload, b"restarted".as_slice());
    // Re-registering the winner itself must be harmless.
    let registered = right.register_session(fresh_inbound.clone()).await.unwrap();
    assert!(Arc::ptr_eq(&registered, &fresh_inbound));
    assert!(fresh_inbound.connection.close_reason().is_none());

    // A delayed completion from the retired process must not resurrect the
    // original session, including when it had the preferred dial direction.
    let retained = right.register_session(old_right.clone()).await.unwrap();
    assert!(Arc::ptr_eq(&retained, &fresh_inbound));
    assert!(fresh_inbound.connection.close_reason().is_none());

    // A second authenticated handshake still carrying the retired process ID
    // is obsolete too; checking only whether the old Session was closed would
    // not protect against this late completion.
    old_left.close("force a late handshake from the retired process");
    if let Ok(obsolete) = left.connect(&peer, SessionKind::Control).await {
        tokio::time::timeout(Duration::from_secs(2), obsolete.connection.closed())
            .await
            .expect("a retired process must not regain the live session");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), incoming.recv())
            .await
            .is_err(),
        "retired process handshakes must not reach feature subscribers"
    );
    assert!(fresh_inbound.connection.close_reason().is_none());

    drop(old_left);
    restarted.shutdown("test complete");
    left.shutdown("test complete");
    right.shutdown("test complete");
}

#[tokio::test]
async fn opposing_dials_still_converge_on_one_initiator() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("opposing-left"), "Left").await;
    let right = runtime(&root.path().join("opposing-right"), "Right").await;
    let _left_incoming = left.subscribe();
    let mut right_incoming = right.subscribe();
    let left_peer = advertisement(&left);
    let right_peer = advertisement(&right);
    let pairing = left
        .connect(&right_peer, SessionKind::Pairing)
        .await
        .unwrap();
    let inbound_pairing = right_incoming.recv().await.unwrap();
    left.confirm_pairing(&pairing).await.unwrap();
    right.confirm_pairing(&inbound_pairing).await.unwrap();

    // Bypass the active-session shortcut so both sides really dial, even if
    // one handshake finishes before the other starts on a slow test machine.
    let (left_result, right_result) = tokio::join!(
        left.race_endpoints(
            right_peer.connection_addresses.clone(),
            dial::ExpectedPeer::Advertised(right_peer),
            SessionKind::Control,
            EndpointSource::Mdns,
        ),
        right.race_endpoints(
            left_peer.connection_addresses.clone(),
            dial::ExpectedPeer::Advertised(left_peer),
            SessionKind::Control,
            EndpointSource::Mdns,
        ),
    );
    assert!(left_result.is_ok() || right_result.is_ok());
    let left_active = left
        .active(&right.device_id(), SessionKind::Control)
        .await
        .unwrap();
    let right_active = right
        .active(&left.device_id(), SessionKind::Control)
        .await
        .unwrap();
    let winner = left.device_id().min(right.device_id());
    assert_eq!(left_active.initiator_id(), &winner);
    assert_eq!(right_active.initiator_id(), &winner);
    let _stream = left_active
        .open_feature_stream("arcrelay.control", b"winner")
        .await
        .unwrap();
    let accepted =
        tokio::time::timeout(Duration::from_secs(2), right_active.accept_feature_stream())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(accepted.opening_payload, b"winner".as_slice());
    left.shutdown("test complete");
    right.shutdown("test complete");
}

#[tokio::test]
async fn authenticated_dial_race_bypasses_a_silent_first_endpoint() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("race-left"), "Left").await;
    let right = runtime(&root.path().join("race-right"), "Right").await;
    let mut incoming = right.subscribe();
    // An open UDP socket that never responds reproduces an IPv6 or stale route
    // black hole without relying on external network conditions.
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut peer = advertisement(&right);
    peer.connection_addresses
        .insert(0, blackhole.local_addr().unwrap());
    let session = tokio::time::timeout(
        Duration::from_secs(3),
        left.connect(&peer, SessionKind::Pairing),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(session.peer().device_id, right.device_id());
    let inbound = incoming.recv().await.unwrap();
    assert_eq!(inbound.peer().device_id, left.device_id());
    left.shutdown("test finished");
    right.shutdown("test finished");
}

#[tokio::test]
async fn authenticated_dial_race_rejects_a_faster_wrong_identity() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("race-left"), "Left").await;
    let right = runtime(&root.path().join("race-right"), "Right").await;
    let mut incoming = right.subscribe();
    let wrong = runtime(&root.path().join("race-wrong"), "Wrong").await;
    let mut peer = advertisement(&right);
    peer.connection_addresses
        .insert(0, advertisement(&wrong).connection_addresses[0]);
    let session = tokio::time::timeout(
        Duration::from_secs(3),
        left.connect(&peer, SessionKind::Pairing),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(session.peer().device_id, right.device_id());
    let inbound = incoming.recv().await.unwrap();
    assert_eq!(inbound.peer().device_id, left.device_id());
    assert!(!left.connected_peers().await.contains(&wrong.device_id()));
    left.shutdown("test finished");
    right.shutdown("test finished");
    wrong.shutdown("test finished");
}

#[tokio::test]
async fn a_stalled_header_does_not_block_an_independent_feature_stream() {
    let root = tempfile::tempdir().unwrap();
    let left = runtime(&root.path().join("headers-left"), "Left").await;
    let right = runtime(&root.path().join("headers-right"), "Right").await;
    let mut incoming = right.subscribe();
    let outgoing = left
        .connect(&advertisement(&right), SessionKind::Pairing)
        .await
        .unwrap();
    let incoming = incoming.recv().await.unwrap();
    let (mut stalled, _receive) = outgoing.transport_handle().open_bi().await.unwrap();
    stalled.write_all(&100_u32.to_be_bytes()).await.unwrap();
    let _valid = outgoing
        .open_feature_stream_versioned("arcrelay.transfer", 1, 0, 0, "offer", b"")
        .await
        .unwrap();
    let stream = tokio::time::timeout(Duration::from_secs(1), incoming.accept_feature_stream())
        .await
        .expect("another header must not wait for the stalled header deadline")
        .unwrap();
    assert_eq!(stream.operation, "offer");
    let _ = stalled.reset(0_u32.into());
    left.shutdown("test finished");
    right.shutdown("test finished");
}
