use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) enum Direction {
    Inbound,
    Outbound,
}

// Keeping both interval bounds explicit makes this remain correct when a later
// v1 release raises the minimum supported minor above zero.
#[allow(clippy::absurd_extreme_comparisons)]
pub(super) fn validate_hello(
    hello: &common::SessionHello,
    expected_kind: Option<SessionKind>,
) -> Result<SessionPeer, NetworkError> {
    if hello.protocol_major != arcrelay_wire::PROTOCOL_MAJOR
        || hello.min_protocol_minor > hello.max_protocol_minor
        || hello.max_protocol_minor < arcrelay_wire::MIN_PROTOCOL_MINOR
        || hello.min_protocol_minor > arcrelay_wire::MAX_PROTOCOL_MINOR
        || hello.nonce.len() != 32
        || hello.endpoint_certificate_sha256.len() != 32
        || hello.device_name.len() > 255
        || hello.platform.len() > 64
        || hello.model.len() > 255
    {
        return Err(NetworkError::Protocol("invalid session hello".into()));
    }
    let kind = SessionKind::decode(hello.session_kind)?;
    if expected_kind.is_some_and(|expected| expected != kind) {
        return Err(NetworkError::Protocol("session kind mismatch".into()));
    }
    let device_id = DeviceId::parse(&hello.device_id)
        .map_err(|error| NetworkError::InvalidIdentity(error.to_string()))?;
    let public_key = DevicePublicKey::from_bytes(hello.root_public_key.to_vec())
        .map_err(|error| NetworkError::InvalidIdentity(error.to_string()))?;
    device_id
        .verify_key(&public_key)
        .map_err(|error| NetworkError::InvalidIdentity(error.to_string()))?;
    let certificate_sha256: [u8; 32] = hello
        .endpoint_certificate_sha256
        .as_ref()
        .try_into()
        .map_err(|_| NetworkError::InvalidIdentity("certificate digest length".into()))?;
    let signature = DeviceSignature::from_bytes(hello.endpoint_binding_signature.to_vec())
        .map_err(|error| NetworkError::InvalidIdentity(error.to_string()))?;
    verify_signature(
        &public_key,
        SigningContext::EndpointBinding,
        &certificate_sha256,
        &signature,
    )?;
    Ok(SessionPeer {
        device_id,
        public_key,
        metadata: DeviceMetadata {
            name: hello.device_name.clone(),
            platform: hello.platform.clone(),
            model: hello.model.clone(),
        },
        certificate_sha256,
        listen_port: 0,
    })
}

pub(super) fn negotiate_protocol_minor(
    local: &common::SessionHello,
    remote: &common::SessionHello,
) -> Result<u32, NetworkError> {
    let minimum = local.min_protocol_minor.max(remote.min_protocol_minor);
    let maximum = local.max_protocol_minor.min(remote.max_protocol_minor);
    (minimum <= maximum)
        .then_some(maximum)
        .ok_or_else(|| NetworkError::Protocol("no compatible protocol minor version".into()))
}

pub(super) fn validate_process_instance_id(value: &[u8]) -> Result<Option<[u8; 16]>, NetworkError> {
    if value.is_empty() {
        return Ok(None);
    }
    value
        .try_into()
        .map(Some)
        .map_err(|_| NetworkError::Protocol("invalid peer process instance id".into()))
}

pub(super) fn session_transcript(
    connection: &quinn::Connection,
    local: &common::SessionHello,
    remote: &common::SessionHello,
) -> Result<Vec<u8>, NetworkError> {
    let mut exporter = [0_u8; 32];
    connection
        .export_keying_material(&mut exporter, TLS_EXPORTER_LABEL, b"")
        .map_err(|_| NetworkError::Tls("TLS exporter is unavailable".into()))?;
    let (first, second) = if local.device_id <= remote.device_id {
        (local, remote)
    } else {
        (remote, local)
    };
    let mut transcript = b"arcrelay.session-transcript.v1\0".to_vec();
    append_message(&mut transcript, first)?;
    append_message(&mut transcript, second)?;
    transcript.extend_from_slice(&exporter);
    Ok(transcript)
}

pub(super) fn append_message<M: Message>(
    target: &mut Vec<u8>,
    message: &M,
) -> Result<(), NetworkError> {
    let mut encoded = Vec::with_capacity(message.encoded_len());
    message
        .encode(&mut encoded)
        .map_err(|error| NetworkError::Protocol(error.to_string()))?;
    target.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    target.extend_from_slice(&encoded);
    Ok(())
}

pub(super) fn verification_code(transcript: &[u8]) -> String {
    let digest = Sha256::digest(transcript);
    let number = u32::from_be_bytes(digest[..4].try_into().expect("four-byte digest prefix"));
    format!("{:06}", number % 1_000_000)
}

pub(super) async fn send_message<M: Message>(
    send: &mut quinn::SendStream,
    message: &M,
) -> Result<(), NetworkError> {
    send_message_with_limit(send, message, HANDSHAKE_FRAME_LIMIT).await
}

pub(super) async fn send_message_with_limit<M: Message>(
    send: &mut quinn::SendStream,
    message: &M,
    limit: usize,
) -> Result<(), NetworkError> {
    let mut bytes = Vec::with_capacity(message.encoded_len());
    message
        .encode(&mut bytes)
        .map_err(|error| NetworkError::Protocol(error.to_string()))?;
    write_frame(send, &bytes, limit).await?;
    Ok(())
}

pub(super) async fn receive_message<M: Message + Default>(
    receive: &mut quinn::RecvStream,
) -> Result<M, NetworkError> {
    receive_message_with_limit(receive, HANDSHAKE_FRAME_LIMIT).await
}

pub(super) async fn receive_message_with_limit<M: Message + Default>(
    receive: &mut quinn::RecvStream,
    limit: usize,
) -> Result<M, NetworkError> {
    let bytes = read_frame(receive, limit).await?;
    M::decode(bytes.as_slice()).map_err(|error| NetworkError::Protocol(error.to_string()))
}

pub(super) fn observed_certificate_sha256(
    connection: &quinn::Connection,
) -> Result<[u8; 32], NetworkError> {
    let certificate = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certificates| certificates.first().cloned())
        .ok_or_else(|| NetworkError::InvalidIdentity("peer TLS certificate is missing".into()))?;
    Ok(Sha256::digest(certificate.as_ref()).into())
}

pub(super) fn bind_socket(address: IpAddr, port: u16) -> Result<std::net::UdpSocket, NetworkError> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if address.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket.bind(&SocketAddr::new(address, port).into())?;
    let socket: std::net::UdpSocket = socket.into();
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub fn reserve_udp_socket(address: IpAddr, port: u16) -> Result<std::net::UdpSocket, NetworkError> {
    bind_socket(address, port)
}

pub(super) fn client_config() -> Result<quinn::ClientConfig, NetworkError> {
    let mut tls = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    tls.alpn_protocols = vec![arcrelay_wire::ALPN.to_vec()];
    let quic =
        QuicClientConfig::try_from(tls).map_err(|error| NetworkError::Tls(error.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic));
    config.transport_config(transport_config());
    Ok(config)
}

#[derive(Debug)]
pub(super) struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub(super) fn random_nonzero_u64() -> u64 {
    rand::rngs::OsRng.next_u64().max(1)
}

pub(super) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_instance_allows_legacy_absence_and_rejects_malformed_ids() {
        assert_eq!(validate_process_instance_id(&[]).unwrap(), None);
        assert_eq!(
            validate_process_instance_id(&[7; 16]).unwrap(),
            Some([7; 16])
        );
        for length in [1, 15, 17, 32] {
            assert!(validate_process_instance_id(&vec![7; length]).is_err());
        }
    }

    #[test]
    fn minor_negotiation_selects_highest_common_version() {
        let local = common::SessionHello {
            min_protocol_minor: 1,
            max_protocol_minor: 4,
            ..Default::default()
        };
        let remote = common::SessionHello {
            min_protocol_minor: 2,
            max_protocol_minor: 3,
            ..Default::default()
        };
        assert_eq!(negotiate_protocol_minor(&local, &remote).unwrap(), 3);
    }

    #[test]
    fn minor_negotiation_rejects_disjoint_ranges() {
        let local = common::SessionHello {
            min_protocol_minor: 0,
            max_protocol_minor: 1,
            ..Default::default()
        };
        let remote = common::SessionHello {
            min_protocol_minor: 2,
            max_protocol_minor: 3,
            ..Default::default()
        };
        assert!(negotiate_protocol_minor(&local, &remote).is_err());
    }
}
