use super::*;

#[derive(Debug, Clone)]
pub struct SessionPeer {
    pub device_id: DeviceId,
    pub public_key: DevicePublicKey,
    pub metadata: DeviceMetadata,
    pub certificate_sha256: [u8; 32],
    pub listen_port: u16,
}

pub struct Session {
    pub(super) peer_process_instance_id: Option<[u8; 16]>,
    pub(super) relay_tunnel: std::sync::OnceLock<Arc<super::relay::RelayTunnel>>,
    // A recovered connection keeps its client socket on the same long-lived
    // runtime, without rebinding the listener or moving unrelated sessions.
    pub(super) recovery_endpoint: std::sync::OnceLock<Arc<quinn::Endpoint>>,
    pub(super) pending_headers:
        tokio::sync::Mutex<tokio::task::JoinSet<Result<FeatureStream, NetworkError>>>,
    pub(super) _dial_selection: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(super) id: u64,
    pub(super) kind: SessionKind,
    pub(super) peer: SessionPeer,
    pub(super) verification_code: String,
    pub(super) rank: SessionRank,
    pub(super) connection: quinn::Connection,
    pub(super) protocol_minor: u32,
}

impl Session {
    pub fn is_relayed(&self) -> bool {
        self.relay_tunnel.get().is_some()
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn kind(&self) -> SessionKind {
        self.kind
    }

    pub fn protocol_minor(&self) -> u32 {
        self.protocol_minor
    }

    pub fn peer(&self) -> &SessionPeer {
        &self.peer
    }

    /// Device that initiated the physical session. Feature adapters use this
    /// to ensure only the initiator opens the session's primary feature stream.
    pub fn initiator_id(&self) -> &DeviceId {
        &self.rank.initiator_id
    }

    /// Six-digit SAS shown on both devices during pairing.
    pub fn verification_code(&self) -> &str {
        &self.verification_code
    }

    pub async fn open_feature_stream(
        &self,
        feature_id: impl Into<String>,
        opening_payload: &[u8],
    ) -> Result<FeatureStream, NetworkError> {
        self.open_feature_stream_versioned(feature_id, 1, 0, 0, "", opening_payload)
            .await
    }

    pub async fn open_feature_stream_versioned(
        &self,
        feature_id: impl Into<String>,
        feature_major: u32,
        min_feature_minor: u32,
        max_feature_minor: u32,
        operation: impl Into<String>,
        opening_payload: &[u8],
    ) -> Result<FeatureStream, NetworkError> {
        let feature_id = feature_id.into();
        let operation = operation.into();
        if !valid_feature_id(&feature_id)
            || feature_major == 0
            || min_feature_minor > max_feature_minor
            || !valid_operation(&operation)
        {
            return Err(NetworkError::Protocol(
                "invalid local feature stream header".into(),
            ));
        }
        let (mut send, receive) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::Quic(error.to_string()))?;
        let header = common::FeaturePayload {
            feature_id,
            body: opening_payload.to_vec().into(),
            feature_major,
            min_feature_minor,
            max_feature_minor,
            stream_id: super::random_nonzero_u64(),
            operation,
        };
        send_message_with_limit(&mut send, &header, FEATURE_HEADER_LIMIT).await?;
        Ok(FeatureStream {
            feature_id: header.feature_id,
            opening_payload: header.body,
            feature_major: header.feature_major,
            min_feature_minor: header.min_feature_minor,
            max_feature_minor: header.max_feature_minor,
            stream_id: header.stream_id,
            operation: header.operation,
            send,
            receive,
        })
    }

    /// Incomplete headers occupy one of eight bounded parsing slots, not the
    /// entire session. Dropping the caller preserves already accepted streams.
    pub async fn accept_feature_stream(&self) -> Result<FeatureStream, NetworkError> {
        let mut pending = self.pending_headers.lock().await;
        loop {
            tokio::select! {
                biased;
                closed = self.connection.closed() => return Err(NetworkError::Quic(closed.to_string())),
                result = pending.join_next(), if !pending.is_empty() => match result {
                    Some(Ok(Ok(stream))) => return Ok(stream),
                    Some(Ok(Err(error))) => tracing::debug!(%error, "feature stream header rejected"),
                    Some(Err(error)) => tracing::warn!(%error, "feature stream header task failed"),
                    None => {},
                },
                incoming = self.connection.accept_bi(), if pending.len() < 8 => {
                    let (send, receive) = incoming.map_err(|e| NetworkError::Quic(e.to_string()))?;
                    pending.spawn(Self::read_feature_header(send, receive));
                }
            }
        }
    }

    async fn read_feature_header(
        mut send: quinn::SendStream,
        mut receive: quinn::RecvStream,
    ) -> Result<FeatureStream, NetworkError> {
        let header: common::FeaturePayload = match tokio::time::timeout(
            Duration::from_secs(5),
            receive_message_with_limit(&mut receive, FEATURE_HEADER_LIMIT),
        )
        .await
        {
            Ok(Ok(header)) => header,
            result => {
                let _ = send.reset(400_u32.into());
                let _ = receive.stop(400_u32.into());
                return Err(match result {
                    Ok(Err(error)) => error,
                    _ => NetworkError::Timeout,
                });
            }
        };
        if !valid_feature_id(&header.feature_id)
            || header.feature_major == 0
            || header.min_feature_minor > header.max_feature_minor
            || header.stream_id == 0
            || !valid_operation(&header.operation)
        {
            let _ = send.reset(400_u32.into());
            let _ = receive.stop(400_u32.into());
            return Err(NetworkError::Protocol(
                "invalid feature stream header".into(),
            ));
        }
        Ok(FeatureStream {
            feature_id: header.feature_id,
            opening_payload: header.body,
            feature_major: header.feature_major,
            min_feature_minor: header.min_feature_minor,
            max_feature_minor: header.max_feature_minor,
            stream_id: header.stream_id,
            operation: header.operation,
            send,
            receive,
        })
    }

    pub fn send_datagram(&self, bytes: Bytes) -> Result<(), NetworkError> {
        self.connection
            .send_datagram(bytes)
            .map_err(|error| NetworkError::Quic(error.to_string()))
    }

    pub async fn read_datagram(&self) -> Result<Bytes, NetworkError> {
        self.connection
            .read_datagram()
            .await
            .map_err(|error| NetworkError::Quic(error.to_string()))
    }

    pub fn close(&self, reason: &str) {
        self.connection.close(0_u32.into(), reason.as_bytes());
    }

    /// Adapter hook for feature-specific protobuf handlers. Endpoint creation
    /// and authentication remain owned by this crate; feature code must never
    /// construct or dial this handle.
    #[doc(hidden)]
    pub fn transport_handle(&self) -> quinn::Connection {
        self.connection.clone()
    }
}

fn valid_feature_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

fn valid_operation(value: &str) -> bool {
    value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

pub struct FeatureStream {
    pub feature_id: String,
    pub opening_payload: Bytes,
    pub feature_major: u32,
    pub min_feature_minor: u32,
    pub max_feature_minor: u32,
    pub stream_id: u64,
    pub operation: String,
    pub send: quinn::SendStream,
    pub receive: quinn::RecvStream,
}

impl FeatureStream {
    pub fn negotiate_minor(
        &self,
        supported_major: u32,
        supported_min_minor: u32,
        supported_max_minor: u32,
    ) -> Result<u32, NetworkError> {
        if self.feature_major != supported_major || supported_min_minor > supported_max_minor {
            return Err(NetworkError::Protocol(
                "unsupported feature major version".into(),
            ));
        }
        let minimum = self.min_feature_minor.max(supported_min_minor);
        let maximum = self.max_feature_minor.min(supported_max_minor);
        (minimum <= maximum)
            .then_some(maximum)
            .ok_or_else(|| NetworkError::Protocol("no compatible feature minor version".into()))
    }
}
