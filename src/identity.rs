use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use arcrelay_peer::{
    DeviceId, DeviceKeyProvider, DevicePublicKey, DeviceSignature, SigningContext,
};
use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use quinn::crypto::rustls::QuicServerConfig;
use rand::rngs::OsRng;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

use crate::NetworkError;

const ROOT_KEY_FILE: &str = "device-root.ed25519";
const TLS_CERT_FILE: &str = "endpoint-cert.der";
const TLS_KEY_FILE: &str = "endpoint-key.der";

/// The sole cryptographic identity of an ArcRelay installation. TLS endpoint
/// keys may rotate; the Ed25519 root key and its derived DeviceId do not.
pub struct DeviceIdentity {
    signing_key: Arc<SigningKey>,
    certificate_der: Vec<u8>,
    certificate_sha256: [u8; 32],
    server_config: quinn::ServerConfig,
}

impl DeviceIdentity {
    pub fn load_or_create(directory: &Path) -> Result<Arc<Self>, NetworkError> {
        std::fs::create_dir_all(directory)?;
        harden_directory(directory)?;
        let signing_key = load_or_create_root(&directory.join(ROOT_KEY_FILE))?;
        let (certificate_der, private_key_der) = load_or_create_tls(directory)?;
        let certificate_sha256 = Sha256::digest(&certificate_der).into();
        let server_config = server_config(&certificate_der, &private_key_der)?;
        Ok(Arc::new(Self {
            signing_key: Arc::new(signing_key),
            certificate_der,
            certificate_sha256,
            server_config,
        }))
    }

    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_public_key(&self.public_key_value())
    }

    pub fn public_key_value(&self) -> DevicePublicKey {
        DevicePublicKey::from_bytes(self.signing_key.verifying_key().to_bytes().to_vec())
            .expect("Ed25519 public keys always contain 32 bytes")
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn certificate_sha256(&self) -> [u8; 32] {
        self.certificate_sha256
    }

    pub fn endpoint_binding_signature(&self) -> DeviceSignature {
        self.sign(SigningContext::EndpointBinding, &self.certificate_sha256)
    }

    pub fn server_config(&self) -> quinn::ServerConfig {
        self.server_config.clone()
    }

    pub fn sign(&self, context: SigningContext, message: &[u8]) -> DeviceSignature {
        let transcript = signing_transcript(context, message);
        DeviceSignature::from_bytes(self.signing_key.sign(&transcript).to_bytes().to_vec())
            .expect("Ed25519 signatures always contain 64 bytes")
    }
}

#[async_trait]
impl DeviceKeyProvider for DeviceIdentity {
    async fn public_key(
        &self,
    ) -> Result<DevicePublicKey, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.public_key_value())
    }

    async fn sign(
        &self,
        context: SigningContext,
        message: &[u8],
    ) -> Result<DeviceSignature, Box<dyn std::error::Error + Send + Sync>> {
        Ok(DeviceIdentity::sign(self, context, message))
    }
}

pub fn verify_signature(
    public_key: &DevicePublicKey,
    context: SigningContext,
    message: &[u8],
    signature: &DeviceSignature,
) -> Result<(), NetworkError> {
    let key: [u8; 32] = public_key
        .as_bytes()
        .try_into()
        .map_err(|_| NetworkError::InvalidIdentity("public key length".into()))?;
    let signature = Signature::from_slice(signature.as_bytes())
        .map_err(|_| NetworkError::InvalidIdentity("signature length".into()))?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| NetworkError::InvalidIdentity("public key".into()))?
        .verify_strict(&signing_transcript(context, message), &signature)
        .map_err(|_| NetworkError::InvalidIdentity("signature verification".into()))
}

fn signing_transcript(context: SigningContext, message: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(context.domain().len() + 8 + message.len());
    transcript.extend_from_slice(context.domain());
    transcript.extend_from_slice(&(message.len() as u64).to_be_bytes());
    transcript.extend_from_slice(message);
    transcript
}

fn load_or_create_root(path: &Path) -> Result<SigningKey, NetworkError> {
    if path.exists() {
        let bytes: [u8; 32] = std::fs::read(path)?
            .try_into()
            .map_err(|_| NetworkError::InvalidIdentity("stored root key length".into()))?;
        return Ok(SigningKey::from_bytes(&bytes));
    }
    let key = SigningKey::generate(&mut OsRng);
    private_write(path, &key.to_bytes())?;
    Ok(key)
}

fn load_or_create_tls(directory: &Path) -> Result<(Vec<u8>, Vec<u8>), NetworkError> {
    let certificate_path = directory.join(TLS_CERT_FILE);
    let key_path = directory.join(TLS_KEY_FILE);
    if certificate_path.exists() && key_path.exists() {
        return Ok((std::fs::read(certificate_path)?, std::fs::read(key_path)?));
    }
    let generated = generate_simple_self_signed(vec!["ArcRelay".into(), "localhost".into()])
        .map_err(|error| NetworkError::Tls(error.to_string()))?;
    let certificate = generated.cert.der().to_vec();
    let key = generated.key_pair.serialize_der();
    private_write(&certificate_path, &certificate)?;
    private_write(&key_path, &key)?;
    Ok((certificate, key))
}

fn server_config(
    certificate_der: &[u8],
    private_key_der: &[u8],
) -> Result<quinn::ServerConfig, NetworkError> {
    let certificate = CertificateDer::from(certificate_der.to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der.to_vec()));
    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .map_err(|error| NetworkError::Tls(error.to_string()))?;
    tls.alpn_protocols = vec![arcrelay_wire::ALPN.to_vec()];
    let quic =
        QuicServerConfig::try_from(tls).map_err(|error| NetworkError::Tls(error.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    config.transport_config(transport_config());
    Ok(config)
}

pub(crate) fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.initial_rtt(std::time::Duration::from_millis(20));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport.max_concurrent_bidi_streams(64_u32.into());
    transport.max_concurrent_uni_streams(32_u32.into());
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(transport)
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<(), NetworkError> {
    let parent = path
        .parent()
        .ok_or_else(|| NetworkError::InvalidIdentity("identity path has no parent".into()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| NetworkError::InvalidIdentity("invalid identity file name".into()))?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{:016x}",
        rand::RngCore::next_u64(&mut OsRng)
    ));
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let result = (|| -> Result<(), std::io::Error> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

fn harden_directory(path: &Path) -> Result<(), NetworkError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_and_binds_endpoint_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let first = DeviceIdentity::load_or_create(directory.path()).unwrap();
        let second = DeviceIdentity::load_or_create(directory.path()).unwrap();
        assert_eq!(first.device_id(), second.device_id());
        assert_eq!(first.certificate_sha256(), second.certificate_sha256());
        verify_signature(
            &first.public_key_value(),
            SigningContext::EndpointBinding,
            &first.certificate_sha256(),
            &first.endpoint_binding_signature(),
        )
        .unwrap();
    }
}
