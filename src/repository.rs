use std::net::SocketAddr;
use std::path::Path;

use arcrelay_peer::{
    CapabilityId, DeviceId, DevicePublicKey, Grant, GrantDirection, PeerRecord, PeerRepository,
    RepositoryError, TrustState,
};
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};

use crate::endpoint::network_scope;
use crate::{EndpointRepository, EndpointSource, NetworkError, RememberedEndpoint};

/// Durable, process-safe peer and authorization repository. This is the only
/// trust database used by all LAN features.
#[derive(Clone)]
pub struct SqlitePeerRepository {
    pool: SqlitePool,
}

impl SqlitePeerRepository {
    pub async fn open(path: &Path) -> Result<Self, RepositoryError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(backend)?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            // Peer metadata is small and infrequently updated. Each SQLite
            // connection owns an OS worker thread, so keep one spare reader.
            .max_connections(2)
            .idle_timeout(std::time::Duration::from_secs(30))
            .connect_with(options)
            .await
            .map_err(backend)?;
        let repository = Self { pool };
        repository.migrate().await?;
        Ok(repository)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn migrate(&self) -> Result<(), RepositoryError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS peers (\
             device_id TEXT PRIMARY KEY NOT NULL,\
             public_key BLOB NOT NULL,\
             display_name TEXT NOT NULL,\
             platform TEXT NOT NULL,\
             model TEXT NOT NULL,\
             trust_state INTEGER NOT NULL,\
             auto_connect INTEGER NOT NULL DEFAULT 1,\
             paired_at_ms INTEGER NOT NULL,\
             updated_at_ms INTEGER NOT NULL\
             ) STRICT",
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        let peer_columns = sqlx::query("PRAGMA table_info(peers)")
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?;
        if !peer_columns.iter().any(|row| {
            row.try_get::<String, _>("name")
                .is_ok_and(|name| name == "auto_connect")
        }) {
            sqlx::query("ALTER TABLE peers ADD COLUMN auto_connect INTEGER NOT NULL DEFAULT 1")
                .execute(&self.pool)
                .await
                .map_err(backend)?;
        }
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS grants (\
             peer_id TEXT NOT NULL REFERENCES peers(device_id) ON DELETE CASCADE,\
             capability TEXT NOT NULL,\
             direction INTEGER NOT NULL,\
             constraints_json TEXT NOT NULL,\
             granted_at_ms INTEGER NOT NULL,\
             PRIMARY KEY (peer_id, capability, direction)\
             ) STRICT",
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS peer_endpoints (\
             peer_id TEXT NOT NULL REFERENCES peers(device_id) ON DELETE CASCADE,\
             address TEXT NOT NULL,\
             certificate_sha256 BLOB NOT NULL,\
             source INTEGER NOT NULL,\
             network_scope TEXT NOT NULL,\
             first_seen_at_ms INTEGER NOT NULL,\
             last_seen_at_ms INTEGER NOT NULL,\
             last_success_at_ms INTEGER NOT NULL,\
             consecutive_failures INTEGER NOT NULL DEFAULT 0,\
             retry_after_ms INTEGER NOT NULL DEFAULT 0,\
             PRIMARY KEY (peer_id, address)\
             ) STRICT",
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }
}

#[async_trait]
impl EndpointRepository for SqlitePeerRepository {
    async fn endpoints(&self, peer_id: &DeviceId) -> Result<Vec<RememberedEndpoint>, NetworkError> {
        const MAX_AGE_MS: i64 = 90 * 24 * 60 * 60 * 1_000;
        let now = now_ms();
        sqlx::query(
            "SELECT * FROM peer_endpoints \
             WHERE peer_id = ? AND retry_after_ms <= ? AND last_success_at_ms >= ? \
             ORDER BY last_success_at_ms DESC, last_seen_at_ms DESC LIMIT 16",
        )
        .bind(peer_id.as_str())
        .bind(now)
        .bind(now.saturating_sub(MAX_AGE_MS))
        .fetch_all(&self.pool)
        .await
        .map_err(network_backend)?
        .into_iter()
        .map(decode_endpoint)
        .collect()
    }

    async fn record_authenticated(
        &self,
        peer_id: &DeviceId,
        address: SocketAddr,
        certificate_sha256: [u8; 32],
        source: EndpointSource,
    ) -> Result<(), NetworkError> {
        let now = now_ms();
        sqlx::query(
            "INSERT INTO peer_endpoints (\
             peer_id, address, certificate_sha256, source, network_scope, first_seen_at_ms, \
             last_seen_at_ms, last_success_at_ms, consecutive_failures, retry_after_ms\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0) \
             ON CONFLICT(peer_id, address) DO UPDATE SET \
             certificate_sha256=excluded.certificate_sha256, source=excluded.source, \
             network_scope=excluded.network_scope, last_seen_at_ms=excluded.last_seen_at_ms, \
             last_success_at_ms=excluded.last_success_at_ms, consecutive_failures=0, retry_after_ms=0",
        )
        .bind(peer_id.as_str())
        .bind(address.to_string())
        .bind(certificate_sha256.as_slice())
        .bind(source.encode())
        .bind(network_scope(address))
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(network_backend)?;
        Ok(())
    }

    async fn record_failure(
        &self,
        peer_id: &DeviceId,
        address: SocketAddr,
    ) -> Result<(), NetworkError> {
        let now = now_ms();
        sqlx::query(
            "UPDATE peer_endpoints SET \
             consecutive_failures=consecutive_failures + 1, \
             retry_after_ms=? + MIN(300000, (1 << MIN(consecutive_failures + 1, 8)) * 1000) \
             WHERE peer_id=? AND address=?",
        )
        .bind(now)
        .bind(peer_id.as_str())
        .bind(address.to_string())
        .execute(&self.pool)
        .await
        .map_err(network_backend)?;
        Ok(())
    }

    async fn forget(&self, peer_id: &DeviceId) -> Result<(), NetworkError> {
        sqlx::query("DELETE FROM peer_endpoints WHERE peer_id = ?")
            .bind(peer_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(network_backend)?;
        Ok(())
    }
}

#[async_trait]
impl PeerRepository for SqlitePeerRepository {
    async fn peer(&self, id: &DeviceId) -> Result<Option<PeerRecord>, RepositoryError> {
        sqlx::query("SELECT * FROM peers WHERE device_id = ?")
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?
            .map(decode_peer)
            .transpose()
    }

    async fn peers(&self) -> Result<Vec<PeerRecord>, RepositoryError> {
        sqlx::query("SELECT * FROM peers ORDER BY display_name, device_id")
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?
            .into_iter()
            .map(decode_peer)
            .collect()
    }

    async fn save_peer(&self, peer: PeerRecord) -> Result<(), RepositoryError> {
        peer.device_id
            .verify_key(&peer.public_key)
            .map_err(backend)?;
        sqlx::query(
            "INSERT INTO peers (device_id, public_key, display_name, platform, model, trust_state, auto_connect, paired_at_ms, updated_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(device_id) DO UPDATE SET \
             public_key=excluded.public_key, display_name=excluded.display_name, \
             platform=excluded.platform, model=excluded.model, trust_state=excluded.trust_state, \
             auto_connect=excluded.auto_connect, paired_at_ms=excluded.paired_at_ms, updated_at_ms=excluded.updated_at_ms",
        )
        .bind(peer.device_id.as_str())
        .bind(peer.public_key.as_bytes())
        .bind(peer.display_name)
        .bind(peer.platform)
        .bind(peer.model)
        .bind(encode_trust(peer.trust_state))
        .bind(peer.auto_connect)
        .bind(peer.paired_at_ms)
        .bind(peer.updated_at_ms)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn save_pairing(
        &self,
        peer: PeerRecord,
        grants: Vec<Grant>,
    ) -> Result<(), RepositoryError> {
        peer.device_id
            .verify_key(&peer.public_key)
            .map_err(backend)?;
        if grants.iter().any(|grant| grant.peer_id != peer.device_id) {
            return Err(RepositoryError::Backend(
                "pairing grant belongs to another peer".into(),
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(backend)?;
        sqlx::query(
            "INSERT INTO peers (device_id, public_key, display_name, platform, model, trust_state, auto_connect, paired_at_ms, updated_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(device_id) DO UPDATE SET \
             public_key=excluded.public_key, display_name=excluded.display_name, \
             platform=excluded.platform, model=excluded.model, trust_state=excluded.trust_state, \
             auto_connect=excluded.auto_connect, paired_at_ms=excluded.paired_at_ms, updated_at_ms=excluded.updated_at_ms",
        )
        .bind(peer.device_id.as_str())
        .bind(peer.public_key.as_bytes())
        .bind(&peer.display_name)
        .bind(&peer.platform)
        .bind(&peer.model)
        .bind(encode_trust(TrustState::Paired))
        .bind(peer.auto_connect)
        .bind(peer.paired_at_ms)
        .bind(peer.updated_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(backend)?;
        sqlx::query("DELETE FROM grants WHERE peer_id = ?")
            .bind(peer.device_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(backend)?;
        for grant in grants {
            sqlx::query(
                "INSERT INTO grants (peer_id, capability, direction, constraints_json, granted_at_ms) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(grant.peer_id.as_str())
            .bind(grant.capability.token())
            .bind(encode_direction(grant.direction))
            .bind(serde_json::to_string(&grant.constraints).map_err(backend)?)
            .bind(grant.granted_at_ms)
            .execute(&mut *transaction)
            .await
            .map_err(backend)?;
        }
        transaction.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn forget_peer(&self, id: &DeviceId) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM peers WHERE device_id = ?")
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(result.rows_affected() != 0)
    }

    async fn grants(&self, id: &DeviceId) -> Result<Vec<Grant>, RepositoryError> {
        sqlx::query(
            "SELECT peer_id, capability, direction, constraints_json, granted_at_ms \
             FROM grants WHERE peer_id = ? ORDER BY capability, direction",
        )
        .bind(id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .into_iter()
        .map(decode_grant)
        .collect()
    }

    async fn save_grant(&self, grant: Grant) -> Result<(), RepositoryError> {
        let constraints = serde_json::to_string(&grant.constraints).map_err(backend)?;
        sqlx::query(
            "INSERT INTO grants (peer_id, capability, direction, constraints_json, granted_at_ms) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(peer_id, capability, direction) DO UPDATE SET \
             constraints_json=excluded.constraints_json, granted_at_ms=excluded.granted_at_ms",
        )
        .bind(grant.peer_id.as_str())
        .bind(grant.capability.token())
        .bind(encode_direction(grant.direction))
        .bind(constraints)
        .bind(grant.granted_at_ms)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn revoke_grant(
        &self,
        id: &DeviceId,
        capability: CapabilityId,
        direction: GrantDirection,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "DELETE FROM grants WHERE peer_id = ? AND capability = ? AND direction = ?",
        )
        .bind(id.as_str())
        .bind(capability.token())
        .bind(encode_direction(direction))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(result.rows_affected() != 0)
    }
}

fn decode_peer(row: SqliteRow) -> Result<PeerRecord, RepositoryError> {
    let device_id = DeviceId::parse(row.try_get::<String, _>("device_id").map_err(backend)?)
        .map_err(backend)?;
    let public_key =
        DevicePublicKey::from_bytes(row.try_get::<Vec<u8>, _>("public_key").map_err(backend)?)
            .map_err(backend)?;
    device_id.verify_key(&public_key).map_err(backend)?;
    Ok(PeerRecord {
        device_id,
        public_key,
        display_name: row.try_get("display_name").map_err(backend)?,
        platform: row.try_get("platform").map_err(backend)?,
        model: row.try_get("model").map_err(backend)?,
        trust_state: decode_trust(row.try_get("trust_state").map_err(backend)?)?,
        auto_connect: row.try_get::<i64, _>("auto_connect").map_err(backend)? != 0,
        paired_at_ms: row.try_get("paired_at_ms").map_err(backend)?,
        updated_at_ms: row.try_get("updated_at_ms").map_err(backend)?,
    })
}

fn decode_grant(row: SqliteRow) -> Result<Grant, RepositoryError> {
    let capability = row
        .try_get::<String, _>("capability")
        .map_err(backend)
        .and_then(|value| {
            CapabilityId::parse_token(&value)
                .ok_or_else(|| RepositoryError::Backend(format!("unknown capability {value}")))
        })?;
    Ok(Grant {
        peer_id: DeviceId::parse(row.try_get::<String, _>("peer_id").map_err(backend)?)
            .map_err(backend)?,
        capability,
        direction: decode_direction(row.try_get("direction").map_err(backend)?)?,
        constraints: serde_json::from_str(
            &row.try_get::<String, _>("constraints_json")
                .map_err(backend)?,
        )
        .map_err(backend)?,
        granted_at_ms: row.try_get("granted_at_ms").map_err(backend)?,
    })
}

const fn encode_trust(value: TrustState) -> i64 {
    match value {
        TrustState::Paired => 1,
        TrustState::Revoked => 2,
    }
}

fn decode_trust(value: i64) -> Result<TrustState, RepositoryError> {
    match value {
        1 => Ok(TrustState::Paired),
        2 => Ok(TrustState::Revoked),
        _ => Err(RepositoryError::Backend("unknown trust state".into())),
    }
}

const fn encode_direction(value: GrantDirection) -> i64 {
    match value {
        GrantDirection::Inbound => 1,
        GrantDirection::Outbound => 2,
    }
}

fn decode_direction(value: i64) -> Result<GrantDirection, RepositoryError> {
    match value {
        1 => Ok(GrantDirection::Inbound),
        2 => Ok(GrantDirection::Outbound),
        _ => Err(RepositoryError::Backend("unknown grant direction".into())),
    }
}

fn decode_endpoint(row: SqliteRow) -> Result<RememberedEndpoint, NetworkError> {
    let peer_id = DeviceId::parse(
        &row.try_get::<String, _>("peer_id")
            .map_err(network_backend)?,
    )
    .map_err(|error| NetworkError::Repository(error.to_string()))?;
    let address = row
        .try_get::<String, _>("address")
        .map_err(network_backend)?
        .parse()
        .map_err(|error: std::net::AddrParseError| NetworkError::Repository(error.to_string()))?;
    let certificate_sha256 = row
        .try_get::<Vec<u8>, _>("certificate_sha256")
        .map_err(network_backend)?
        .try_into()
        .map_err(|_| NetworkError::Repository("remembered certificate digest length".into()))?;
    let failures = row
        .try_get::<i64, _>("consecutive_failures")
        .map_err(network_backend)?;
    Ok(RememberedEndpoint {
        peer_id,
        address,
        certificate_sha256,
        source: EndpointSource::decode(row.try_get("source").map_err(network_backend)?)?,
        network_scope: row.try_get("network_scope").map_err(network_backend)?,
        first_seen_at_ms: row.try_get("first_seen_at_ms").map_err(network_backend)?,
        last_seen_at_ms: row.try_get("last_seen_at_ms").map_err(network_backend)?,
        last_success_at_ms: row.try_get("last_success_at_ms").map_err(network_backend)?,
        consecutive_failures: failures.try_into().unwrap_or(u32::MAX),
        retry_after_ms: row.try_get("retry_after_ms").map_err(network_backend)?,
    })
}

fn backend(error: impl std::fmt::Display) -> RepositoryError {
    RepositoryError::Backend(error.to_string())
}

fn network_backend(error: impl std::fmt::Display) -> NetworkError {
    NetworkError::Repository(error.to_string())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcrelay_peer::GrantConstraints;

    #[tokio::test]
    async fn peer_auto_connect_preference_is_persisted() {
        let directory = tempfile::tempdir().unwrap();
        let repository = SqlitePeerRepository::open(&directory.path().join("peers.sqlite"))
            .await
            .unwrap();
        let public_key = DevicePublicKey::from_bytes(vec![3; 32]).unwrap();
        let id = DeviceId::from_public_key(&public_key);
        repository
            .save_peer(PeerRecord {
                device_id: id.clone(),
                public_key,
                display_name: "Manual peer".into(),
                platform: "test".into(),
                model: "test".into(),
                trust_state: TrustState::Paired,
                auto_connect: false,
                paired_at_ms: 1,
                updated_at_ms: 2,
            })
            .await
            .unwrap();

        let stored = repository.peer(&id).await.unwrap().unwrap();
        assert!(!stored.auto_connect);
    }

    #[tokio::test]
    async fn forget_cascades_all_capability_grants() {
        let directory = tempfile::tempdir().unwrap();
        let repository = SqlitePeerRepository::open(&directory.path().join("peers.sqlite"))
            .await
            .unwrap();
        let public_key = DevicePublicKey::from_bytes(vec![4; 32]).unwrap();
        let id = DeviceId::from_public_key(&public_key);
        repository
            .save_peer(PeerRecord {
                device_id: id.clone(),
                public_key,
                display_name: "Peer".into(),
                platform: "test".into(),
                model: "test".into(),
                trust_state: TrustState::Paired,
                auto_connect: true,
                paired_at_ms: 1,
                updated_at_ms: 1,
            })
            .await
            .unwrap();
        repository
            .save_grant(Grant {
                peer_id: id.clone(),
                capability: CapabilityId::ClipboardSync,
                direction: GrantDirection::Inbound,
                constraints: GrantConstraints::None,
                granted_at_ms: 2,
            })
            .await
            .unwrap();
        repository
            .record_authenticated(
                &id,
                "192.168.10.20:8765".parse().unwrap(),
                [9; 32],
                EndpointSource::Inbound,
            )
            .await
            .unwrap();
        assert_eq!(repository.endpoints(&id).await.unwrap().len(), 1);
        assert!(repository.forget_peer(&id).await.unwrap());
        assert!(repository.grants(&id).await.unwrap().is_empty());
        assert!(repository.endpoints(&id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn authenticated_endpoints_are_updated_and_backed_off() {
        let directory = tempfile::tempdir().unwrap();
        let repository = SqlitePeerRepository::open(&directory.path().join("peers.sqlite"))
            .await
            .unwrap();
        let public_key = DevicePublicKey::from_bytes(vec![5; 32]).unwrap();
        let id = DeviceId::from_public_key(&public_key);
        repository
            .save_peer(PeerRecord {
                device_id: id.clone(),
                public_key,
                display_name: "Remembered Peer".into(),
                platform: "test".into(),
                model: "test".into(),
                trust_state: TrustState::Paired,
                auto_connect: true,
                paired_at_ms: 1,
                updated_at_ms: 1,
            })
            .await
            .unwrap();
        let address = "10.42.7.8:8767".parse().unwrap();
        repository
            .record_authenticated(&id, address, [3; 32], EndpointSource::Manual)
            .await
            .unwrap();
        let endpoints = repository.endpoints(&id).await.unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].address, address);
        assert_eq!(endpoints[0].network_scope, "10.42.7.0/24");

        repository.record_failure(&id, address).await.unwrap();
        assert!(repository.endpoints(&id).await.unwrap().is_empty());
        repository
            .record_authenticated(&id, address, [4; 32], EndpointSource::History)
            .await
            .unwrap();
        let endpoints = repository.endpoints(&id).await.unwrap();
        assert_eq!(endpoints[0].certificate_sha256, [4; 32]);
        assert_eq!(endpoints[0].consecutive_failures, 0);
    }
}
