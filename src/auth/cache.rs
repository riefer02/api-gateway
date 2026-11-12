use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Small sharded TTL cache.
///
/// Deliberately not a general-purpose cache: no eviction callbacks, no weight
/// accounting. Entries expire lazily on read and are swept when a shard grows
/// past its cap.
pub(crate) struct TtlCache<K, V> {
    shards: Vec<Mutex<HashMap<K, Entry<V>>>>,
    ttl: Duration,
    max_entries_per_shard: usize,
}

struct Entry<V> {
    value: V,
    expires_at: Instant,
}

impl<K, V> TtlCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    pub(crate) fn new(ttl: Duration) -> Self {
        const SHARDS: usize = 16;

        Self {
            shards: (0..SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            ttl,
            max_entries_per_shard: 8_192,
        }
    }

    pub(crate) fn get(&self, key: &K) -> Option<V> {
        let now = Instant::now();
        let mut shard = self.shard(key);

        match shard.get(key) {
            Some(entry) if entry.expires_at > now => Some(entry.value.clone()),
            Some(_) => {
                shard.remove(key);
                None
            }
            None => None,
        }
    }

    pub(crate) fn insert(&self, key: K, value: V) {
        let now = Instant::now();
        let mut shard = self.shard(&key);

        if shard.len() >= self.max_entries_per_shard {
            shard.retain(|_, entry| entry.expires_at > now);
        }

        shard.insert(
            key,
            Entry {
                value,
                expires_at: now + self.ttl,
            },
        );
    }

    pub(crate) fn invalidate(&self, key: &K) {
        self.shard(key).remove(key);
    }

    fn shard(&self, key: &K) -> std::sync::MutexGuard<'_, HashMap<K, Entry<V>>> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.shards.len();

        self.shards[index]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

use crate::auth::store::{ApiKeyStore, NewApiKey, StoreError};
use crate::auth::{ApiKeyId, Credential};

/// Postgres channel used to tell every replica that a key was revoked.
pub(crate) const REVOCATION_CHANNEL: &str = "api_key_revoked";

/// Wraps a credential store with a short-lived read cache.
///
/// The cache bounds how long a revocation can go unnoticed *across processes*.
/// In-process revocations invalidate immediately, because the admin service
/// shares this same store instance.
pub(crate) struct CachedApiKeyStore {
    inner: Arc<dyn ApiKeyStore>,
    cache: TtlCache<ApiKeyId, Credential>,
}

impl CachedApiKeyStore {
    pub(crate) fn new(inner: Arc<dyn ApiKeyStore>, ttl: Duration) -> Self {
        Self {
            inner,
            cache: TtlCache::new(ttl),
        }
    }

    /// Drops one entry. Called locally on revoke and remotely via `LISTEN`.
    pub(crate) fn invalidate(&self, key_id: &ApiKeyId) {
        self.cache.invalidate(key_id);
    }
}

/// Keeps every replica's cache honest: a revoke anywhere is broadcast on a
/// Postgres channel, so no replica serves a revoked key past the write.
pub(crate) async fn listen_for_revocations(pool: sqlx::PgPool, store: Arc<CachedApiKeyStore>) {
    loop {
        let Ok(mut listener) = sqlx::postgres::PgListener::connect_with(&pool).await else {
            tracing::warn!("could not connect the revocation listener; retrying");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };

        if listener
            .listen(REVOCATION_CHANNEL)
            .await
            .is_err()
        {
            tracing::warn!("could not subscribe to revocation events; retrying");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        tracing::info!("listening for cross-replica revocation events");

        loop {
            match listener.recv().await {
                Ok(notification) => {
                    store.invalidate(&ApiKeyId(notification.payload().to_owned()));
                    tracing::debug!(key_id = notification.payload(), "cache invalidated");
                }
                Err(error) => {
                    tracing::warn!(%error, "revocation listener disconnected; reconnecting");
                    break;
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[async_trait::async_trait]
impl ApiKeyStore for CachedApiKeyStore {
    async fn find_by_key_id(&self, key_id: &ApiKeyId) -> Result<Option<Credential>, StoreError> {
        if let Some(credential) = self.cache.get(key_id) {
            metrics::counter!("gateway_auth_cache_total", "result" => "hit").increment(1);
            return Ok(Some(credential));
        }

        metrics::counter!("gateway_auth_cache_total", "result" => "miss").increment(1);

        let credential = self
            .inner
            .find_by_key_id(key_id)
            .await?;

        if let Some(credential) = &credential {
            self.cache
                .insert(key_id.clone(), credential.clone());
        }

        Ok(credential)
    }

    async fn revoke_by_key_id(&self, key_id: &ApiKeyId) -> Result<bool, StoreError> {
        // Invalidate first: a failed revoke is retried by the caller, and a
        // stale hit would keep a revoked key alive for the TTL.
        self.cache.invalidate(key_id);

        self.inner
            .revoke_by_key_id(key_id)
            .await
    }

    async fn insert_key(&self, key: NewApiKey) -> Result<(), StoreError> {
        self.inner.insert_key(key).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::auth::store::{InMemoryApiKeyStore, NewApiKey};
    use crate::auth::{ApiKeyId, ClientId};

    fn key(id: &str) -> NewApiKey {
        NewApiKey {
            key_id: ApiKeyId(id.to_owned()),
            client_id: ClientId("client".to_owned()),
            verifier: crate::auth::SecretVerifier([1_u8; 32]),
            verifier_version: 2,
            scopes: HashSet::new(),
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn serves_the_second_read_from_cache() {
        let inner: Arc<dyn crate::auth::store::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::default());
        inner
            .insert_key(key("k1"))
            .await
            .expect("insert");

        let store = CachedApiKeyStore::new(Arc::clone(&inner), Duration::from_secs(30));

        assert!(
            store
                .find_by_key_id(&ApiKeyId("k1".to_owned()))
                .await
                .unwrap()
                .is_some()
        );
        // Prove the cached copy is what answers: drop the backing entry.
        inner
            .revoke_by_key_id(&ApiKeyId("k1".to_owned()))
            .await
            .unwrap();

        let cached = store
            .find_by_key_id(&ApiKeyId("k1".to_owned()))
            .await
            .unwrap()
            .unwrap();
        assert!(cached.key.revoked_at.is_none(), "served from cache");
    }

    #[tokio::test]
    async fn revoke_invalidates_the_cache() {
        let inner: Arc<dyn crate::auth::store::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::default());
        inner
            .insert_key(key("k1"))
            .await
            .expect("insert");

        let store = CachedApiKeyStore::new(Arc::clone(&inner), Duration::from_secs(30));
        store
            .find_by_key_id(&ApiKeyId("k1".to_owned()))
            .await
            .unwrap();

        assert!(
            store
                .revoke_by_key_id(&ApiKeyId("k1".to_owned()))
                .await
                .unwrap()
        );

        let reloaded = store
            .find_by_key_id(&ApiKeyId("k1".to_owned()))
            .await
            .unwrap()
            .unwrap();
        assert!(
            reloaded.key.revoked_at.is_some(),
            "cache invalidated on revoke"
        );
    }

    #[tokio::test]
    async fn entries_expire() {
        let inner: Arc<dyn crate::auth::store::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::default());
        inner
            .insert_key(key("k1"))
            .await
            .expect("insert");

        let store = CachedApiKeyStore::new(Arc::clone(&inner), Duration::from_millis(50));
        store
            .find_by_key_id(&ApiKeyId("k1".to_owned()))
            .await
            .unwrap();

        inner
            .revoke_by_key_id(&ApiKeyId("k1".to_owned()))
            .await
            .unwrap();
        std::thread::sleep(Duration::from_millis(60));

        let reloaded = store
            .find_by_key_id(&ApiKeyId("k1".to_owned()))
            .await
            .unwrap()
            .unwrap();
        assert!(reloaded.key.revoked_at.is_some(), "expired entry reloaded");
    }
}
