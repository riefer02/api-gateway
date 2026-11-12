use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::auth::store::{ApiKeyStore, NewApiKey, StoreError};
use crate::auth::{ApiKeyId, Credential};

/// Postgres channel used to tell every replica that a key was revoked.
pub(crate) const REVOCATION_CHANNEL: &str = "api_key_revoked";

/// How long "this key id does not exist" is remembered. Short, because a key
/// created a moment ago must still work.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// Small sharded TTL cache.
///
/// Deliberately not a general-purpose cache: no eviction callbacks, no weight
/// accounting. Entries expire lazily on read and each shard is swept at most
/// once every 30 seconds, so a full shard never turns a request into a scan.
pub(crate) struct TtlCache<K, V> {
    shards: Vec<Mutex<Shard<K, V>>>,
    ttl: Duration,
}

struct Shard<K, V> {
    entries: HashMap<K, Entry<V>>,
    last_swept: Instant,
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
                .map(|_| {
                    Mutex::new(Shard {
                        entries: HashMap::new(),
                        last_swept: Instant::now(),
                    })
                })
                .collect(),
            ttl,
        }
    }

    pub(crate) fn get(&self, key: &K) -> Option<V> {
        let now = Instant::now();
        let shard = self.shard(key);
        let mut shard = shard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        match shard.entries.get(key) {
            Some(entry) if entry.expires_at > now => Some(entry.value.clone()),
            Some(_) => {
                shard.entries.remove(key);
                None
            }
            None => None,
        }
    }

    pub(crate) fn insert(&self, key: K, value: V) {
        let now = Instant::now();
        let shard = self.shard(&key);
        let mut shard = shard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if now.saturating_duration_since(shard.last_swept) > Duration::from_secs(30) {
            shard
                .entries
                .retain(|_, entry| entry.expires_at > now);
            shard.last_swept = now;
        }

        shard.entries.insert(
            key,
            Entry {
                value,
                expires_at: now + self.ttl,
            },
        );
    }

    pub(crate) fn invalidate(&self, key: &K) {
        self.shard(key)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .remove(key);
    }

    fn shard(&self, key: &K) -> &Mutex<Shard<K, V>> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.shards.len();

        &self.shards[index]
    }
}

/// Wraps a credential store with a short-lived read cache.
///
/// The cache bounds how long a revocation can go unnoticed *across processes*.
/// In-process revocations invalidate immediately, and remote ones arrive over
/// [`REVOCATION_CHANNEL`], so the TTL is only the fallback.
pub(crate) struct CachedApiKeyStore {
    inner: Arc<dyn ApiKeyStore>,
    cache: TtlCache<ApiKeyId, Credential>,
    /// Unknown keys are cached briefly so credential scanners cannot turn every
    /// request into a database round trip.
    negative: TtlCache<ApiKeyId, ()>,
}

impl CachedApiKeyStore {
    pub(crate) fn new(inner: Arc<dyn ApiKeyStore>, ttl: Duration) -> Self {
        Self {
            inner,
            cache: TtlCache::new(ttl),
            negative: TtlCache::new(NEGATIVE_TTL),
        }
    }

    /// Drops one entry. Called locally on revoke and remotely via `LISTEN`.
    pub(crate) fn invalidate(&self, key_id: &ApiKeyId) {
        self.cache.invalidate(key_id);
        self.negative.invalidate(key_id);
    }
}

#[async_trait::async_trait]
impl ApiKeyStore for CachedApiKeyStore {
    async fn find_by_key_id(&self, key_id: &ApiKeyId) -> Result<Option<Credential>, StoreError> {
        if self.negative.get(key_id).is_some() {
            metrics::counter!("gateway_auth_cache_total", "result" => "negative").increment(1);
            return Ok(None);
        }

        if let Some(credential) = self.cache.get(key_id) {
            metrics::counter!("gateway_auth_cache_total", "result" => "hit").increment(1);
            return Ok(Some(credential));
        }

        metrics::counter!("gateway_auth_cache_total", "result" => "miss").increment(1);

        let credential = self
            .inner
            .find_by_key_id(key_id)
            .await?;

        match &credential {
            Some(credential) => self
                .cache
                .insert(key_id.clone(), credential.clone()),
            None => self.negative.insert(key_id.clone(), ()),
        }

        Ok(credential)
    }

    async fn revoke_by_key_id(&self, key_id: &ApiKeyId) -> Result<bool, StoreError> {
        // Invalidate first: a failed revoke is retried by the caller, and a
        // stale hit would keep a revoked key alive for the TTL.
        self.invalidate(key_id);

        self.inner
            .revoke_by_key_id(key_id)
            .await
    }

    async fn insert_key(&self, key: NewApiKey) -> Result<(), StoreError> {
        // A negative entry for this id would hide the new key, so publish the
        // invalidation before writing.
        self.negative.invalidate(&key.key_id);

        self.inner.insert_key(key).await
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

    fn store_with_key(ttl: Duration) -> (Arc<dyn ApiKeyStore>, CachedApiKeyStore) {
        let inner: Arc<dyn ApiKeyStore> = Arc::new(InMemoryApiKeyStore::default());
        let cached = CachedApiKeyStore::new(Arc::clone(&inner), ttl);

        (inner, cached)
    }

    #[tokio::test]
    async fn serves_the_second_read_from_cache() {
        let (inner, store) = store_with_key(Duration::from_secs(30));
        inner
            .insert_key(key("k1"))
            .await
            .expect("insert");

        assert!(
            store
                .find_by_key_id(&ApiKeyId("k1".to_owned()))
                .await
                .unwrap()
                .is_some()
        );

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
        let (inner, store) = store_with_key(Duration::from_secs(30));
        inner
            .insert_key(key("k1"))
            .await
            .expect("insert");

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

        assert!(reloaded.key.revoked_at.is_some());
    }

    #[tokio::test]
    async fn unknown_keys_are_negatively_cached() {
        let (_inner, store) = store_with_key(Duration::from_secs(30));

        assert!(
            store
                .find_by_key_id(&ApiKeyId("missing".to_owned()))
                .await
                .unwrap()
                .is_none()
        );

        // Creating the key must not stay hidden behind the negative entry.
        store
            .insert_key(key("missing"))
            .await
            .expect("insert");

        assert!(
            store
                .find_by_key_id(&ApiKeyId("missing".to_owned()))
                .await
                .unwrap()
                .is_some(),
            "insert clears the negative entry"
        );
    }

    #[tokio::test]
    async fn entries_expire() {
        let (inner, store) = store_with_key(Duration::from_millis(50));
        inner
            .insert_key(key("k1"))
            .await
            .expect("insert");

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
