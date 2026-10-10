//! The sidecar's challenge store: the pending records, the consumed
//! tombstones and the issuance-bound metadata, behind one small trait.
//!
//! The trait mirrors the core verifier's storage seam so the handler can
//! run the exact production sequence: an atomic consume, the hash
//! derivation with no lock held, then a short commit. Backends:
//!
//! - [`MemoryStore`]: in-process maps. Volatile by contract; a restart
//!   loses outstanding challenges and replays answer not-found. The
//!   default for a single small deployment, documented as such.
//! - [`FileStore`]: the same maps written through to one local
//!   directory. Every durable write lands through a unique temporary
//!   file plus `rename` with `sync_all`, the peer discipline of the PHP
//!   core's `FilesystemStorage`: a reader observes either the whole
//!   envelope or the one that came before it, and a crash leaves a
//!   consistent directory. One JSON envelope per nonce carries the
//!   record, the metadata and the state, so the pending to consumed
//!   transition is a single atomic rename. Single node and single
//!   process by contract; multi-node deployments use the Redis backend.
//! - [`RedisStore`] (feature `redis-store`): the core crate's fused
//!   `RedisChallengeStore`, key-compatible with the PHP bundle's Redis
//!   storage.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kiwicaptcha::challenge::{security_random, ChallengeRecord};
use kiwicaptcha::verify::sha256_hex;

/// The issuance-bound metadata a record carries: the provider fields
/// echoed on a successful verify, plus the risk decision id the outcome
/// confirmation needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecordMeta {
    pub action: Option<String>,
    pub cdata: Option<String>,
    #[serde(default)]
    pub decision_id: Option<String>,
    /// The operation identity of the winning verification (if any).
    /// An idempotent retry carrying the same identity returns the
    /// stored success; a different identity is a plain replay.
    #[serde(default)]
    pub operation_identity: Option<String>,
}

/// The atomic consume decision: the caller either owns the single
/// derivation, or the record was already burned.
#[derive(Debug)]
pub enum ConsumeOutcome {
    /// This caller won the pending to consumed transition and owns the
    /// one derivation. The record is the consumed copy to verify.
    Won {
        record: Box<ChallengeRecord>,
        meta: RecordMeta,
    },
    /// The record was already consumed (a replay, or the loser of a
    /// race). The retained metadata rides along for the provider echo.
    AlreadyConsumed {
        meta: RecordMeta,
        /// The stored verdict of the first (winning) verification.
        succeeded: Option<bool>,
    },
    /// No record under the nonce, pending or consumed.
    NotFound,
    /// The backend could not serve the transition; the record's state is
    /// unknown and untouched where the backend could report it.
    Unavailable(String),
}

/// The storage seam. Implementations must make [`RecordStore::consume`]
/// atomic: exactly one caller observes [`ConsumeOutcome::Won`] per
/// record, which is the one-shot bound (one derivation per nonce).
pub trait RecordStore: Send + Sync {
    /// Insert a freshly issued record as pending.
    fn put_pending(&self, record: &ChallengeRecord, meta: RecordMeta) -> Result<(), String>;

    /// The atomic pending to consumed transition. Expired records are
    /// pruned within the same call.
    fn consume(
        &self,
        nonce: &str,
        now_unix: u64,
        operation_identity: Option<&str>,
    ) -> ConsumeOutcome;

    /// Persist the derivation outcome on the consumed record. Best
    /// effort: a lost commit only degrades a later replay to the
    /// duplicate answer.
    fn commit(&self, nonce: &str, record: &ChallengeRecord, valid: bool);

    /// The live record counts: pending, consumed (for `/metrics`).
    fn counts(&self) -> (usize, usize);

    /// A short label for `/doctor` and the startup line.
    fn describe(&self) -> String;
}

/// One live record: the challenge record, its metadata and, once
/// committed, the verdict.
#[derive(Debug, Clone)]
struct Entry {
    record: ChallengeRecord,
    meta: RecordMeta,
    valid: Option<bool>,
}

impl Entry {
    fn new(record: ChallengeRecord, meta: RecordMeta) -> Self {
        Entry {
            record,
            meta,
            valid: None,
        }
    }
}

/// The shared in-map state machine behind both the memory and the file
/// backend. The mutex is the transition boundary: it covers only the
/// bookkeeping, never a hash derivation.
#[derive(Default)]
struct MapState {
    pending: HashMap<String, Entry>,
    consumed: HashMap<String, Entry>,
}

impl MapState {
    /// Drop expired records; returns their nonces so a durable backend
    /// can remove the persisted envelopes too.
    fn prune_expired(&mut self, now_unix: u64) -> Vec<String> {
        let mut dropped = Vec::new();
        self.pending.retain(|nonce, e| {
            let live = e.record.expires_at > now_unix;
            if !live {
                dropped.push(nonce.clone());
            }
            live
        });
        self.consumed.retain(|nonce, e| {
            let live = e.record.expires_at > now_unix;
            if !live {
                dropped.push(nonce.clone());
            }
            live
        });
        dropped
    }

    fn consume(
        &mut self,
        nonce: &str,
        now_unix: u64,
        operation_identity: Option<&str>,
    ) -> ConsumeOutcome {
        self.prune_expired(now_unix);
        if let Some(entry) = self.pending.remove(nonce) {
            let mut meta = entry.meta.clone();
            if let Some(identity) = operation_identity {
                meta.operation_identity = Some(identity.to_string());
            }
            let record = entry.record.clone();
            let mut entry = entry;
            entry.meta = meta.clone();
            self.consumed.insert(nonce.to_string(), entry);
            return ConsumeOutcome::Won {
                record: Box::new(record),
                meta,
            };
        }
        match self.consumed.get(nonce) {
            Some(entry) => ConsumeOutcome::AlreadyConsumed {
                meta: entry.meta.clone(),
                succeeded: entry.valid,
            },
            None => ConsumeOutcome::NotFound,
        }
    }

    fn counts(&self) -> (usize, usize) {
        (self.pending.len(), self.consumed.len())
    }
}

/// The in-process store (the default). Volatile: a restart loses every
/// outstanding challenge, and a replay after a restart answers not-found
/// rather than the duplicate vocabulary. That is the documented
/// single-node small-site trade.
pub struct MemoryStore {
    state: Mutex<MapState>,
}

impl MemoryStore {
    pub fn new() -> Self {
        MemoryStore {
            state: Mutex::new(MapState::default()),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordStore for MemoryStore {
    fn put_pending(&self, record: &ChallengeRecord, meta: RecordMeta) -> Result<(), String> {
        let mut state = self.state.lock().expect("store lock");
        state
            .pending
            .insert(record.nonce.clone(), Entry::new(record.clone(), meta));
        Ok(())
    }

    fn consume(
        &self,
        nonce: &str,
        now_unix: u64,
        operation_identity: Option<&str>,
    ) -> ConsumeOutcome {
        let mut state = self.state.lock().expect("store lock");
        state.consume(nonce, now_unix, operation_identity)
    }

    fn commit(&self, nonce: &str, record: &ChallengeRecord, valid: bool) {
        let mut state = self.state.lock().expect("store lock");
        if let Some(entry) = state.consumed.get_mut(nonce) {
            entry.record = record.clone();
            entry.valid = Some(valid);
        }
    }

    fn counts(&self) -> (usize, usize) {
        let state = self.state.lock().expect("store lock");
        state.counts()
    }

    fn describe(&self) -> String {
        "in-process memory (volatile; a restart loses outstanding challenges)".to_string()
    }
}

/// The durable single-directory store. One JSON envelope per nonce under
/// a namespaced, sharded hash path (the nonce never appears in a path);
/// every write is a unique temporary file, a `sync_all`, then an atomic
/// rename within the same filesystem. Layout marker:
/// `kiwi-verifier-file-store-1`; a foreign marker refuses the open.
pub struct FileStore {
    state: Mutex<MapState>,
    dir: PathBuf,
    records_dir: PathBuf,
}

const FILE_STORE_MARKER: &str = "kiwi-verifier-file-store-1";
const HASH_NAMESPACE: &str = "kiwicaptcha-verifier:record:v1";
const STATE_PENDING: &str = "pending";
const STATE_CONSUMED: &str = "consumed";

/// The on-disk envelope (serde shape). The state field makes the pending
/// to consumed transition a single rename on one file.
#[derive(serde::Serialize, serde::Deserialize)]
struct Envelope {
    state: String,
    record: ChallengeRecord,
    meta: RecordMeta,
    valid: Option<bool>,
}

impl FileStore {
    /// Open (or create) the store directory. Loads every live envelope
    /// back into memory, so a restart keeps outstanding challenges and
    /// the duplicate vocabulary. Refuses a directory carrying a foreign
    /// marker, and refuses corrupt envelopes: a final-name envelope is
    /// always whole under the rename discipline, so corruption means a
    /// foreign writer touched the store.
    pub fn open(dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create store dir {}: {e}", dir.display()))?;
        let marker = dir.join(FILE_STORE_MARKER);
        match fs::read_to_string(&marker) {
            Ok(text) if text.trim() == FILE_STORE_MARKER => {}
            Ok(_) => {
                return Err(format!(
                    "refusing store dir {}: foreign or newer layout marker",
                    dir.display()
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::write(&marker, FILE_STORE_MARKER)
                    .map_err(|e| format!("cannot write store marker: {e}"))?;
            }
            Err(e) => return Err(format!("cannot read store marker: {e}")),
        }
        let records_dir = dir.join("records");
        fs::create_dir_all(&records_dir).map_err(|e| format!("cannot create records dir: {e}"))?;
        let store = FileStore {
            state: Mutex::new(MapState::default()),
            dir: dir.to_path_buf(),
            records_dir,
        };
        store.load()?;
        Ok(store)
    }

    fn load(&self) -> Result<(), String> {
        let mut state = self.state.lock().expect("store lock");
        let shards =
            fs::read_dir(&self.records_dir).map_err(|e| format!("cannot read records dir: {e}"))?;
        for shard in shards {
            let shard = shard.map_err(|e| format!("store shard read failed: {e}"))?;
            if !shard.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let files = fs::read_dir(shard.path())
                .map_err(|e| format!("store shard listing failed: {e}"))?;
            for file in files {
                let file = file.map_err(|e| format!("store file read failed: {e}"))?;
                let path = file.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.ends_with(".tmp") {
                    // Crashed-writer debris: no final name ever carries
                    // the suffix, so the boot sweep drops it.
                    let _ = fs::remove_file(&path);
                    continue;
                }
                let raw = fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read store file {}: {e}", path.display()))?;
                let envelope: Envelope = serde_json::from_str(&raw).map_err(|e| {
                    format!(
                        "corrupt store envelope {}: {e} (a final-name envelope is always whole under the rename discipline, so this is a foreign writer; refusing)",
                        path.display()
                    )
                })?;
                let entry = Entry {
                    record: envelope.record,
                    meta: envelope.meta,
                    valid: envelope.valid,
                };
                let nonce = entry.record.nonce.clone();
                if state.pending.contains_key(&nonce) || state.consumed.contains_key(&nonce) {
                    return Err(format!(
                        "duplicate record nonce across store files: {nonce}"
                    ));
                }
                if envelope.state == STATE_CONSUMED {
                    state.consumed.insert(nonce, entry);
                } else {
                    state.pending.insert(nonce, entry);
                }
            }
        }
        Ok(())
    }

    fn record_path(&self, nonce: &str) -> PathBuf {
        let hash = sha256_hex(&format!("{HASH_NAMESPACE}:{nonce}"));
        self.records_dir
            .join(&hash[..2])
            .join(format!("{hash}.json"))
    }

    /// Write one envelope durably: unique temp file, `sync_all`, atomic
    /// rename, best-effort directory sync. The peer of the PHP
    /// filesystem storage's write path, built from std only.
    fn write_envelope(&self, nonce: &str, envelope: &Envelope) -> Result<(), String> {
        let path = self.record_path(nonce);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create shard dir: {e}"))?;
        }
        let suffix = match security_random::<8>() {
            Ok(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            Err(_) => format!("{}", std::process::id()),
        };
        let tmp = path.with_extension(format!("json.{suffix}.tmp"));
        let body = serde_json::to_vec(envelope)
            .map_err(|e| format!("envelope serialization failed: {e}"))?;
        {
            let mut file = fs::File::create(&tmp).map_err(|e| format!("temp write failed: {e}"))?;
            file.write_all(&body)
                .map_err(|e| format!("temp write failed: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("temp sync failed: {e}"))?;
        }
        fs::rename(&tmp, &path).map_err(|e| format!("atomic rename failed: {e}"))?;
        // The directory entry itself: sync the shard dir so the rename
        // survives a power cut. Best effort: some filesystems refuse a
        // directory fsync, and the rename already orders the visibility.
        if let Some(parent) = path.parent() {
            if let Ok(dirf) = fs::File::open(parent) {
                let _ = dirf.sync_all();
            }
        }
        Ok(())
    }

    fn persist(&self, state_mark: &str, entry: &Entry) -> Result<(), String> {
        self.write_envelope(
            &entry.record.nonce,
            &Envelope {
                state: state_mark.to_string(),
                record: entry.record.clone(),
                meta: entry.meta.clone(),
                valid: entry.valid,
            },
        )
    }

    fn remove_persisted(&self, nonce: &str) {
        let _ = fs::remove_file(self.record_path(nonce));
    }
}

impl RecordStore for FileStore {
    fn put_pending(&self, record: &ChallengeRecord, meta: RecordMeta) -> Result<(), String> {
        let mut state = self.state.lock().expect("store lock");
        let entry = Entry::new(record.clone(), meta);
        // Write through before the map insert: a crash then leaves the
        // record either absent (the client re-issues) or pending. The
        // reverse order could lose a record the map already served.
        self.persist(STATE_PENDING, &entry)?;
        state.pending.insert(record.nonce.clone(), entry);
        Ok(())
    }

    fn consume(
        &self,
        nonce: &str,
        now_unix: u64,
        operation_identity: Option<&str>,
    ) -> ConsumeOutcome {
        let mut state = self.state.lock().expect("store lock");
        let dropped = state.prune_expired(now_unix);
        for gone in &dropped {
            self.remove_persisted(gone);
        }
        // The transition: flip the persisted envelope to consumed (one
        // atomic rename) BEFORE answering Won. A crash after the flip
        // replays the duplicate answer on the next boot, which is the
        // one-shot contract: the record is burned even if the caller
        // never saw its answer.
        if let Some(entry) = state.pending.remove(nonce) {
            if let Err(e) = self.persist(STATE_CONSUMED, &entry) {
                // The transition may or may not have landed; restore the
                // pending entry in memory so the map stays consistent
                // with whichever file state survived.
                state.pending.insert(nonce.to_string(), entry.clone());
                return ConsumeOutcome::Unavailable(e);
            }
            let meta = entry.meta.clone();
            let record = entry.record.clone();
            state.consumed.insert(nonce.to_string(), entry);
            let mut meta = meta;
            if let Some(identity) = operation_identity {
                meta.operation_identity = Some(identity.to_string());
            }
            return ConsumeOutcome::Won {
                record: Box::new(record),
                meta,
            };
        }
        match state.consumed.get(nonce) {
            Some(entry) => ConsumeOutcome::AlreadyConsumed {
                meta: entry.meta.clone(),
                succeeded: entry.valid,
            },
            None => ConsumeOutcome::NotFound,
        }
    }

    fn commit(&self, nonce: &str, record: &ChallengeRecord, valid: bool) {
        let mut state = self.state.lock().expect("store lock");
        if let Some(entry) = state.consumed.get_mut(nonce) {
            entry.record = record.clone();
            entry.valid = Some(valid);
            if self.persist(STATE_CONSUMED, entry).is_err() {
                // Best effort: a lost commit only degrades a later
                // replay to the undecided duplicate answer.
            }
        }
    }

    fn counts(&self) -> (usize, usize) {
        let state = self.state.lock().expect("store lock");
        state.counts()
    }

    fn describe(&self) -> String {
        format!(
            "file store at {} (durable, atomic rename; single node, single process)",
            self.dir.display()
        )
    }
}

#[cfg(feature = "redis-store")]
/// The core crate's fused Redis verifier store: the production backend,
/// key-compatible with the PHP bundle's Redis storage. The issuance-bound
/// metadata (action, cdata, decision id) stays in-process on this
/// backend, so a restart drops the provider metadata echo, never the
/// challenge or replay state.
pub struct RedisStore {
    inner: kiwicaptcha::redis_verify::RedisChallengeStore,
    meta: Mutex<HashMap<String, RecordMeta>>,
    #[allow(dead_code)]
    url: String,
}

#[cfg(feature = "redis-store")]
impl RedisStore {
    /// Connect to `url` under the key prefix `prefix`. The connection
    /// opens lazily per command inside the core store's pool, so this
    /// only validates the URL shape.
    pub fn connect(url: &str, prefix: &str) -> Result<Self, String> {
        let client = redis::Client::open(url.to_string())
            .map_err(|e| format!("cannot parse redis url {url}: {e}"))?;
        let inner = kiwicaptcha::redis_verify::RedisChallengeStore::new(client, prefix);
        Ok(RedisStore {
            inner,
            meta: Mutex::new(HashMap::new()),
            url: url.to_string(),
        })
    }
}

#[cfg(feature = "redis-store")]
impl RecordStore for RedisStore {
    fn put_pending(&self, record: &ChallengeRecord, meta: RecordMeta) -> Result<(), String> {
        self.meta
            .lock()
            .expect("meta lock")
            .insert(record.nonce.clone(), meta);
        self.inner
            .store(record)
            .map_err(|e| format!("redis store failed: {e}"))
    }

    fn consume(
        &self,
        nonce: &str,
        _now_unix: u64,
        operation_identity: Option<&str>,
    ) -> ConsumeOutcome {
        let meta = self
            .meta
            .lock()
            .expect("meta lock")
            .get(nonce)
            .cloned()
            .unwrap_or_default();
        match self.inner.consume(nonce, _now_unix, operation_identity) {
            Ok(Some(consumed)) => {
                if consumed.first {
                    ConsumeOutcome::Won {
                        record: Box::new(consumed.record),
                        meta,
                    }
                } else {
                    ConsumeOutcome::AlreadyConsumed {
                        meta,
                        succeeded: entry.valid,
                    }
                }
            }
            Ok(None) => ConsumeOutcome::NotFound,
            Err(e) => ConsumeOutcome::Unavailable(format!("redis consume failed: {e}")),
        }
    }

    fn commit(&self, nonce: &str, _record: &ChallengeRecord, valid: bool) {
        let _ = self.inner.commit_result(nonce, valid, None);
    }

    fn counts(&self) -> (usize, usize) {
        (0, 0)
    }

    fn describe(&self) -> String {
        "redis (the core crate's fused verifier store; multi-node capable)".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwicaptcha::challenge::{
        issue_challenge, now_epoch_micros, BindingMode, ChallengeConfig, PoWAlgorithm,
    };

    fn record(scope: &str) -> ChallengeRecord {
        let cfg = ChallengeConfig {
            secret_key: "kiwi-verifier-unit-test-secret-0123456789".to_string(),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 8,
            argon2_target_bits: 4,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 8,
            binding_mode: BindingMode::None,
            policy_version: 1,
            region: None,
            issuer: None,
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
            tenant: None,
        };
        let now_ns = now_epoch_micros();
        issue_challenge(
            &cfg,
            scope,
            "198.51.100.7",
            now_ns / 1_000_000,
            now_ns,
            0,
            None,
        )
        .expect("issue")
        .record
    }

    #[test]
    fn memory_store_consume_is_one_shot() {
        let store = MemoryStore::new();
        let record = record("login");
        let nonce = record.nonce.clone();
        store.put_pending(&record, RecordMeta::default()).unwrap();
        let now = now_epoch_micros() / 1_000_000;
        assert!(matches!(
            store.consume(&nonce, now, None),
            ConsumeOutcome::Won { .. }
        ));
        assert!(matches!(
            store.consume(&nonce, now, None),
            ConsumeOutcome::AlreadyConsumed { .. }
        ));
        store.commit(&nonce, &record, true);
        assert_eq!(store.counts(), (0, 1));
    }

    #[test]
    fn memory_store_prunes_expired_records() {
        let store = MemoryStore::new();
        let record = record("login");
        store.put_pending(&record, RecordMeta::default()).unwrap();
        let future = record.expires_at + 10;
        assert!(matches!(
            store.consume(&record.nonce, future, None),
            ConsumeOutcome::NotFound
        ));
        assert_eq!(store.counts(), (0, 0));
    }

    #[test]
    fn file_store_survives_a_reopen() {
        let dir = std::env::temp_dir().join(format!("kiwi-file-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let nonce;
        {
            let store = FileStore::open(&dir).expect("open");
            let r = record("login");
            nonce = r.nonce.clone();
            store
                .put_pending(
                    &r,
                    RecordMeta {
                        action: Some("checkout".to_string()),
                        cdata: None,
                        decision_id: None,
                        operation_identity: None,
                    },
                )
                .unwrap();
            let now = now_epoch_micros() / 1_000_000;
            match store.consume(&nonce, now, None) {
                ConsumeOutcome::Won { record, meta } => {
                    assert_eq!(meta.action.as_deref(), Some("checkout"));
                    store.commit(&nonce, &record, true);
                }
                other => panic!("expected a won consume, got {other:?}"),
            }
        }
        {
            let reopened = FileStore::open(&dir).expect("reopen");
            let now = now_epoch_micros() / 1_000_000;
            assert!(matches!(
                reopened.consume(&nonce, now, None),
                ConsumeOutcome::AlreadyConsumed { .. }
            ));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_store_keeps_a_pending_record_over_a_reopen() {
        let dir =
            std::env::temp_dir().join(format!("kiwi-file-store-pending-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let nonce;
        {
            let store = FileStore::open(&dir).expect("open");
            let r = record("login");
            nonce = r.nonce.clone();
            store.put_pending(&r, RecordMeta::default()).unwrap();
        }
        {
            let reopened = FileStore::open(&dir).expect("reopen");
            let now = now_epoch_micros() / 1_000_000;
            assert!(matches!(
                reopened.consume(&nonce, now, None),
                ConsumeOutcome::Won { .. }
            ));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_store_refuses_a_foreign_marker() {
        let dir =
            std::env::temp_dir().join(format!("kiwi-file-store-foreign-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(FILE_STORE_MARKER), "someone-elses-store-9").unwrap();
        assert!(FileStore::open(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
