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
    /// The remoteip the issue request presented. Stored so an idempotent
    /// retry can revalidate the client address before replaying a
    /// stored success (a different client is a plain already_consumed).
    #[serde(default)]
    pub remoteip: Option<String>,
    /// The scope the challenge was issued for. Stored so an idempotent
    /// retry can revalidate the scope before replaying a stored success
    /// (a different scope is a plain already_consumed).
    #[serde(default)]
    pub scope: Option<String>,
}

/// The authenticated material of a stored success: what an idempotent
/// replay must MAC-verify AND re-check context against before it may
/// return that success. The MAC is the core's `consumed_result_mac` tag
/// over the challenge, the verdict, the binding and the operation
/// identity the commit signed. The full record rides along so the
/// replay re-runs the CURRENT request's scope and binding expectation
/// against the record itself — the same replay security check every SDK
/// verifier performs — never against issuance metadata alone. A success
/// without a MAC (a legacy envelope, or a writer that never held the
/// master secret) carries no material and never replays as a success.
#[derive(Debug, Clone)]
pub struct StoredSuccess {
    /// The consumed record as the store holds it: challenge, scope,
    /// request binding and the rest of the signed issuance context.
    pub record: Box<ChallengeRecord>,
    /// The stored server-state MAC tag.
    pub mac: String,
}

/// The pre-consume snapshot: the admission gate and the capacity
/// ceiling classify from THIS (the stored record), never from
/// present-day configuration — the PHP verifier's runtime-state peek
/// mirror. A cancelled record reports `NotFound` exactly like the PHP
/// verifier's record-not-found answer for it.
#[derive(Debug)]
pub enum PeekOutcome {
    /// The record exists and is pending: consumable and derivable.
    Pending(Box<ChallengeRecord>),
    /// The record is retained in the terminal consumed state; the
    /// authoritative envelope still comes from `consume`.
    Consumed,
    /// No live record under the nonce (missing, cancelled, or expired
    /// and swept by this call's prune).
    NotFound,
    /// The backend could not serve the snapshot; the record's state is
    /// unknown and untouched.
    Unavailable(String),
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
        /// The MAC-verification material of the stored success, present
        /// when a verdict was committed with a server-state MAC. The
        /// replay path may return the stored success only after this
        /// material verifies against the caller's own derived keys.
        stored: Option<StoredSuccess>,
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

    /// The pre-consume snapshot: read-only classification of the
    /// nonce's live state (expired records are pruned within the
    /// call). The verify path peeks BEFORE admission so the Argon
    /// gate meters the AUTHENTICATED stored record's algorithm and
    /// memory weight — never the present-day scope rung — and so an
    /// already-consumed record resolves its replay without ever
    /// spending a scarce admission reservation.
    fn peek(&self, nonce: &str, now_unix: u64) -> PeekOutcome;

    /// Persist the derivation outcome on the consumed record. Best
    /// effort: a lost commit only degrades a later replay to the
    /// duplicate answer.
    fn commit(&self, nonce: &str, record: &ChallengeRecord, valid: bool);

    /// Persist the derivation outcome together with a server-state MAC.
    /// Every shipped backend stores the MAC alongside the verdict so a
    /// later idempotent replay can re-verify it before returning the
    /// stored success. The default falls back to [`Self::commit`] for
    /// foreign stores that do not carry the material; their replays then
    /// answer the duplicate vocabulary, never a success.
    fn commit_with_mac(
        &self,
        nonce: &str,
        record: &ChallengeRecord,
        valid: bool,
        operation_identity: Option<&str>,
        mac: Option<&str>,
    ) {
        let _ = (operation_identity, mac);
        self.commit(nonce, record, valid);
    }

    /// The live record counts: pending, consumed (for `/metrics`).
    fn counts(&self) -> (usize, usize);

    /// A short label for `/doctor` and the startup line.
    fn describe(&self) -> String;

    /// One live backend probe for `/doctor`: `Ok` carries a short fact
    /// about the answer, `Err` the refusal reason. The default is the
    /// structural truth for the in-process stores (no external
    /// dependency exists to reach); backends WITH an external
    /// dependency must override it and prove the round trip — a doctor
    /// store check that can never fail is not a check.
    fn probe(&self) -> Result<String, String> {
        Ok("in-process store, no external dependency to probe".to_string())
    }
}

/// One live record: the challenge record, its metadata and, once
/// committed, the verdict together with the MAC that authenticates it.
#[derive(Debug, Clone)]
struct Entry {
    record: ChallengeRecord,
    meta: RecordMeta,
    valid: Option<bool>,
    /// The server-state MAC the commit signed the verdict with. `None`
    /// before the commit, or when a legacy/plain commit landed without
    /// one — such a verdict never replays as a success.
    mac: Option<String>,
}

impl Entry {
    fn new(record: ChallengeRecord, meta: RecordMeta) -> Self {
        Entry {
            record,
            meta,
            valid: None,
            mac: None,
        }
    }

    /// The MAC-verification material this entry's stored verdict
    /// carries, when it carries one.
    fn stored_success(&self) -> Option<StoredSuccess> {
        let mac = self.mac.clone()?;
        Some(StoredSuccess {
            record: Box::new(self.record.clone()),
            mac,
        })
    }
}

/// The shared in-map state machine behind both the memory and the file
/// backend. The mutex is the transition boundary: it covers only the
/// bookkeeping, never a hash derivation.
struct MapState {
    pending: HashMap<String, Entry>,
    consumed: HashMap<String, Entry>,
    /// The earliest `expires_at` across both maps (`u64::MAX` when both
    /// are empty): the sweep gate. A sweep before that instant cannot
    /// drop anything, so it is skipped; an expired entry necessarily
    /// pulls this horizon to `<= now`, which opens the gate again —
    /// every caller prunes before it looks a record up, so the gate can
    /// never let an expired record answer a lookup. The invariant is
    /// maintained at every insert (`note_expiry`), at every commit
    /// (the replaced record's own expiry) and by the sweep's recompute.
    next_expiry: u64,
}

impl Default for MapState {
    fn default() -> Self {
        MapState {
            pending: HashMap::new(),
            consumed: HashMap::new(),
            next_expiry: u64::MAX,
        }
    }
}

impl MapState {
    /// Lower the horizon to a newly inserted record's expiry.
    fn note_expiry(&mut self, expires_at: u64) {
        if expires_at < self.next_expiry {
            self.next_expiry = expires_at;
        }
    }

    /// Drop expired records; returns their nonces so a durable backend
    /// can remove the persisted envelopes too. Gated on
    /// [`Self::next_expiry`]: one integer compare on the hot path
    /// instead of a full-map retain per request (the pre-gate sweep was
    /// O(live records) per insert — O(n²) cumulative for a long-lived
    /// process holding a full TTL window).
    fn prune_expired(&mut self, now_unix: u64) -> Vec<String> {
        if now_unix < self.next_expiry {
            return Vec::new();
        }
        let mut dropped = Vec::new();
        let mut next = u64::MAX;
        self.pending.retain(|nonce, e| {
            let live = e.record.expires_at > now_unix;
            if !live {
                dropped.push(nonce.clone());
            } else {
                next = next.min(e.record.expires_at);
            }
            live
        });
        self.consumed.retain(|nonce, e| {
            let live = e.record.expires_at > now_unix;
            if !live {
                dropped.push(nonce.clone());
            } else {
                next = next.min(e.record.expires_at);
            }
            live
        });
        self.next_expiry = next;
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
                stored: entry.stored_success(),
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
        // Issue-time prune: a TTL-backed store must not depend on
        // redemption traffic to reap issuance traffic. An attacker
        // that issues and never verifies would otherwise retain
        // expired challenges indefinitely.
        state.prune_expired(record.issued_at);
        state
            .pending
            .insert(record.nonce.clone(), Entry::new(record.clone(), meta));
        state.note_expiry(record.expires_at);
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
        self.commit_inner(nonce, record, valid, None);
    }

    fn commit_with_mac(
        &self,
        nonce: &str,
        record: &ChallengeRecord,
        valid: bool,
        operation_identity: Option<&str>,
        mac: Option<&str>,
    ) {
        let _ = operation_identity;
        self.commit_inner(nonce, record, valid, mac);
    }

    fn peek(&self, nonce: &str, now_unix: u64) -> PeekOutcome {
        let mut state = self.state.lock().expect("store lock");
        state.prune_expired(now_unix);
        if let Some(entry) = state.pending.get(nonce) {
            return PeekOutcome::Pending(Box::new(entry.record.clone()));
        }
        if state.consumed.contains_key(nonce) {
            return PeekOutcome::Consumed;
        }
        PeekOutcome::NotFound
    }

    fn counts(&self) -> (usize, usize) {
        let state = self.state.lock().expect("store lock");
        state.counts()
    }

    fn describe(&self) -> String {
        "in-process memory (volatile; a restart loses outstanding challenges)".to_string()
    }
}

impl MemoryStore {
    /// The shared commit seam: the verdict (and, when the caller signed
    /// one, the MAC that authenticates it) lands on the consumed entry.
    fn commit_inner(&self, nonce: &str, record: &ChallengeRecord, valid: bool, mac: Option<&str>) {
        let mut state = self.state.lock().expect("store lock");
        if let Some(entry) = state.consumed.get_mut(nonce) {
            entry.record = record.clone();
            entry.valid = Some(valid);
            entry.mac = mac.map(str::to_string);
            let expires_at = entry.record.expires_at;
            state.note_expiry(expires_at);
        }
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
    /// The server-state MAC the commit signed the verdict with. Absent
    /// on envelopes written before the authenticated seam (or by a
    /// plain commit); such a verdict never replays as a success.
    #[serde(default)]
    mac: Option<String>,
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
                    mac: envelope.mac,
                };
                let nonce = entry.record.nonce.clone();
                if state.pending.contains_key(&nonce) || state.consumed.contains_key(&nonce) {
                    return Err(format!(
                        "duplicate record nonce across store files: {nonce}"
                    ));
                }
                let expires_at = entry.record.expires_at;
                if envelope.state == STATE_CONSUMED {
                    state.consumed.insert(nonce, entry);
                } else {
                    state.pending.insert(nonce, entry);
                }
                // A loaded expired envelope must pull the sweep horizon
                // into the past so the first prune reaps it.
                state.note_expiry(expires_at);
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
                mac: entry.mac.clone(),
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
        // Issue-time prune: a TTL-backed store must not depend on
        // redemption traffic to reap issuance traffic.
        let dropped = state.prune_expired(record.issued_at);
        for gone in &dropped {
            self.remove_persisted(gone);
        }
        let entry = Entry::new(record.clone(), meta);
        // Write through before the map insert: a crash then leaves the
        // record either absent (the client re-issues) or pending. The
        // reverse order could lose a record the map already served.
        self.persist(STATE_PENDING, &entry)?;
        state.pending.insert(record.nonce.clone(), entry);
        state.note_expiry(record.expires_at);
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
        if let Some(mut entry) = state.pending.remove(nonce) {
            // The winning operation identity lands in the entry BEFORE
            // the consumed persist: the envelope on disk is what a
            // restart (or a replay of the record) reads, so the identity
            // must be part of the atomic flip, not an afterthought.
            if let Some(identity) = operation_identity {
                entry.meta.operation_identity = Some(identity.to_string());
            }
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
            return ConsumeOutcome::Won {
                record: Box::new(record),
                meta,
            };
        }
        match state.consumed.get(nonce) {
            Some(entry) => ConsumeOutcome::AlreadyConsumed {
                meta: entry.meta.clone(),
                succeeded: entry.valid,
                stored: entry.stored_success(),
            },
            None => ConsumeOutcome::NotFound,
        }
    }

    fn commit(&self, nonce: &str, record: &ChallengeRecord, valid: bool) {
        self.commit_inner(nonce, record, valid, None);
    }

    fn commit_with_mac(
        &self,
        nonce: &str,
        record: &ChallengeRecord,
        valid: bool,
        operation_identity: Option<&str>,
        mac: Option<&str>,
    ) {
        let _ = operation_identity;
        self.commit_inner(nonce, record, valid, mac);
    }

    fn peek(&self, nonce: &str, now_unix: u64) -> PeekOutcome {
        let mut state = self.state.lock().expect("store lock");
        let dropped = state.prune_expired(now_unix);
        for gone in &dropped {
            self.remove_persisted(gone);
        }
        if let Some(entry) = state.pending.get(nonce) {
            return PeekOutcome::Pending(Box::new(entry.record.clone()));
        }
        if state.consumed.contains_key(nonce) {
            return PeekOutcome::Consumed;
        }
        PeekOutcome::NotFound
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

    fn probe(&self) -> Result<String, String> {
        // The live directory read: a store whose records directory
        // vanished or lost its permission answers Err, so /doctor can
        // actually fail.
        let entries = fs::read_dir(&self.records_dir)
            .map_err(|e| format!("records directory unreadable: {e}"))?;
        let shards = entries.count();
        Ok(format!("directory readable ({shards} shard entries)"))
    }
}

impl FileStore {
    /// The shared commit seam: the verdict (and, when the caller signed
    /// one, the MAC) lands on the consumed entry and persists through
    /// the atomic rename. Best effort: a lost commit only degrades a
    /// later replay to the undecided duplicate answer.
    fn commit_inner(&self, nonce: &str, record: &ChallengeRecord, valid: bool, mac: Option<&str>) {
        let mut state = self.state.lock().expect("store lock");
        let mut expires_at = None;
        if let Some(entry) = state.consumed.get_mut(nonce) {
            entry.record = record.clone();
            entry.valid = Some(valid);
            entry.mac = mac.map(str::to_string);
            expires_at = Some(entry.record.expires_at);
            if self.persist(STATE_CONSUMED, entry).is_err() {
                // Best effort: a lost commit only degrades a later
                // replay to the undecided duplicate answer.
            }
        }
        if let Some(expires_at) = expires_at {
            state.note_expiry(expires_at);
        }
    }
}

#[cfg(feature = "redis-store")]
/// The core crate's fused Redis verifier store: the production backend,
/// key-compatible with the PHP bundle's Redis storage. The issuance-bound
/// metadata (action, cdata, decision id, scope, remoteip) rides a
/// TTL-bound companion key (`<prefix><nonce>:smeta`) so a token minted
/// on node A carries its provider metadata to node B; the operation
/// identity and the MAC-authenticated verdict live in the core's own
/// envelope (the authority both the replay gate and the MAC verify
/// against). The node-local map is kept only as a read-through cache.
pub struct RedisStore {
    inner: kiwicaptcha::redis_verify::RedisChallengeStore,
    /// A second handle on the same server for the sidecar metadata
    /// companion keys (`<prefix><nonce>:smeta`). The challenge record
    /// itself lives in the core envelope; action, cdata, scope and the
    /// issued remoteip ride a TTL-bound companion key so a token minted
    /// on node A carries its provider metadata to node B. The old
    /// node-local map is kept only as a read-through cache.
    meta_client: redis::Client,
    meta_prefix: String,
    meta: Mutex<MetaCache>,
}

#[cfg(feature = "redis-store")]
/// The node-local read-through cache with its own sweep horizon: the
/// per-put retain over every cached nonce was O(cache) per issuance
/// (O(n²) cumulative); the horizon gates it to instants where a drop is
/// actually possible, the same gate the in-process maps use.
struct MetaCache {
    map: HashMap<String, (u64, RecordMeta)>,
    /// The earliest cached expiry (`u64::MAX` when empty).
    next_expiry: u64,
}

#[cfg(feature = "redis-store")]
impl MetaCache {
    fn new() -> Self {
        MetaCache {
            map: HashMap::new(),
            next_expiry: u64::MAX,
        }
    }
}

#[cfg(feature = "redis-store")]
impl RedisStore {
    /// Connect to `url` under the key prefix `prefix`. The connection
    /// opens lazily per command inside the core store's pool, so this
    /// only validates the URL shape.
    pub fn connect(url: &str, prefix: &str) -> Result<Self, String> {
        let client = redis::Client::open(url.to_string())
            .map_err(|e| format!("cannot parse redis url {url}: {e}"))?;
        let meta_client = redis::Client::open(url.to_string())
            .map_err(|e| format!("cannot parse redis url {url}: {e}"))?;
        let inner = kiwicaptcha::redis_verify::RedisChallengeStore::new(client, prefix);
        Ok(RedisStore {
            inner,
            meta_client,
            meta_prefix: prefix.to_string(),
            meta: Mutex::new(MetaCache::new()),
        })
    }

    /// The companion metadata key: one per challenge, TTL-bound like
    /// the record itself.
    fn meta_key(&self, nonce: &str) -> String {
        format!("{}{}:smeta", self.meta_prefix, nonce)
    }

    /// Write the provider metadata to Redis so any node can serve the
    /// replay. Best effort: the local map still works for single-node.
    fn write_meta(&self, nonce: &str, expires_at: u64, meta: &RecordMeta) {
        let ttl = expires_at.saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let Ok(mut conn) = self.meta_client.get_connection() else {
            return;
        };
        let ttl_ms = (ttl.max(1) * 1000).min(2147483647) as i64;
        let payload = serde_json::to_string(meta).unwrap_or_default();
        let _: redis::RedisResult<()> = redis::cmd("SET")
            .arg(self.meta_key(nonce))
            .arg(payload)
            .arg("PX")
            .arg(ttl_ms)
            .query(&mut conn);
    }

    /// Read the provider metadata: Redis first (multi-node), then the
    /// local map (single-node fast path).
    fn read_meta(&self, nonce: &str) -> RecordMeta {
        if let Ok(mut conn) = self.meta_client.get_connection() {
            let payload: redis::RedisResult<Option<String>> =
                redis::cmd("GET").arg(self.meta_key(nonce)).query(&mut conn);
            if let Ok(Some(json)) = payload {
                if let Ok(meta) = serde_json::from_str::<RecordMeta>(&json) {
                    return meta;
                }
            }
        }
        let cache = self.meta.lock().expect("meta lock");
        cache
            .map
            .get(nonce)
            .map(|(_, m)| m.clone())
            .unwrap_or_default()
    }
}

#[cfg(feature = "redis-store")]
impl RecordStore for RedisStore {
    fn put_pending(&self, record: &ChallengeRecord, meta: RecordMeta) -> Result<(), String> {
        // Multi-node: write the provider metadata to the TTL-bound
        // companion key BEFORE the local cache, so a token minted on
        // this node carries its action/cdata to any peer.
        self.write_meta(&record.nonce, record.expires_at, &meta);
        let mut cache = self.meta.lock().expect("meta lock");
        // Issue-time prune of the local metadata cache, horizon-gated:
        // a sweep only runs when something can actually be dropped.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now >= cache.next_expiry {
            let mut next = u64::MAX;
            cache.map.retain(|_, (exp, _)| {
                let live = *exp > now;
                if live {
                    next = next.min(*exp);
                }
                live
            });
            cache.next_expiry = next;
        }
        cache
            .map
            .insert(record.nonce.clone(), (record.expires_at, meta));
        if record.expires_at < cache.next_expiry {
            cache.next_expiry = record.expires_at;
        }
        drop(cache);
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
        // Redis first: a token minted on another node must carry its
        // action/cdata/scope/remoteip here. The local map is only a
        // single-node cache.
        let meta = self.read_meta(nonce);
        match self
            .inner
            .consume_with_operation_identity(nonce, operation_identity)
        {
            Ok(Some(consumed)) => {
                // The envelope's recorded operation identity is the
                // authority for both branches: it is what the core's
                // replay gate and the commit MAC are signed against, and
                // it rides the atomic consume write, so it survives a
                // restart and reaches every node. The smeta companion
                // (action/cdata/scope/remoteip/decision) never carries
                // it, so a stale companion can never disagree here.
                let mut meta = meta;
                if consumed.operation_identity.is_some() {
                    meta.operation_identity = consumed.operation_identity.clone();
                }
                if consumed.first {
                    ConsumeOutcome::Won {
                        record: Box::new(consumed.record),
                        meta,
                    }
                } else {
                    let succeeded = consumed.stored_result.as_ref().map(|r| r.valid);
                    let stored = consumed.stored_result.as_ref().and_then(|r| {
                        let mac = r.mac.clone()?;
                        Some(StoredSuccess {
                            record: Box::new(consumed.record.clone()),
                            mac,
                        })
                    });
                    ConsumeOutcome::AlreadyConsumed {
                        meta,
                        succeeded,
                        stored,
                    }
                }
            }
            Ok(None) => ConsumeOutcome::NotFound,
            Err(e) => ConsumeOutcome::Unavailable(format!("redis consume failed: {e}")),
        }
    }

    fn peek(&self, nonce: &str, _now_unix: u64) -> PeekOutcome {
        use kiwicaptcha::redis_verify::RuntimeState;
        // One snapshot GET through the core's runtime-state seam: the
        // consumed envelope is not needed here (the authoritative
        // consume below supplies it), only the classification.
        match self.inner.runtime_state(nonce) {
            Ok(RuntimeState::Pending(record)) => PeekOutcome::Pending(record),
            Ok(RuntimeState::Consumed(_)) => PeekOutcome::Consumed,
            Ok(RuntimeState::Missing) | Ok(RuntimeState::Cancelled(_)) => PeekOutcome::NotFound,
            Err(e) => PeekOutcome::Unavailable(format!("redis peek failed: {e}")),
        }
    }

    fn commit(&self, nonce: &str, _record: &ChallengeRecord, valid: bool) {
        let _ = self.inner.commit_result(nonce, valid, None);
    }

    fn commit_with_mac(
        &self,
        nonce: &str,
        record: &ChallengeRecord,
        valid: bool,
        operation_identity: Option<&str>,
        mac: Option<&str>,
    ) {
        // Record the winning operation identity so a same-operation
        // retry can match it; the authenticated MAC is what makes the
        // stored result non-forgeable by a writer without the secret.
        if let Some(identity) = operation_identity {
            let mut cache = self.meta.lock().expect("meta lock");
            if let Some(entry) = cache.map.get_mut(nonce) {
                entry.1.operation_identity = Some(identity.to_string());
            }
        }
        // The binding rides the same value the MAC was signed over (the
        // record's own request binding): the core's retained-result
        // verification re-derives the tag from the STORED binding, so a
        // commit that stored None while signing Some(...) would make
        // every replay fail closed as malformed.
        let binding = record.request_binding.as_deref();
        let _ = self
            .inner
            .commit_result_with_mac(nonce, valid, binding, mac);
    }

    fn counts(&self) -> (usize, usize) {
        (0, 0)
    }

    fn describe(&self) -> String {
        "redis (the core crate's fused verifier store; multi-node capable)".to_string()
    }

    fn probe(&self) -> Result<String, String> {
        let mut conn = self
            .meta_client
            .get_connection()
            .map_err(|e| format!("connect failed: {e}"))?;
        let pong: redis::RedisResult<String> = redis::cmd("PING").query(&mut conn);
        match pong {
            Ok(reply) => Ok(format!("redis answered PING ({reply})")),
            Err(e) => Err(format!("PING failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwicaptcha::challenge::{
        issue_challenge, now_epoch_micros, BindingMode, ChallengeConfig, PoWAlgorithm,
    };

    fn record(scope: &str) -> ChallengeRecord {
        bound_record_inner(scope, None)
    }

    /// A record with an application transaction binding — the MAC's
    /// binding input must ride the commit and the replay material.
    fn bound_record(scope: &str) -> ChallengeRecord {
        bound_record_inner(scope, Some("req-mac-1:abc.de-1"))
    }

    fn bound_record_inner(scope: &str, binding: Option<&str>) -> ChallengeRecord {
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
            binding,
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
                        remoteip: None,
                        scope: None,
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

    /// The authenticated commit leaves verification material behind on
    /// BOTH in-process backends, so an idempotent replay can re-verify
    /// the tag; a plain commit leaves none (its verdict never replays
    /// as a success).
    #[test]
    fn commit_with_mac_leaves_replay_material_on_memory_and_file() {
        let mac = "cd".repeat(32);
        let check = |store: &dyn RecordStore, label: &str| {
            let record = bound_record("login");
            let nonce = record.nonce.clone();
            store.put_pending(&record, RecordMeta::default()).unwrap();
            let now = now_epoch_micros() / 1_000_000;
            let won = store.consume(&nonce, now, Some("op-material-1"));
            let (won_record, won_meta) = match won {
                ConsumeOutcome::Won { record, meta } => (*record, meta),
                other => panic!("[{label}] expected Won, got {other:?}"),
            };
            assert_eq!(
                won_meta.operation_identity.as_deref(),
                Some("op-material-1"),
                "[{label}] the winning consume must carry the identity"
            );
            store.commit_with_mac(
                &nonce,
                &won_record,
                true,
                won_meta.operation_identity.as_deref(),
                Some(&mac),
            );
            match store.consume(&nonce, now, Some("op-material-1")) {
                ConsumeOutcome::AlreadyConsumed {
                    succeeded,
                    stored,
                    meta,
                    ..
                } => {
                    assert_eq!(succeeded, Some(true), "[{label}] the verdict stored");
                    assert_eq!(
                        meta.operation_identity.as_deref(),
                        Some("op-material-1"),
                        "[{label}] the replay still sees the identity"
                    );
                    let stored = stored.unwrap_or_else(|| panic!("[{label}] MAC material"));
                    assert_eq!(stored.mac, mac, "[{label}] the signed tag rides along");
                    assert_eq!(
                        stored.record.challenge, record.challenge,
                        "[{label}] the MAC's challenge input"
                    );
                    assert_eq!(
                        stored.record.request_binding, record.request_binding,
                        "[{label}] the MAC's binding input"
                    );
                }
                other => panic!("[{label}] expected AlreadyConsumed, got {other:?}"),
            }
        };

        check(&MemoryStore::new(), "memory");

        let dir =
            std::env::temp_dir().join(format!("kiwi-file-store-material-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        check(&FileStore::open(&dir).expect("open"), "file");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A plain (MAC-less) commit stores the verdict but no replay
    /// material: its AlreadyConsumed answers `stored: None`, which the
    /// handler refuses to replay as a success.
    #[test]
    fn a_plain_commit_leaves_no_replay_material() {
        let store = MemoryStore::new();
        let record = record("login");
        let nonce = record.nonce.clone();
        store.put_pending(&record, RecordMeta::default()).unwrap();
        let now = now_epoch_micros() / 1_000_000;
        assert!(matches!(
            store.consume(&nonce, now, None),
            ConsumeOutcome::Won { .. }
        ));
        store.commit(&nonce, &record, true);
        match store.consume(&nonce, now, None) {
            ConsumeOutcome::AlreadyConsumed {
                succeeded, stored, ..
            } => {
                assert_eq!(succeeded, Some(true));
                assert!(stored.is_none(), "a MAC-less verdict carries no material");
            }
            other => panic!("expected AlreadyConsumed, got {other:?}"),
        }
    }

    /// The file backend records the winning operation identity INSIDE
    /// the consumed envelope — the atomic flip — so a restart (or any
    /// later reader) still matches an idempotent retry. Before the fix
    /// the identity only rode the in-memory return value and the
    /// envelope kept `null`, which made every file-backend retry a plain
    /// already_consumed after a reopen.
    #[test]
    fn file_store_records_the_operation_identity_in_the_consumed_envelope() {
        let dir =
            std::env::temp_dir().join(format!("kiwi-file-store-identity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let nonce;
        {
            let store = FileStore::open(&dir).expect("open");
            let r = record("login");
            nonce = r.nonce.clone();
            store.put_pending(&r, RecordMeta::default()).unwrap();
            let now = now_epoch_micros() / 1_000_000;
            match store.consume(&nonce, now, Some("op-envelope-1")) {
                ConsumeOutcome::Won { meta, .. } => {
                    assert_eq!(meta.operation_identity.as_deref(), Some("op-envelope-1"))
                }
                other => panic!("expected Won, got {other:?}"),
            }
        }
        {
            let reopened = FileStore::open(&dir).expect("reopen");
            let now = now_epoch_micros() / 1_000_000;
            match reopened.consume(&nonce, now, Some("op-envelope-1")) {
                ConsumeOutcome::AlreadyConsumed { meta, .. } => assert_eq!(
                    meta.operation_identity.as_deref(),
                    Some("op-envelope-1"),
                    "the identity must survive the restart inside the envelope"
                ),
                other => panic!("expected AlreadyConsumed, got {other:?}"),
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// The horizon gate keeps its two obligations: a live workload
    /// never sweeps (the gate closes), and an expired record still
    /// pulls the horizon into the past so the next call reaps it and
    /// the expired nonce answers NotFound — never a Won consume.
    #[test]
    fn horizon_gate_reaps_expired_and_gates_live() {
        let store = MemoryStore::new();
        let now = now_epoch_micros() / 1_000_000;

        // A fresh mint aged into the past: issued 400 s ago, expired
        // 280 s ago (ttl 120 s).
        let mut stale = record("login");
        stale.issued_at = now - 400;
        stale.expires_at = now - 280;
        store
            .put_pending(&stale, RecordMeta::default())
            .expect("insert stale");

        // A fresh live record: its issue-time prune observes the stale
        // horizon (the stale expiry pulled it into the past) and reaps.
        let live = record("login");
        store
            .put_pending(&live, RecordMeta::default())
            .expect("insert live");
        let (pending, _) = store.counts();
        assert_eq!(
            pending, 1,
            "the expired record is swept, the live one stays"
        );
        assert!(
            matches!(
                store.consume(&stale.nonce, now, None),
                ConsumeOutcome::NotFound
            ),
            "an expired nonce must answer NotFound, never Won"
        );
        assert!(matches!(
            store.consume(&live.nonce, now, None),
            ConsumeOutcome::Won { .. }
        ));
    }

    /// The A/B prune bench (manual), same process, same population:
    /// Phase A simulates the pre-gate behavior (sweep forced every
    /// call), Phase B runs the shipped horizon gate. Issue cost is
    /// measured outside the timed window.
    /// `cargo test -p kiwicaptcha-verifier --release store_prune_horizon_bench -- --ignored --nocapture`
    #[test]
    #[ignore = "manual A/B bench, not a gate"]
    fn store_prune_horizon_bench() {
        use std::time::Instant;
        const LIVE: usize = 50_000;
        const SWEEPS: usize = 5_000;
        let now = now_epoch_micros() / 1_000_000;

        let make_state = || {
            let mut st = MapState::default();
            for _ in 0..LIVE {
                let r = record("login");
                let expires = r.expires_at;
                st.pending
                    .insert(r.nonce.clone(), Entry::new(r, RecordMeta::default()));
                st.note_expiry(expires);
            }
            st
        };

        // Phase A — the pre-gate behavior: an unconditional full sweep
        // on every call (the horizon forced open each iteration).
        let mut ungated = make_state();
        let start = Instant::now();
        for _ in 0..SWEEPS {
            ungated.next_expiry = 0;
            let dropped = ungated.prune_expired(now);
            assert!(dropped.is_empty(), "the population is entirely live");
        }
        let ungated_elapsed = start.elapsed();

        // Phase B — the shipped gate: all-live population, horizon in
        // the future ⇒ one integer compare per call.
        let mut gated = make_state();
        let start = Instant::now();
        for _ in 0..SWEEPS {
            let dropped = gated.prune_expired(now);
            assert!(dropped.is_empty());
        }
        let gated_elapsed = start.elapsed();

        println!(
            "prune A/B: {SWEEPS} sweeps over {LIVE} live records: ungated {ungated_elapsed:?} ({:.2} us/op) vs gated {gated_elapsed:?} ({:.4} us/op) — {:.0}x",
            ungated_elapsed.as_micros() as f64 / SWEEPS as f64,
            gated_elapsed.as_nanos() as f64 / SWEEPS as f64 / 1_000.0,
            ungated_elapsed.as_secs_f64() / gated_elapsed.as_secs_f64().max(1e-12),
        );

        // End-to-end store path with the issuance cost excluded from
        // the timed window: put_pending over the same population.
        let store = MemoryStore::new();
        let mut prefill = Vec::with_capacity(LIVE);
        for _ in 0..LIVE {
            prefill.push(record("login"));
        }
        for r in &prefill {
            store
                .put_pending(r, RecordMeta::default())
                .expect("prefill");
        }
        let mut ops = Vec::with_capacity(SWEEPS);
        for _ in 0..SWEEPS {
            ops.push(record("login"));
        }
        let start = Instant::now();
        for r in &ops {
            store.put_pending(r, RecordMeta::default()).expect("op");
        }
        let elapsed = start.elapsed();
        println!(
            "store path: {SWEEPS} inserts over {LIVE} live records in {elapsed:?} ({:.3} us/op, issuance excluded)",
            elapsed.as_micros() as f64 / SWEEPS as f64
        );
        assert_eq!(store.counts().0, LIVE + SWEEPS);
    }
}

#[cfg(all(test, feature = "redis-store"))]
mod redis_store_tests {
    use super::*;
    use kiwicaptcha::challenge::{issue_challenge, now_epoch_micros, BindingMode, ChallengeConfig};

    const SECRET: &str = "kiwi-verifier-redis-store-test-secret-0123456789";

    /// The env-gated Redis URL: `TEST_REDIS_URL` first (the shared test
    /// harness convention), then `RISK_REDIS_URL`. Without either the
    /// test skips, exactly like the core's Redis suites.
    fn redis_url() -> Option<String> {
        for name in ["TEST_REDIS_URL", "RISK_REDIS_URL"] {
            if let Ok(url) = std::env::var(name) {
                if !url.is_empty() {
                    return Some(if let Some(rest) = url.strip_prefix("tcp://") {
                        format!("redis://{rest}")
                    } else {
                        url
                    });
                }
            }
        }
        eprintln!("TEST_REDIS_URL/RISK_REDIS_URL unset — redis-store tests skipped");
        None
    }

    fn prefix(label: &str) -> String {
        format!("kiwi:verifier:test:{label}:{}:", std::process::id())
    }

    fn record() -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: SECRET.to_string(),
            algorithm: kiwicaptcha::challenge::PoWAlgorithm::Sha256,
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
            &config,
            "login",
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
    fn redis_store_round_trips_consume_commit_replay_and_delete() {
        let Some(url) = redis_url() else { return };
        let prefix = prefix("roundtrip");
        let record = record();
        let nonce = record.nonce.clone();
        let meta = RecordMeta {
            action: Some("checkout".to_string()),
            cdata: None,
            decision_id: None,
            operation_identity: None,
            remoteip: None,
            scope: None,
        };

        // Store (pending) through the sidecar's Redis backend.
        let store = RedisStore::connect(&url, &prefix).expect("the store connects");
        store.put_pending(&record, meta).expect("the record stores");

        // Load + the one-shot consume transition.
        let now = now_epoch_micros() / 1_000_000;
        match store.consume(&nonce, now, None) {
            ConsumeOutcome::Won { record, meta } => {
                assert_eq!(record.nonce, nonce);
                assert_eq!(meta.action.as_deref(), Some("checkout"));
            }
            other => panic!("expected the winning consume, got {other:?}"),
        }
        // A second consume is the replay answer; the commit echoes the
        // verdict stored by the first verification.
        store.commit(&nonce, &record, true);
        match store.consume(&nonce, now, None) {
            ConsumeOutcome::AlreadyConsumed { succeeded, .. } => {
                assert_eq!(succeeded, Some(true));
            }
            other => panic!("expected the replay answer, got {other:?}"),
        }

        // Delete: the core store's best-effort terminal cleanup, then a
        // fresh sidecar store sees no record at all.
        let core = kiwicaptcha::redis_verify::RedisChallengeStore::new(
            redis::Client::open(url.clone()).expect("url parses"),
            prefix.clone(),
        );
        core.best_effort_delete(&nonce);
        let reread = RedisStore::connect(&url, &prefix).expect("the store reconnects");
        assert!(matches!(
            reread.consume(&nonce, now, None),
            ConsumeOutcome::NotFound
        ));
    }

    #[test]
    fn redis_store_reports_url_shape_and_backend_errors() {
        // A URL the client cannot parse is refused at construction, not
        // at the first request.
        assert!(RedisStore::connect("not-a-redis-url", "p:").is_err());
        // The describe label is the backend surface /doctor reports.
        let Some(url) = redis_url() else { return };
        let store = RedisStore::connect(&url, &prefix("describe")).expect("the store connects");
        assert!(store.describe().contains("redis"));
    }

    /// The multi-node contract: the operation identity rides the core's
    /// consumed envelope (the authority), and the committed verdict
    /// lands with its MAC AND the record's binding — the exact inputs a
    /// replay on ANY node re-verifies. Before the fix the identity only
    /// lived in the node-local map and the commit stored `binding: null`
    /// while signing `Some(...)`, so every cross-node idempotent retry
    /// either refused as a replay or failed the MAC as malformed.
    #[test]
    fn redis_store_rides_the_envelope_identity_binding_and_mac_to_any_node() {
        let Some(url) = redis_url() else { return };
        let prefix = prefix("macmaterial");
        // A bound record: the MAC's binding input must be the record's
        // own request binding, and the stored result must carry it.
        let config = ChallengeConfig {
            secret_key: SECRET.to_string(),
            algorithm: kiwicaptcha::challenge::PoWAlgorithm::Sha256,
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
        let record = issue_challenge(
            &config,
            "login",
            "198.51.100.7",
            now_ns / 1_000_000,
            now_ns,
            0,
            Some("req-mac-node:abc.de-1"),
        )
        .expect("issue")
        .record;
        let nonce = record.nonce.clone();
        let mac = "ef".repeat(32);
        let binding = record.request_binding.clone();
        assert!(binding.is_some(), "the probe record carries a binding");
        let store = RedisStore::connect(&url, &prefix).expect("the store connects");
        store
            .put_pending(&record, RecordMeta::default())
            .expect("the record stores");

        // The winning consume records the identity in the envelope.
        let now = now_epoch_micros() / 1_000_000;
        let (won_record, won_meta) = match store.consume(&nonce, now, Some("op-node-2")) {
            ConsumeOutcome::Won { record, meta } => (*record, meta),
            other => panic!("expected the winning consume, got {other:?}"),
        };
        assert_eq!(
            won_meta.operation_identity.as_deref(),
            Some("op-node-2"),
            "the winner's identity must come back from the envelope"
        );

        // The authenticated commit stores the verdict with the MAC and
        // the binding the MAC was signed over.
        store.commit_with_mac(&nonce, &won_record, true, Some("op-node-2"), Some(&mac));

        // A retry reaching this store — the "other node" shape: same
        // Redis, fresh store handle, no node-local map state — carries
        // the identity, the verdict and the verification material.
        let other_node = RedisStore::connect(&url, &prefix).expect("the store reconnects");
        match other_node.consume(&nonce, now, Some("op-node-2")) {
            ConsumeOutcome::AlreadyConsumed {
                meta,
                succeeded,
                stored,
            } => {
                assert_eq!(
                    meta.operation_identity.as_deref(),
                    Some("op-node-2"),
                    "the identity must reach a fresh node from the envelope"
                );
                assert_eq!(succeeded, Some(true));
                let stored = stored.expect("the MAC material rides the envelope");
                assert_eq!(stored.mac, mac);
                assert_eq!(stored.record.challenge, record.challenge);
                assert_eq!(stored.record.request_binding, binding);
            }
            other => panic!("expected AlreadyConsumed on the peer node, got {other:?}"),
        }

        // And the core envelope itself carries the binding the MAC was
        // signed over — the input the core's own retained-result
        // verification (the PHP bundle replaying the same record) uses.
        match other_node
            .inner
            .consume_with_operation_identity(&nonce, Some("op-node-2"))
        {
            Ok(Some(consumed)) => {
                let stored = consumed
                    .stored_result
                    .expect("the committed verdict is retained");
                assert_eq!(
                    stored.binding.as_deref(),
                    binding.as_deref(),
                    "the stored result binding must equal the MAC's binding input"
                );
                assert_eq!(stored.mac.as_deref(), Some(mac.as_str()));
                assert_eq!(consumed.operation_identity.as_deref(), Some("op-node-2"));
            }
            other => panic!("expected the consumed record, got {other:?}"),
        }

        // Cleanup so the prefixed keys never linger between runs.
        let core = kiwicaptcha::redis_verify::RedisChallengeStore::new(
            redis::Client::open(url.clone()).expect("url parses"),
            prefix.clone(),
        );
        core.best_effort_delete(&nonce);
    }
}
