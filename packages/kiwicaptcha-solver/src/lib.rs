//! # kiwicaptcha-solver
//!
//! The native solver library behind the KiwiCaptcha automation CLI: it
//! fetches a challenge document, performs the exact proof of work a browser
//! widget performs, and packs the wire token the verify endpoint accepts.
//! It exists to give unauthenticated, well-behaved automation a supported
//! path at the same price as a browser, and it is honest about that price:
//! the caps, the difficulty ceilings and the token grammar are the browser's
//! own, imported rather than reimplemented.
//!
//! ## The documented JSON flow
//!
//! 1. Fetch the challenge: the reference deployments expose the challenge
//!    route as an HTTP POST carrying a JSON body (`{"scope": "login"}`,
//!    plus `"algorithm"` when a non-default profile is requested), and
//!    answer with the bare challenge object whose keys this crate's
//!    [`Challenge`] parses (`nonce`, `challenge`, `salt`, `algorithm`,
//!    `mKib`, `t`, `p`, `targetBits`, `ttlSecs`, `minDurationMs`,
//!    `prefix`, plus the optional `decoy_field`, `execution_program` and
//!    `rsw_modulus` keys).
//! 2. [`solve`] the challenge: SHA-256 or Argon2id hash search, or the rsw
//!    sequential-squaring time lock, always inside the protocol caps.
//! 3. [`Solution::token`] packs the wire token, and
//!    [`verify_endpoint_request`] builds the provider-shaped siteverify
//!    POST body (`secret`, `response`, optional `remoteip`) the symfony
//!    bundle's `/siteverify` route documents.
//!
//! ## Sharing decision
//!
//! The algorithms are shared with the other solvers, not forked blindly:
//!
//! - The token encoder is [`kiwicaptcha::SolutionToken::encode`] from the
//!   workspace core crate, used verbatim. The token this crate emits is
//!   byte-identical to the widget's by construction, because it is the
//!   same encoder.
//! - The caps are the core crate's re-exported constants, themselves kept
//!   in parity with protocol/limits.json by the repository's CI gate:
//!   [`SOLVER_MAX_HASHES`] (20,000,000), [`SOLVER_MAX_TARGET_BITS`] (20),
//!   [`SOLVER_MAX_ARGON2_TARGET_BITS`] (10) and
//!   [`SOLVER_MAX_ARGON2_M_KIB`] (64 MiB in KiB). This crate adds no cap
//!   of its own and refuses to run past the documented ones.
//! - The rsw public path reuses [`kiwicaptcha::derive_base`] and
//!   [`kiwicaptcha::proof_hex`]: the base derivation and the 512-hex wire
//!   form are the core crate's own functions, so the sequential squaring
//!   here starts and ends exactly where the trapdoor verifier expects.
//! - The SHA-256 and Argon2id search loops are implemented here against
//!   the shared preimage contract: SHA-256 over `prefix || counter || salt`
//!   with the counter in decimal, and Argon2id over `prefix || counter`
//!   as the password with the salt bytes and the issued `m_kib`/`t`/`p`.
//!   The core verifier's `derive_hash` is private to that crate and the
//!   wasm solver is wasm-bindgen-shaped and excluded from the workspace,
//!   so neither can be called directly; the tests prove the equivalence
//!   the strong way instead, by running the core verifier end to end over
//!   tokens this crate produces, and by pinning the token wire bytes to
//!   the shared protocol fixtures.
//!
//! ## What is refused
//!
//! A challenge carrying an execution program needs the browser's sandboxed
//! interpreter and is refused with [`SolveError::ExecutionUnsupported`]:
//! that dimension is deliberately outside the native path. Challenges
//! whose difficulty exceeds the browser ceilings, Argon2id parameters
//! outside the issued contract, and rsw parameters outside the protocol
//! bounds are all refused before any work is spent, and a caller-supplied
//! hash cap above the documented solver maximum is refused outright. A
//! solve that would exceed the cap returns [`SolveError::Exhausted`]
//! instead of looping without bound.

pub mod bench;
pub mod http;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kiwicaptcha::PoWAlgorithm;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

// The protocol caps, imported from the core crate so this solver and the
// verifier it must satisfy can never drift. protocol/limits.json is the
// authority; the core constants are its Rust mirror.
pub use kiwicaptcha::{
    derive_base, proof_hex, SOLVER_MAX_ARGON2_M_KIB, SOLVER_MAX_ARGON2_TARGET_BITS,
    SOLVER_MAX_HASHES, SOLVER_MAX_TARGET_BITS,
};

/// The client contract's rsw bounds (protocol/limits.json rsw_t_min and
/// rsw_t_max, mirrored by the core crate's issuance constants).
const RSW_T_MIN: u32 = kiwicaptcha::challenge::MIN_RSW_T;
const RSW_T_MAX: u32 = kiwicaptcha::challenge::MAX_RSW_T;

/// How often the SHA-256 loop checks the cancellation token, the same
/// cadence the wasm chunk solver checks its clock: a relaxed atomic load
/// every 256 hashes keeps cancellation prompt without touching the hot
/// path's cost.
const SHA_CANCEL_INTERVAL: u64 = 256;

/// The default progress cadence per algorithm when the caller leaves
/// `progress_interval` at zero: dense enough to animate a CLI, sparse
/// enough that the callback never costs more than the work it reports.
const DEFAULT_SHA_PROGRESS_INTERVAL: u64 = 65_536;
const DEFAULT_ARGON_PROGRESS_INTERVAL: u64 = 64;
const DEFAULT_RSW_PROGRESS_INTERVAL: u64 = 1024;

/// A challenge document, parsed from the challenge endpoint's JSON.
///
/// The wire keys are the endpoint's own (the PHP `Challenge::toArray` key
/// set the symfony route emits and the widget driver validates): camelCase
/// `mKib`/`targetBits`/`ttlSecs`/`minDurationMs` beside the snake_case
/// optional keys. Unknown keys are tolerated so a newer deployment can add
/// one without breaking this solver. The rsw modulus rides `rsw_modulus`
/// exactly as issued; the trapdoor lambda never appears on this surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// The single-use nonce, standard base64 of 32 bytes (44 chars).
    pub nonce: String,
    /// The signed challenge string, folded into the proof's prefix.
    pub challenge: String,
    /// The salt, standard base64; folded into the hash input.
    pub salt: String,
    /// The proof-of-work algorithm; the solver dispatches on this field
    /// alone, exactly like the widget and the verifier.
    pub algorithm: PoWAlgorithm,
    /// Memory cost in KiB for Argon2id challenges (0 for the others).
    #[serde(rename = "mKib")]
    pub m_kib: u32,
    /// Time cost: Argon2id passes, or the rsw squaring count T.
    pub t: u32,
    /// Parallelism (always 1 in the issued contract).
    pub p: u32,
    /// Required leading zero bits (the rsw contract pins 1 and never
    /// consults it: the time lock is the proof).
    #[serde(rename = "targetBits")]
    pub target_bits: u32,
    /// Challenge lifetime in seconds.
    #[serde(rename = "ttlSecs")]
    pub ttl_secs: u64,
    /// The server-enforced minimum solve duration, informational here.
    #[serde(rename = "minDurationMs")]
    pub min_duration_ms: u64,
    /// The preimage prefix (`challenge|salt|`), prepended to the counter.
    pub prefix: String,
    /// The server-issued decoy field name, informational for a client
    /// that posts no forms: a decoy is form-field evidence, never part of
    /// the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_field: Option<String>,
    /// The ExecutionChallengeV1 program. Present means the challenge
    /// needs the browser interpreter, and [`solve`] refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_program: Option<String>,
    /// The rsw modulus n (standard base64 of the 2048-bit composite),
    /// present only for rsw challenges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsw_modulus: Option<String>,
}

impl Challenge {
    /// Parse a challenge from the endpoint's JSON response body.
    ///
    /// The bare challenge object is the shape the reference deployments
    /// emit. A wrapper that nests the whole document under a `challenge`
    /// key is unwrapped too, so a gateway that envelopes the response
    /// stays usable: the discriminator is structural (the bare object's
    /// own `challenge` field is a string, an envelope's is an object).
    /// Parsing validates nothing beyond the JSON grammar; the client
    /// contract is enforced at solve time, mirroring the split the widget
    /// itself makes between fetch and validation.
    pub fn from_json(raw: &str) -> Result<Self, SolveError> {
        let value: serde_json::Value = serde_json::from_str(raw).map_err(|_| {
            SolveError::MalformedChallenge("the challenge response is not a JSON document")
        })?;
        let document = match value.get("challenge") {
            Some(nested @ serde_json::Value::Object(_)) => nested,
            _ => &value,
        };
        serde_json::from_value(document.clone()).map_err(|_| {
            SolveError::MalformedChallenge(
                "the challenge object is missing required fields or mistypes one",
            )
        })
    }

    /// Enforce the client contract before any work is spent: the same
    /// bounds the widget driver validates (nonce shape, prefix and salt
    /// sizes, per-algorithm parameter ranges, rsw modulus shape), plus the
    /// refusal of execution-armed challenges the native path cannot run.
    fn validate_for_solve(&self) -> Result<(), SolveError> {
        if self.execution_program.is_some() {
            return Err(SolveError::ExecutionUnsupported);
        }
        if self.nonce.len() != 44
            || !self.nonce.as_bytes()[..43]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
            || !self.nonce.ends_with('=')
        {
            return Err(SolveError::MalformedChallenge(
                "the nonce is not the standard base64 of 32 bytes",
            ));
        }
        if self.prefix.is_empty() || self.prefix.len() > 4096 {
            return Err(SolveError::MalformedChallenge(
                "the prefix length is outside 1..=4096",
            ));
        }
        let salt = B64
            .decode(&self.salt)
            .map_err(|_| SolveError::MalformedChallenge("the salt is not standard base64"))?;
        if salt.is_empty() || self.salt.len() > 512 {
            return Err(SolveError::MalformedChallenge(
                "the salt is empty or longer than 512 characters",
            ));
        }
        match self.algorithm {
            PoWAlgorithm::Sha256 => {
                if self.target_bits == 0 || self.target_bits > SOLVER_MAX_TARGET_BITS {
                    return Err(SolveError::DifficultyBeyondCap {
                        algorithm: self.algorithm,
                        target_bits: self.target_bits,
                        cap: SOLVER_MAX_TARGET_BITS,
                    });
                }
            }
            PoWAlgorithm::Argon2id => {
                if self.target_bits == 0 || self.target_bits > SOLVER_MAX_ARGON2_TARGET_BITS {
                    return Err(SolveError::DifficultyBeyondCap {
                        algorithm: self.algorithm,
                        target_bits: self.target_bits,
                        cap: SOLVER_MAX_ARGON2_TARGET_BITS,
                    });
                }
                if self.m_kib < 8 || self.m_kib > SOLVER_MAX_ARGON2_M_KIB || self.m_kib < 8 * self.p
                {
                    return Err(SolveError::UnsupportedArgon2Params {
                        m_kib: self.m_kib,
                        t: self.t,
                        p: self.p,
                    });
                }
                if self.t < 3 || self.t > 6 || self.p != 1 {
                    return Err(SolveError::UnsupportedArgon2Params {
                        m_kib: self.m_kib,
                        t: self.t,
                        p: self.p,
                    });
                }
            }
            PoWAlgorithm::Rsw => {
                if self.t < RSW_T_MIN || self.t > RSW_T_MAX || self.p != 1 || self.m_kib != 0 {
                    return Err(SolveError::UnsupportedRswParams(
                        "the squaring count T is outside the protocol bounds or the memory fields are nonzero",
                    ));
                }
                let modulus =
                    self.rsw_modulus
                        .as_deref()
                        .ok_or(SolveError::UnsupportedRswParams(
                            "an rsw challenge carries no modulus",
                        ))?;
                let bytes = B64.decode(modulus).map_err(|_| {
                    SolveError::UnsupportedRswParams("the rsw modulus is not standard base64")
                })?;
                if bytes.len() != kiwicaptcha::rsw::MODULUS_BYTES
                    || bytes[0] & 0x80 == 0
                    || bytes[bytes.len() - 1] & 1 == 0
                {
                    return Err(SolveError::UnsupportedRswParams(
                        "the rsw modulus is not a canonical 2048-bit odd composite",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A cooperative cancellation token: [`solve`] polls it inside the search
/// loop and stops with [`SolveError::Cancelled`] when it fires.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. Polling observes the request promptly (within
    /// one SHA-256 check interval, or one Argon2id or rsw step).
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// One progress report from a running solve: the number of hashes (or
/// squarings) completed so far. The final outcome travels on the
/// [`Solution`], not on the callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressEvent {
    pub attempted: u64,
}

/// The knobs of one solve. Defaults give the documented browser price: the
/// full [`SOLVER_MAX_HASHES`] search space and a per-algorithm progress
/// cadence. A `max_hashes` above the documented cap is refused (same price
/// as a browser means the same caps, never more).
#[derive(Default)]
pub struct SolveOptions<'a> {
    /// The search-space bound. Zero means the documented default,
    /// [`SOLVER_MAX_HASHES]; values above it are refused.
    pub max_hashes: u64,
    /// Report progress every this many hashes or squarings; zero selects
    /// the per-algorithm default cadence. Progress is never reported more
    /// often than the cap allows.
    pub progress_interval: u64,
    /// The cancellation token polled inside the loop.
    pub cancel: Option<&'a CancellationToken>,
    /// The progress callback.
    pub on_progress: Option<&'a mut dyn FnMut(ProgressEvent)>,
}

impl SolveOptions<'_> {
    /// The effective search-space bound: the documented cap when the
    /// caller passes zero, and a refusal when the caller asks for more
    /// than the cap (the browser's price is the maximum on offer).
    fn effective_max_hashes(&self) -> Result<u64, SolveError> {
        match self.max_hashes {
            0 => Ok(SOLVER_MAX_HASHES),
            n if n > SOLVER_MAX_HASHES => Err(SolveError::CapTooLarge {
                requested: n,
                cap: SOLVER_MAX_HASHES,
            }),
            n => Ok(n),
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel.is_some_and(CancellationToken::is_cancelled)
    }

    fn emit(&mut self, attempted: u64) {
        if let Some(cb) = self.on_progress.as_mut() {
            cb(ProgressEvent { attempted });
        }
    }
}

/// A completed solve.
#[derive(Debug, Clone, PartialEq)]
pub struct Solution {
    /// The winning counter (the first counter whose hash meets the
    /// target). Zero for rsw, whose proof carries no search counter.
    pub counter: u64,
    /// The wall-clock solve duration in milliseconds, as the widget
    /// reports it (telemetry only; the server measures its own floor).
    pub duration_ms: u64,
    /// The work spent: hashes tried, or squarings performed.
    pub hashes: u64,
    /// The winning digest, 64 lowercase hex, or the rsw final value's
    /// 512-hex wire form.
    pub hash_hex: String,
    /// The rsw final value, present only for an rsw solve.
    pub rsw_proof: Option<String>,
    /// The telemetry object folded into the token: `{}`, the shape an
    /// off widget sends and the default this solver reports (a native
    /// client has no browser signals to claim).
    pub telemetry: serde_json::Value,
}

impl Solution {
    /// Pack the wire token the verify endpoint accepts:
    /// `base64(nonce.counter.duration.telemetry)` with the rsw proof
    /// appended as the final 512-hex segment for an rsw solve. The
    /// encoder is the core crate's own, so the bytes are the widget's
    /// bytes by construction.
    pub fn token(&self, challenge: &Challenge) -> String {
        kiwicaptcha::SolutionToken {
            nonce: challenge.nonce.clone(),
            counter: self.counter,
            duration_ms: self.duration_ms.min(kiwicaptcha::token::MAX_DURATION_MS),
            telemetry: self.telemetry.clone(),
            execution_digest: None,
            execution_trace: None,
            rsw_proof: self.rsw_proof.clone(),
        }
        .encode()
    }
}

/// Why a solve refused to run or failed to find a proof.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SolveError {
    #[error("the challenge document is malformed: {0}")]
    MalformedChallenge(&'static str),
    #[error("target_bits {target_bits} exceeds the solver cap {cap} for {}", .algorithm.as_str())]
    DifficultyBeyondCap {
        algorithm: PoWAlgorithm,
        target_bits: u32,
        cap: u32,
    },
    #[error("argon2id parameters are outside the client contract (m_kib {m_kib}, t {t}, p {p})")]
    UnsupportedArgon2Params { m_kib: u32, t: u32, p: u32 },
    #[error("the rsw parameters are outside the client contract: {0}")]
    UnsupportedRswParams(&'static str),
    #[error(
        "an execution-armed challenge needs the browser interpreter; the native solver refuses it"
    )]
    ExecutionUnsupported,
    #[error("the requested hash cap {requested} exceeds the documented solver cap {cap}")]
    CapTooLarge { requested: u64, cap: u64 },
    #[error("no counter met the target within the {attempted}-hash cap")]
    Exhausted { attempted: u64 },
    #[error("the solve was cancelled after {attempted} hashes")]
    Cancelled { attempted: u64 },
}

/// Solve a challenge at the browser's price.
///
/// The search is bounded by the cap (never the challenge's theoretical
/// difficulty), reports progress through the callback, stops promptly on
/// cancellation, and returns the first acceptable counter together with
/// the derived digest. The caller packs the wire token with
/// [`Solution::token`].
pub fn solve(challenge: &Challenge, opts: &mut SolveOptions<'_>) -> Result<Solution, SolveError> {
    challenge.validate_for_solve()?;
    let cap = opts.effective_max_hashes()?;
    match challenge.algorithm {
        PoWAlgorithm::Sha256 => solve_sha256(challenge, opts, cap),
        PoWAlgorithm::Argon2id => solve_argon2id(challenge, opts, cap),
        PoWAlgorithm::Rsw => solve_rsw(challenge, opts),
    }
}

/// The SHA-256 search: hash `prefix || decimal(counter) || salt` for each
/// counter from zero, first hit wins. The preimage layout is the contract
/// the core verifier's derive_hash and the wasm chunk solver share.
fn solve_sha256(
    challenge: &Challenge,
    opts: &mut SolveOptions<'_>,
    cap: u64,
) -> Result<Solution, SolveError> {
    let salt = B64
        .decode(&challenge.salt)
        .map_err(|_| SolveError::MalformedChallenge("the salt stopped decoding between checks"))?;
    let started = Instant::now();
    let interval = match opts.progress_interval {
        0 => DEFAULT_SHA_PROGRESS_INTERVAL,
        n => n,
    };
    let mut base = Sha256::new();
    base.update(challenge.prefix.as_bytes());
    let mut counter_buf = [0u8; 20];
    for counter in 0..cap {
        if counter.is_multiple_of(SHA_CANCEL_INTERVAL) && opts.cancelled() {
            return Err(SolveError::Cancelled { attempted: counter });
        }
        let mut hasher = base.clone();
        let len = write_decimal(counter, &mut counter_buf);
        hasher.update(&counter_buf[..len]);
        hasher.update(&salt);
        let digest = hasher.finalize();
        if leading_zero_bits(&digest) >= challenge.target_bits {
            let attempted = counter + 1;
            opts.emit(attempted);
            return Ok(Solution {
                counter,
                duration_ms: started.elapsed().as_millis() as u64,
                hashes: attempted,
                hash_hex: hex_lower(&digest),
                rsw_proof: None,
                telemetry: empty_telemetry(),
            });
        }
        let attempted = counter + 1;
        if interval > 0 && attempted.is_multiple_of(interval) {
            opts.emit(attempted);
        }
    }
    Err(SolveError::Exhausted { attempted: cap })
}

/// The Argon2id search: Argon2id(password `prefix || decimal(counter)`,
/// salt, m_kib, t, p) for each counter, first hit wins, with the memory
/// buffer allocated once and reused exactly like the wasm chunk solver.
fn solve_argon2id(
    challenge: &Challenge,
    opts: &mut SolveOptions<'_>,
    cap: u64,
) -> Result<Solution, SolveError> {
    let salt = B64
        .decode(&challenge.salt)
        .map_err(|_| SolveError::MalformedChallenge("the salt stopped decoding between checks"))?;
    let params =
        Params::new(challenge.m_kib, challenge.t, challenge.p, Some(32)).map_err(|_| {
            SolveError::UnsupportedArgon2Params {
                m_kib: challenge.m_kib,
                t: challenge.t,
                p: challenge.p,
            }
        })?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut memory = vec![Block::default(); params.block_count()];
    let started = Instant::now();
    let interval = match opts.progress_interval {
        0 => DEFAULT_ARGON_PROGRESS_INTERVAL,
        n => n,
    };
    let mut password = Vec::with_capacity(challenge.prefix.len() + 20);
    password.extend_from_slice(challenge.prefix.as_bytes());
    let digit_start = password.len();
    let mut counter_buf = [0u8; 20];
    let mut output = [0u8; 32];
    for counter in 0..cap {
        if opts.cancelled() {
            return Err(SolveError::Cancelled { attempted: counter });
        }
        password.truncate(digit_start);
        let len = write_decimal(counter, &mut counter_buf);
        password.extend_from_slice(&counter_buf[..len]);
        hasher
            .hash_password_into_with_memory(&password, &salt, &mut output, &mut memory)
            .map_err(|_| SolveError::UnsupportedArgon2Params {
                m_kib: challenge.m_kib,
                t: challenge.t,
                p: challenge.p,
            })?;
        if leading_zero_bits(&output) >= challenge.target_bits {
            let attempted = counter + 1;
            opts.emit(attempted);
            return Ok(Solution {
                counter,
                duration_ms: started.elapsed().as_millis() as u64,
                hashes: attempted,
                hash_hex: hex_lower(&output),
                rsw_proof: None,
                telemetry: empty_telemetry(),
            });
        }
        let attempted = counter + 1;
        if interval > 0 && attempted.is_multiple_of(interval) {
            opts.emit(attempted);
        }
    }
    Err(SolveError::Exhausted { attempted: cap })
}

/// The rsw time lock: T sequential modular squarings of the derived base
/// over the issued 2048-bit composite, rendered as the 512-hex wire form.
/// The base derivation and the rendering are the core crate's own public
/// functions; only the irreducibly sequential loop lives here, exactly as
/// the worker's BigInt solver performs it.
fn solve_rsw(challenge: &Challenge, opts: &mut SolveOptions<'_>) -> Result<Solution, SolveError> {
    let modulus_b64 = challenge
        .rsw_modulus
        .as_deref()
        .ok_or(SolveError::UnsupportedRswParams(
            "an rsw challenge carries no modulus",
        ))?;
    let modulus_bytes = B64
        .decode(modulus_b64)
        .map_err(|_| SolveError::UnsupportedRswParams("the rsw modulus is not standard base64"))?;
    let modulus = BigUint::from_bytes_be(&modulus_bytes);
    let t = u64::from(challenge.t);
    let started = Instant::now();
    let interval = match opts.progress_interval {
        0 => DEFAULT_RSW_PROGRESS_INTERVAL,
        n => n,
    };
    let mut value = derive_base(&challenge.prefix, &challenge.nonce, &modulus);
    let mut done: u64 = 0;
    while done < t {
        if opts.cancelled() {
            return Err(SolveError::Cancelled { attempted: done });
        }
        value = (&value * &value) % &modulus;
        done += 1;
        if interval > 0 && done.is_multiple_of(interval) {
            opts.emit(done);
        }
    }
    let proof = proof_hex(&value);
    opts.emit(done);
    Ok(Solution {
        counter: 0,
        duration_ms: started.elapsed().as_millis() as u64,
        hashes: done,
        hash_hex: proof.clone(),
        rsw_proof: Some(proof),
        telemetry: empty_telemetry(),
    })
}

/// Build the verify POST body: the provider-shaped siteverify document
/// (`secret`, `response`, optional `remoteip`) the symfony bundle's
/// `/siteverify` route accepts as JSON or form data. The secret is the
/// server-to-server key that resolves the expected scope server-side; the
/// response is the wire token; `remoteip` is required only when the
/// deployment binds challenges to the client IP.
pub fn verify_endpoint_request(secret: &str, response: &str, remoteip: Option<&str>) -> String {
    let mut body = serde_json::json!({
        "secret": secret,
        "response": response,
    });
    if let Some(ip) = remoteip {
        body["remoteip"] = serde_json::Value::String(ip.to_string());
    }
    body.to_string()
}

/// The off-widget telemetry object: `{}`.
fn empty_telemetry() -> serde_json::Value {
    serde_json::json!({})
}

/// Write `n` as decimal ASCII digits into `buf`, returning the digit
/// count. The u64 spelling of the wasm solver's u32 helper, so counters
/// beyond the u32 chunk ceiling would still render identically.
fn write_decimal(mut n: u64, buf: &mut [u8; 20]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut temp = [0u8; 20];
    let mut j = 0;
    while n > 0 {
        temp[j] = b'0' + (n % 10) as u8;
        n /= 10;
        j += 1;
    }
    for i in 0..j {
        buf[i] = temp[j - 1 - i];
    }
    j
}

/// Count the leading zero bits of a digest, big-endian bit order, the
/// shared notion of all three solvers and the verifier.
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Lowercase hex without a dependency: the digests and proofs are short,
/// and the spelling must match the wire form exactly.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_spelling_matches_the_format_macro() {
        let mut buf = [0u8; 20];
        for value in [0u64, 1, 9, 10, 42, 19_999_999, 20_000_000, u32::MAX as u64] {
            let len = write_decimal(value, &mut buf);
            assert_eq!(
                std::str::from_utf8(&buf[..len]).unwrap(),
                format!("{value}"),
                "the counter spelling must be the plain decimal one"
            );
        }
    }

    #[test]
    fn leading_zero_counting_matches_the_shared_notion() {
        assert_eq!(leading_zero_bits(&[0, 0, 1]), 23);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0]), 8);
        assert_eq!(leading_zero_bits(&[0x0f]), 4);
    }

    #[test]
    fn hex_spelling_is_lowercase_and_double_width() {
        assert_eq!(hex_lower(&[0x00, 0xff, 0x1a]), "00ff1a");
    }

    #[test]
    fn progress_event_reports_the_attempted_count() {
        let mut seen = Vec::new();
        {
            let mut sink = |ev: ProgressEvent| seen.push(ev.attempted);
            let mut opts = SolveOptions {
                on_progress: Some(&mut sink),
                ..SolveOptions::default()
            };
            opts.emit(7);
        }
        assert_eq!(seen, vec![7]);
    }

    #[test]
    fn verify_body_carries_secret_response_and_optional_remoteip() {
        let with_ip = verify_endpoint_request("s", "tok", Some("203.0.113.9"));
        let parsed: serde_json::Value = serde_json::from_str(&with_ip).unwrap();
        assert_eq!(parsed["secret"], "s");
        assert_eq!(parsed["response"], "tok");
        assert_eq!(parsed["remoteip"], "203.0.113.9");
        let without_ip = verify_endpoint_request("s", "tok", None);
        let parsed: serde_json::Value = serde_json::from_str(&without_ip).unwrap();
        assert!(parsed.get("remoteip").is_none());
    }
}
