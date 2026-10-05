//! The attacker-cost bench behind `kiwicaptcha-solver bench`.
//!
//! It measures what one solve of every difficulty-ladder rung costs on
//! the adopter's own CPU, using this crate's real solver loops, then
//! sets the numbers beside free, published hardware reference classes
//! and against declared per-value-class abuse values. The ladder
//! parameters are read from the core crate's own profiles
//! ([`kiwicaptcha::ChallengeProfile`]), so the bench can never measure
//! a rung the issuer cannot mint.
//!
//! Honesty rules the whole module:
//!
//! - Wall time is measured single-threaded on the host that runs it;
//!   the table says "this CPU", never "a CPU".
//! - The hardware references are conservative class figures from
//!   public tables, shipped in `reference-costs.json` with provenance
//!   fields the parser requires; argon2id and rsw intentionally carry
//!   no reference class, and their verdicts say
//!   insufficient-reference-data instead of guessing.
//! - The declared abuse values are the table's policy defaults, printed
//!   as such; the runtime doctor owns the real per-scope values.
//! - Instances derive deterministically from a seed, so two runs at
//!   one seed solve byte-identical challenges and find identical
//!   counters; only the timings vary.

use crate::{solve, Challenge, SolveOptions};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kiwicaptcha::challenge::{DEFAULT_RSW_T, MAX_RSW_T, MIN_RSW_T};
use kiwicaptcha::PoWAlgorithm;
use serde::Deserialize;
use std::time::Instant;

/// The shipped reference table, embedded so the binary always carries
/// one valid copy; `--reference-costs PATH` overrides it with a
/// refreshed file.
pub const EMBEDDED_REFERENCE_COSTS: &str = include_str!("../reference-costs.json");

/// The documented test modulus for the rsw rung: the public 2048-bit
/// fixture modulus shared by both language suites
/// (protocol/rsw-identity-v1/fixtures.json). It carries no production
/// trapdoor; the bench only needs a canonical composite to square
/// against, and this one is published test material.
pub const BENCH_RSW_MODULUS_B64: &str = "sL1Mk2YZ4BnznBgWe2YB3uOZ+KFN/VETl1T0H9zuWkP54/nAN8sgPhqozDrRCVQxdJc5IDgkh9EemAGzYjku+zqv2fdryfy5iHbtQEhkHJVt+5f/6yxrZDvDUMhgDRAmLe7rRjEIZC8GqcfcbQyVECgxzNfd3FE+ATeuxc8wKafjUtQ/rvizFBJCo5L0r4U67JDooXVt4yTLtRsoFK3WZBOKIOSZ+E0vZJDt2ddeDSluS/qaqZ5C3dSVeaSyaelX8dGpmovr8xClC+9SKsFnMc+6m9WBo2CsCSpJGk3LZM2847HM5/r2gfmNdN5zRecjEY5MLLEQ/34JinuMtMJpuw==";

/// The default sample count per rung, the number the published tables
/// are quoted at.
pub const DEFAULT_SAMPLES: u32 = 50;

/// The default instance seed: pinned, so two default runs solve the
/// same challenges and their timings stay comparable.
pub const DEFAULT_SEED: u64 = 0x6b77_6b69_7769_3031;

/// One ladder rung the bench measures, its parameters read from the
/// core crate's profiles where a profile exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RungSpec {
    /// The ladder name, the same spelling the pricing ladder uses.
    pub name: &'static str,
    /// The proof-of-work algorithm of the rung.
    pub algorithm: PoWAlgorithm,
    /// Required leading zero bits (the rsw contract pins 1 and never
    /// consults it).
    pub target_bits: u32,
    /// Argon2id memory cost in KiB, 0 for the others.
    pub m_kib: u32,
    /// Argon2id passes, or the rsw squaring count T.
    pub t: u32,
    /// Parallelism, always 1 in the issued contract.
    pub p: u32,
}

/// The bench's ladder: the three sha rungs and three argon rungs with
/// the core crate's own profile parameters, plus the rsw rung at the
/// protocol default T over the documented test modulus.
pub fn ladder() -> Vec<RungSpec> {
    let sha = |name: &'static str, bits: u8| {
        let profile = kiwicaptcha::ChallengeProfile::sha(bits);
        RungSpec {
            name,
            algorithm: profile.algorithm,
            target_bits: u32::from(profile.target_bits),
            m_kib: profile.m_kib,
            t: profile.t,
            p: profile.p,
        }
    };
    let argon = |name: &'static str, profile: kiwicaptcha::ChallengeProfile| RungSpec {
        name,
        algorithm: profile.algorithm,
        target_bits: u32::from(profile.target_bits),
        m_kib: profile.m_kib,
        t: profile.t,
        p: profile.p,
    };
    vec![
        sha("sha16", 16),
        sha("sha18", 18),
        sha("sha20", 20),
        argon("argon16", kiwicaptcha::ChallengeProfile::argon16()),
        argon("argon32", kiwicaptcha::ChallengeProfile::argon32()),
        argon("argon64", kiwicaptcha::ChallengeProfile::argon64()),
        RungSpec {
            name: "rsw",
            algorithm: PoWAlgorithm::Rsw,
            target_bits: 1,
            m_kib: 0,
            t: DEFAULT_RSW_T,
            p: 1,
        },
    ]
}

/// One rung's measured outcome. The counters and work vectors make the
/// determinism checkable: two runs at one seed agree on them exactly,
/// while the timing fields may differ.
#[derive(Debug, Clone)]
pub struct RungMeasurement {
    /// The ladder name of the measured rung.
    pub rung: String,
    /// The algorithm spelling, as printed.
    pub algorithm: String,
    /// How many instances were solved.
    pub samples: u32,
    /// Mean wall time of one solve, in microseconds.
    pub mean_us: f64,
    /// Median wall time of one solve, in microseconds.
    pub p50_us: f64,
    /// 95th-percentile wall time of one solve, in microseconds.
    pub p95_us: f64,
    /// Mean work units per solve: hashes tried, or squarings performed.
    pub mean_work: f64,
    /// Work units per second over the whole rung run.
    pub work_per_second: f64,
    /// The cost of 1000 solves in single-threaded CPU-seconds.
    pub cpu_seconds_per_1000: f64,
    /// The winning counter of each instance, in instance order.
    pub counters: Vec<u64>,
    /// The work spent on each instance, in instance order.
    pub work: Vec<u64>,
    /// The rsw squaring count T, present only for the rsw rung.
    pub rsw_t: Option<u32>,
}

/// Why a bench refused to run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BenchError {
    /// A rung filter name matched nothing on the ladder.
    #[error(
        "unknown rung \"{0}\"; the ladder is sha16, sha18, sha20, argon16, argon32, argon64, rsw"
    )]
    UnknownRung(String),
    /// The rsw squaring count sits outside the protocol bounds.
    #[error("the rsw squaring count {0} sits outside the protocol bounds {1}..={2}")]
    RswTOutOfBounds(u32, u32, u32),
    /// The reference table could not be read or parsed.
    #[error("the reference-costs table is unusable: {0}")]
    BadReferenceCosts(String),
}

/// Solve `samples` instances of one rung and aggregate the timings.
/// The instances derive from `seed` and the rung's own parameters, so
/// the measurements are reproducible in everything but wall time.
pub fn run_rung(spec: &RungSpec, samples: u32, seed: u64) -> Result<RungMeasurement, BenchError> {
    if spec.algorithm == PoWAlgorithm::Rsw && (spec.t < MIN_RSW_T || spec.t > MAX_RSW_T) {
        return Err(BenchError::RswTOutOfBounds(spec.t, MIN_RSW_T, MAX_RSW_T));
    }
    let mut counters = Vec::with_capacity(samples as usize);
    let mut work = Vec::with_capacity(samples as usize);
    let mut durations_us = Vec::with_capacity(samples as usize);
    for index in 0..samples {
        let challenge = bench_challenge(spec, index, seed);
        let mut options = SolveOptions::default();
        let started = Instant::now();
        let solution = solve(&challenge, &mut options).map_err(|err| {
            BenchError::BadReferenceCosts(format!(
                "the rung {0} refused to solve: {err}",
                spec.name
            ))
        })?;
        durations_us.push(started.elapsed().as_secs_f64() * 1_000_000.0);
        counters.push(solution.counter);
        work.push(solution.hashes);
    }
    let total_us: f64 = durations_us.iter().sum();
    let mean_us = total_us / f64::from(samples);
    let total_work: u64 = work.iter().sum();
    let mean_work = total_work as f64 / f64::from(samples);
    let work_per_second = if total_us > 0.0 {
        total_work as f64 / (total_us / 1_000_000.0)
    } else {
        0.0
    };

    Ok(RungMeasurement {
        rung: spec.name.to_string(),
        algorithm: spec.algorithm.as_str().to_string(),
        samples,
        mean_us,
        p50_us: percentile(&durations_us, 0.50),
        p95_us: percentile(&durations_us, 0.95),
        mean_work,
        work_per_second,
        cpu_seconds_per_1000: mean_us * 1000.0 / 1_000_000.0,
        counters,
        work,
        rsw_t: (spec.algorithm == PoWAlgorithm::Rsw).then_some(spec.t),
    })
}

/// The deterministic challenge of one bench instance: nonce, salt and
/// prefix all derive from the seed, the rung name and the instance
/// index, through one splitmix64 stream. Two runs at one seed build
/// byte-identical challenges.
pub fn bench_challenge(spec: &RungSpec, index: u32, seed: u64) -> Challenge {
    let mut rng = SplitMix64(seed ^ (u64::from(index) << 32) ^ fnv_tag(spec.name));
    let nonce_bytes = rng.bytes(32);
    let salt_bytes = rng.bytes(16);
    let salt_b64 = B64.encode(salt_bytes);
    let challenge = format!("kiwicaptcha-bench-{}-{}", spec.name, index);
    Challenge {
        nonce: B64.encode(nonce_bytes),
        challenge: challenge.clone(),
        salt: salt_b64.clone(),
        algorithm: spec.algorithm,
        m_kib: spec.m_kib,
        t: spec.t,
        p: spec.p,
        target_bits: spec.target_bits,
        ttl_secs: 300,
        min_duration_ms: 0,
        prefix: format!("{challenge}|{salt_b64}|"),
        decoy_field: None,
        execution_program: None,
        rsw_modulus: (spec.algorithm == PoWAlgorithm::Rsw)
            .then(|| BENCH_RSW_MODULUS_B64.to_string()),
    }
}

/// The parsed `reference-costs.json` shape. Every provenance field is
/// required by the deserializer, so a table without provenance cannot
/// parse, and the shipped file is pinned by a unit test.
#[derive(Debug, Clone, Deserialize)]
pub struct ReferenceCosts {
    pub format_version: u32,
    pub provenance: ReferenceProvenance,
    pub attacker_rates: Vec<AttackerRate>,
    pub economics: Economics,
    pub value_classes: Vec<ValueClass>,
}

/// The table's provenance block: what the figures are, where they came
/// from, when they were gathered, and how to refresh them.
#[derive(Debug, Clone, Deserialize)]
pub struct ReferenceProvenance {
    pub statement: String,
    pub source_classes: Vec<String>,
    pub as_of: String,
    pub refresh_note: String,
    pub honesty: String,
}

/// One published hardware reference class.
#[derive(Debug, Clone, Deserialize)]
pub struct AttackerRate {
    pub id: String,
    pub hardware_class: String,
    pub algorithm: String,
    pub hashes_per_second: f64,
    /// The rental rate the dollar comparison uses; absent where no
    /// credible public rate card exists for the class.
    pub usd_per_hour: Option<f64>,
    pub provenance: String,
}

/// The native-CPU dollar conversion figure.
#[derive(Debug, Clone, Deserialize)]
pub struct Economics {
    pub cpu_usd_per_core_hour: f64,
    pub provenance: String,
}

/// One value class's declared policy default.
#[derive(Debug, Clone, Deserialize)]
pub struct ValueClass {
    pub class: String,
    pub rung: String,
    pub declared_abuse_value_usd_per_1000: f64,
    pub provenance: String,
}

/// Parse and sanity-check a reference-costs document.
pub fn parse_reference_costs(raw: &str) -> Result<ReferenceCosts, BenchError> {
    let table: ReferenceCosts = serde_json::from_str(raw).map_err(|err| {
        BenchError::BadReferenceCosts(format!("not valid JSON of the expected shape: {err}"))
    })?;
    if table.format_version != 1 {
        return Err(BenchError::BadReferenceCosts(format!(
            "format_version {} is not 1",
            table.format_version
        )));
    }
    if table.provenance.as_of.is_empty()
        || table.provenance.source_classes.is_empty()
        || table.provenance.refresh_note.is_empty()
    {
        return Err(BenchError::BadReferenceCosts(
            "the provenance block is incomplete (as_of, source_classes and refresh_note are required)".into(),
        ));
    }
    for rate in &table.attacker_rates {
        if rate.provenance.is_empty() || rate.hashes_per_second <= 0.0 {
            return Err(BenchError::BadReferenceCosts(format!(
                "the attacker rate {} lacks provenance or a positive rate",
                rate.id
            )));
        }
    }
    for class in &table.value_classes {
        if class.provenance.is_empty() || class.declared_abuse_value_usd_per_1000 < 0.0 {
            return Err(BenchError::BadReferenceCosts(format!(
                "the value class {} lacks provenance or carries a negative abuse value",
                class.class
            )));
        }
    }
    if table.economics.cpu_usd_per_core_hour <= 0.0 || table.economics.provenance.is_empty() {
        return Err(BenchError::BadReferenceCosts(
            "the economics entry lacks provenance or a positive core-hour rate".into(),
        ));
    }
    Ok(table)
}

/// The doctor-style verdict for one value class.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// The cheapest tabled attacker pays more per 1000 solves than the
    /// declared abuse value: the class is priced above it.
    PricedAbove {
        /// The attacker's dollar cost per 1000 solves.
        attacker_usd_per_1000: f64,
        /// The declared abuse value.
        declared_usd_per_1000: f64,
        /// The reference class the figure came from.
        via: String,
    },
    /// The cheapest tabled attacker pays less than the declared abuse
    /// value: the class is priced below it and the adopter should
    /// raise the difficulty or the scope price.
    PricedBelow {
        attacker_usd_per_1000: f64,
        declared_usd_per_1000: f64,
        via: String,
    },
    /// No published reference class covers the rung's algorithm: no
    /// verdict is derived, and the reason says so.
    InsufficientReferenceData { reason: String },
}

/// The cheapest dollar-per-1000-solves attacker the table offers for
/// one algorithm, or None when no rated class covers it.
pub fn cheapest_reference_usd_per_1000(
    table: &ReferenceCosts,
    algorithm: &str,
    mean_work_per_solve: f64,
) -> Option<(f64, String)> {
    let mut best: Option<(f64, String)> = None;
    for rate in &table.attacker_rates {
        if rate.algorithm != algorithm {
            continue;
        }
        let Some(usd_per_hour) = rate.usd_per_hour else {
            continue;
        };
        let seconds = mean_work_per_solve * 1000.0 / rate.hashes_per_second;
        let usd = seconds * usd_per_hour / 3600.0;
        if best.as_ref().is_none_or(|(cost, _)| usd < *cost) {
            best = Some((usd, rate.id.clone()));
        }
    }
    best
}

/// The verdicts for every value class in the table, doctor-style:
/// priced above or below the declared abuse value where the table
/// allows, and insufficient reference data where it does not.
pub fn value_class_verdicts(
    measurements: &[RungMeasurement],
    table: &ReferenceCosts,
) -> Vec<(String, String, Verdict)> {
    table
        .value_classes
        .iter()
        .map(|class| {
            let verdict = match measurements.iter().find(|m| m.rung == class.rung) {
                None => Verdict::InsufficientReferenceData {
                    reason: format!("the rung {} was not measured in this run", class.rung),
                },
                Some(m) => {
                    match cheapest_reference_usd_per_1000(table, &m.algorithm, m.mean_work) {
                        None => Verdict::InsufficientReferenceData {
                            reason: if m.algorithm == "rsw" {
                                "rsw squaring is inherently sequential; no hardware class in the table buys a speedup".to_string()
                            } else {
                                format!(
                                    "no published class figure for {} in the table; the native CPU estimate is the only anchor",
                                    m.algorithm
                                )
                            },
                        },
                        Some((usd, via)) => {
                            if usd >= class.declared_abuse_value_usd_per_1000 {
                                Verdict::PricedAbove {
                                    attacker_usd_per_1000: usd,
                                    declared_usd_per_1000: class.declared_abuse_value_usd_per_1000,
                                    via,
                                }
                            } else {
                                Verdict::PricedBelow {
                                    attacker_usd_per_1000: usd,
                                    declared_usd_per_1000: class.declared_abuse_value_usd_per_1000,
                                    via,
                                }
                            }
                        }
                    }
                }
            };
            (class.class.clone(), class.rung.clone(), verdict)
        })
        .collect()
}

/// The measured table: one row per rung, times in microseconds.
pub fn render_measurements(measurements: &[RungMeasurement]) -> String {
    let mut out = String::new();
    out.push_str("rung algorithm mean_us p50_us p95_us work_per_s cpu_s_per_1000 notes\n");
    for m in measurements {
        let notes = match m.rsw_t {
            Some(t) => format!("T={t} squarings over the documented test modulus"),
            None if m.mean_work < 4.0 => {
                "ladder target bits; a couple of work units per solve".to_string()
            }
            None => String::new(),
        };
        out.push_str(&format!(
            "{} {} {:.0} {:.0} {:.0} {:.3e} {:.3} {}\n",
            m.rung,
            m.algorithm,
            m.mean_us,
            m.p50_us,
            m.p95_us,
            m.work_per_second,
            m.cpu_seconds_per_1000,
            notes
        ));
    }
    out
}

/// The hardware reference block, quoting the table's own provenance
/// strings so the output never hides where the numbers came from.
pub fn render_references(table: &ReferenceCosts) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "reference classes from reference-costs.json (as_of {}; conservative public-class figures):\n",
        table.provenance.as_of
    ));
    for rate in &table.attacker_rates {
        let rate_line = match rate.usd_per_hour {
            Some(usd) => format!("${usd:.2}/h"),
            None => "no credible public rate card".to_string(),
        };
        out.push_str(&format!(
            "  {} {} {} {:.3e} h/s ({rate_line}) — {}\n",
            rate.id, rate.hardware_class, rate.algorithm, rate.hashes_per_second, rate.provenance
        ));
    }
    out.push_str(&format!(
        "  this CPU dollar conversion: ${:.4} per core-hour — {}\n",
        table.economics.cpu_usd_per_core_hour, table.economics.provenance
    ));
    out
}

/// The dollar comparison: every measured rung's cost per 1000 solves on
/// this CPU, beside the cheapest tabled reference attacker.
pub fn render_dollars(measurements: &[RungMeasurement], table: &ReferenceCosts) -> String {
    let mut out = String::new();
    out.push_str("attacker cost per 1000 solves:\n");
    out.push_str("rung this_cpu_usd best_reference_usd via\n");
    for m in measurements {
        let native = m.cpu_seconds_per_1000 * table.economics.cpu_usd_per_core_hour / 3600.0;
        let reference = cheapest_reference_usd_per_1000(table, &m.algorithm, m.mean_work);
        let (ref_usd, via) = match reference {
            Some((usd, id)) => (format!("{usd:.3e}"), id),
            None => (
                "(no published class figure)".to_string(),
                "insufficient reference data".to_string(),
            ),
        };
        out.push_str(&format!("{} {:.3e} {ref_usd} {via}\n", m.rung, native));
    }
    out
}

/// The value-class verdict block, including the declared-abuse-value
/// caveat that the doctor owns the real per-scope numbers.
pub fn render_verdicts(verdicts: &[(String, String, Verdict)]) -> String {
    let mut out = String::new();
    out.push_str("value-class verdicts (declared abuse values are the table's policy defaults; the doctor owns the per-scope values):\n");
    for (class, rung, verdict) in verdicts {
        let line = match verdict {
            Verdict::PricedAbove {
                attacker_usd_per_1000,
                declared_usd_per_1000,
                via,
            } => format!(
                "priced above the declared abuse value (attacker ${attacker_usd_per_1000:.3e} vs declared ${declared_usd_per_1000} per 1000, via {via})"
            ),
            Verdict::PricedBelow {
                attacker_usd_per_1000,
                declared_usd_per_1000,
                via,
            } => format!(
                "priced below the declared abuse value (attacker ${attacker_usd_per_1000:.3e} vs declared ${declared_usd_per_1000} per 1000, via {via}); raise the difficulty or the scope price"
            ),
            Verdict::InsufficientReferenceData { reason } => {
                format!("insufficient reference data ({reason})")
            }
        };
        out.push_str(&format!("  {class} ({rung}): {line}\n"));
    }
    out
}

/// The nearest-rank percentile of a sample vector.
fn percentile(samples_us: &[f64], fraction: f64) -> f64 {
    let mut sorted = samples_us.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let rank = ((fraction * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// A tiny splitmix64 stream: deterministic, dependency-free, and enough
/// randomness for bench instances that must be reproducible.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

/// A stable per-name tag mixed into every instance seed, so two rungs
/// at one index never solve the same challenge.
fn fnv_tag(name: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn ladder_parameters_come_from_the_core_profiles() {
        let ladder = ladder();
        let argon16 = ladder
            .iter()
            .find(|r| r.name == "argon16")
            .expect("argon16 is on the ladder");
        let profile = kiwicaptcha::ChallengeProfile::argon16();
        assert_eq!(argon16.m_kib, profile.m_kib);
        assert_eq!(argon16.t, profile.t);
        assert_eq!(argon16.p, profile.p);
        assert_eq!(u32::from(profile.target_bits), argon16.target_bits);
        assert_eq!(
            ladder.iter().find(|r| r.name == "argon64").unwrap().m_kib,
            kiwicaptcha::ChallengeProfile::argon64().m_kib
        );
        assert_eq!(
            ladder
                .iter()
                .find(|r| r.name == "sha20")
                .unwrap()
                .target_bits,
            20
        );
        let rsw = ladder.iter().find(|r| r.name == "rsw").unwrap();
        assert_eq!(rsw.t, DEFAULT_RSW_T);
        assert_eq!(ladder.len(), 7);
    }

    #[test]
    fn bench_instances_are_deterministic_per_seed() {
        let spec = ladder().into_iter().find(|r| r.name == "sha16").unwrap();
        let a = bench_challenge(&spec, 0, 42);
        let b = bench_challenge(&spec, 0, 42);
        assert_eq!(a, b, "one seed builds byte-identical challenges");
        let c = bench_challenge(&spec, 0, 43);
        assert_ne!(a.nonce, c.nonce, "another seed builds other instances");
        let d = bench_challenge(&spec, 1, 42);
        assert_ne!(a.nonce, d.nonce, "another index builds other instances");
    }

    #[test]
    fn the_bench_runs_quickly_with_three_samples() {
        let mut specs = ladder();
        // The rsw rung runs at the protocol minimum T so the unoptimized
        // test build stays quick; the squaring loop is linear in T and
        // the default is covered by the CLI pin.
        for spec in &mut specs {
            if spec.algorithm == PoWAlgorithm::Rsw {
                spec.t = MIN_RSW_T;
            }
        }
        for spec in specs {
            let measurement = run_rung(&spec, 3, DEFAULT_SEED).expect("the rung solves");
            assert_eq!(measurement.samples, 3);
            assert_eq!(measurement.counters.len(), 3);
            assert!(measurement.mean_us > 0.0);
            assert!(measurement.p95_us >= measurement.p50_us);
            assert!(measurement.work.iter().all(|w| *w > 0));
        }
    }

    #[test]
    fn solve_work_is_deterministic_on_a_fixed_seed() {
        let spec = ladder().into_iter().find(|r| r.name == "sha16").unwrap();
        let first = run_rung(&spec, 3, 7).expect("the first run solves");
        let second = run_rung(&spec, 3, 7).expect("the second run solves");
        assert_eq!(first.counters, second.counters, "the counters pin");
        assert_eq!(first.work, second.work, "the work pins");
    }

    #[test]
    fn the_shipped_reference_table_is_valid_json_with_provenance() {
        let table =
            parse_reference_costs(EMBEDDED_REFERENCE_COSTS).expect("the shipped table parses");
        assert_eq!(table.format_version, 1);
        assert!(!table.provenance.as_of.is_empty());
        assert!(!table.provenance.source_classes.is_empty());
        assert!(!table.provenance.refresh_note.is_empty());
        assert!(!table.provenance.honesty.is_empty());
        for rate in &table.attacker_rates {
            assert!(!rate.provenance.is_empty());
            assert!(rate.hashes_per_second > 0.0);
        }
        assert!(!table.economics.provenance.is_empty());
        for class in &table.value_classes {
            assert!(!class.provenance.is_empty());
            assert!(ladder().iter().any(|r| r.name == class.rung));
        }
    }

    #[test]
    fn a_reference_table_without_provenance_is_refused() {
        let raw = r#"{
            "format_version": 1,
            "provenance": {"statement": "s", "source_classes": [], "as_of": "", "refresh_note": "", "honesty": "h"},
            "attacker_rates": [],
            "economics": {"cpu_usd_per_core_hour": 0.01, "provenance": ""},
            "value_classes": []
        }"#;
        assert!(parse_reference_costs(raw).is_err());
        assert!(parse_reference_costs("not json").is_err());
    }

    #[test]
    fn the_measurement_table_shape_parses() {
        let specs: Vec<RungSpec> = ladder()
            .into_iter()
            .filter(|r| r.name == "sha16" || r.name == "rsw")
            .collect();
        let rsw = specs.iter().position(|r| r.name == "rsw").unwrap();
        let mut specs = specs;
        specs[rsw].t = MIN_RSW_T;
        let measurements: Vec<RungMeasurement> = specs
            .iter()
            .map(|spec| run_rung(spec, 1, DEFAULT_SEED).expect("the rung solves"))
            .collect();
        let table = render_measurements(&measurements);
        let mut lines = table.lines();
        let header: Vec<&str> = lines
            .next()
            .expect("the header exists")
            .split_whitespace()
            .collect();
        assert_eq!(
            header,
            vec![
                "rung",
                "algorithm",
                "mean_us",
                "p50_us",
                "p95_us",
                "work_per_s",
                "cpu_s_per_1000",
                "notes"
            ]
        );
        for line in lines {
            let columns: Vec<&str> = line.split_whitespace().collect();
            assert!(
                columns.len() >= 7,
                "every row carries the seven columns: {line}"
            );
            assert!(f64::from_str(columns[2]).is_ok_and(|v| v > 0.0));
        }
    }

    #[test]
    fn verdicts_compare_and_refuse_honestly() {
        let table = parse_reference_costs(EMBEDDED_REFERENCE_COSTS).expect("the table parses");
        // A sha16 solve at the ladder difficulty: roughly 2^16 hashes.
        let sha16 = RungMeasurement {
            rung: "sha16".into(),
            algorithm: "sha256".into(),
            samples: 1,
            mean_us: 30_000.0,
            p50_us: 30_000.0,
            p95_us: 30_000.0,
            mean_work: 65_536.0,
            work_per_second: 2.0e6,
            cpu_seconds_per_1000: 30.0,
            counters: vec![1],
            work: vec![65_536],
            rsw_t: None,
        };
        let argon64 = RungMeasurement {
            rung: "argon64".into(),
            algorithm: "argon2id".into(),
            samples: 1,
            mean_us: 200_000.0,
            p50_us: 200_000.0,
            p95_us: 200_000.0,
            mean_work: 2.0,
            work_per_second: 10.0,
            cpu_seconds_per_1000: 200.0,
            counters: vec![1],
            work: vec![2],
            rsw_t: None,
        };
        let verdicts = value_class_verdicts(&[sha16, argon64], &table);
        let low = verdicts.iter().find(|(c, _, _)| c == "low").unwrap();
        assert!(matches!(low.2, Verdict::PricedBelow { .. }));
        let critical = verdicts.iter().find(|(c, _, _)| c == "critical").unwrap();
        assert!(
            matches!(critical.2, Verdict::InsufficientReferenceData { .. }),
            "argon2id carries no reference class and refuses a verdict"
        );
        // A hypothetical class priced above a tiny declared value.
        let mut cheap = table.clone();
        cheap.value_classes.truncate(1);
        cheap.value_classes[0].declared_abuse_value_usd_per_1000 = 1e-12;
        let above = value_class_verdicts(
            &[RungMeasurement {
                rung: "sha16".into(),
                algorithm: "sha256".into(),
                samples: 1,
                mean_us: 1.0,
                p50_us: 1.0,
                p95_us: 1.0,
                mean_work: 65_536.0,
                work_per_second: 1e6,
                cpu_seconds_per_1000: 1.0,
                counters: vec![1],
                work: vec![65_536],
                rsw_t: None,
            }],
            &cheap,
        );
        assert!(matches!(above[0].2, Verdict::PricedAbove { .. }));
    }

    #[test]
    fn out_of_bounds_rsw_t_is_refused() {
        let mut spec = ladder().into_iter().find(|r| r.name == "rsw").unwrap();
        spec.t = MIN_RSW_T - 1;
        assert!(run_rung(&spec, 1, 1).is_err());
        spec.t = MAX_RSW_T + 1;
        assert!(run_rung(&spec, 1, 1).is_err());
    }
}
