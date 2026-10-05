//! The CLI-level bench pins: the subcommand runs quickly at a small
//! sample count, prints the documented table shape, exits 2 on usage
//! errors, and the embedded reference table carries its provenance.

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kiwicaptcha-solver"))
        .args(args)
        .output()
        .expect("the CLI binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn bench_subcommand_prints_tables_and_verdicts_quickly() {
    // Three samples over a small rung subset keeps the CLI pin in a
    // few seconds; the library tests cover the whole ladder.
    let started = std::time::Instant::now();
    let (code, stdout, stderr) = run_cli(&[
        "bench",
        "--samples",
        "3",
        "--seed",
        "1234",
        "--rungs",
        "sha16,argon16,rsw",
        "--rsw-t",
        "10000",
    ]);
    let elapsed = started.elapsed();
    assert_eq!(code, 0, "the bench exits zero; stderr: {stderr}");

    // The measured table: header plus one row per requested rung.
    let header = "rung algorithm mean_us p50_us p95_us work_per_s cpu_s_per_1000 notes";
    assert!(stdout.contains(header), "the measurement header prints");
    for rung in ["sha16", "argon16", "rsw"] {
        let row = stdout
            .lines()
            .find(|line| line.starts_with(&format!("{rung} ")))
            .unwrap_or_else(|| panic!("the {rung} row prints"));
        assert!(
            row.split_whitespace().count() >= 7,
            "the {rung} row carries the columns"
        );
    }

    // The reference block names its provenance and as_of date.
    assert!(stdout.contains("reference classes from reference-costs.json"));
    assert!(stdout.contains("as_of"));
    assert!(stdout.contains("public"));

    // The dollar comparison and the doctor-style verdicts.
    assert!(stdout.contains("attacker cost per 1000 solves"));
    assert!(stdout.contains("value-class verdicts"));
    assert!(stdout.contains("insufficient reference data"));
    assert!(stdout.contains("priced"));

    // Deterministic seed echo on stderr.
    assert!(stderr.contains("seed 1234"), "the run names its seed");

    // The pin's quick bound: a small bench must stay well under a
    // minute even on a slow machine.
    assert!(elapsed.as_secs() < 60, "the small bench ran in {elapsed:?}");
}

#[test]
fn bench_usage_errors_exit_two() {
    let (code, _, stderr) = run_cli(&["bench", "--rungs", "no-such-rung"]);
    assert_eq!(
        code, 2,
        "an unknown rung is a usage error; stderr: {stderr}"
    );
    let (code, _, _) = run_cli(&["bench", "--samples", "0"]);
    assert_eq!(code, 2, "a zero sample count is a usage error");
    let (code, _, _) = run_cli(&["bench", "--reference-costs", "/no/such/file.json"]);
    assert_eq!(code, 2, "an unreadable reference table is a usage error");
    let (code, _, _) = run_cli(&["bench", "--rsw-t", "1"]);
    assert_eq!(code, 2, "an out-of-bounds rsw squaring count is refused");
}

#[test]
fn bench_help_documents_the_subcommand() {
    let (code, stdout, _) = run_cli(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("kiwicaptcha-solver bench"));
    assert!(stdout.contains("reference-costs.json"));
}
