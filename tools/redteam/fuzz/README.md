# tools/redteam/fuzz — coverage-guided fuzz leg (D4.1)

The gate's `coverage-fuzz` row. Two layers:

1. **cargo-fuzz targets** (`fuzz_targets/token_parse.rs`,
   `fuzz_targets/record_parse.rs`) — the real libFuzzer targets over
   `SolutionToken::decode` and `ChallengeRecord` deserialization.
   They build only where `libfuzzer-sys` can be fetched (first build
   needs network). `run.sh` prefers them.

2. **The offline substitute** (`src/coverage_fuzz.rs`) — the same
   no-panic property over the same parse surfaces, with a coverage
   feedback loop over the observed parse-outcome signatures. It has
   no libfuzzer dependency and always builds from the local cargo
   cache. `run.sh` falls back to it when cargo-fuzz cannot build.

Scale honesty: both paths state the measured run count. The
specification's 24 h coverage-guided budget is a CI job; a local run
is GREEN at the scale it actually executed and never claims the 24 h
envelope.

Run: `sh tools/redteam/fuzz/run.sh 10000`
