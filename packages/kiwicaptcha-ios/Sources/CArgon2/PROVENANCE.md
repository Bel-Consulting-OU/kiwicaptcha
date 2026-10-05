# CArgon2 provenance

The sources in this directory are the unmodified reference Argon2 C
implementation, phc-winner-argon2, release/tag `20190702`, downloaded
from the upstream repository:
https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz

Vendored files: `argon2.c`, `core.c`, `core.h`, `encoding.c`,
`encoding.h`, `ref.c`, `thread.h`,
`blake2/blake2b.c`, `blake2/blake2.h`, `blake2/blake2-impl.h`,
`blake2/blamka-round-ref.h`, `blake2/blamka-round-opt.h`, and
`include/argon2.h`, plus the upstream `LICENSE` (Apache-2.0 / CC0
1.0, at your option).

Not vendored: `opt.c` (the SSE4.1 fill-segment variant; the portable
`ref.c` path is compiled), `thread.c` (the build defines
`ARGON2_NO_THREADS`, the protocol profile is single-lane), `genkat.c`
and `genkat.h` (the known-answer-test generator: it carries its own
`main` and compiles in only under the GENKAT define this package
never sets), `run.c`, `bench.c` and `test.c` (the CLI, benchmark and
test mains).

The correctness contract lives in the KiwiCaptcha suites: the
RFC 9106 section 5.3 Argon2id tag and a PHP-libsodium cross-checked
derivation pin every vendored file to the published behavior.
