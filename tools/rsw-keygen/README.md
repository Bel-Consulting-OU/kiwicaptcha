# rsw-keygen

First-party offline generator, checker and fingerprint tool for the
KiwiCaptcha rsw trapdoor pair. The rsw algorithm is a sequential
time-lock over a 2048-bit composite modulus `n`; the server verifies
instantly with the secret `lambda = lcm(p-1, q-1)`. KiwiCaptcha
configuration validation can prove the shape of `n` and `lambda`, but
the assurance that `n` was securely constructed from two large
unpredictable primes lives here: operators MUST produce every deployed
pair with this tool (or a generator it validates), record the modulus
fingerprint, and keep `lambda` and the primes off the servers.

## Build

```sh
cargo build --release
```

The crate builds standalone (it is excluded from the workspace, like
the wasm embed tool) and depends on the shipped `kiwicaptcha` crate by
path, so its self-test exercises exactly the trapdoor math of the
deployed core.

## Generate a pair

```sh
rsw-keygen              # or rsw-keygen --diagnostic
```

Before anything is emitted the fresh pair must pass the shipped decode
and validation of the core (shape, small factors, probable-prime
rejection, the Euler self-test) and the sequential-squaring self-test:
for four deterministic challenge-derived bases the shipped trapdoor
expectation must equal the client-style sequential solve at T = 17,
1000 and 10007, plus T = 250000 for the first base. A mismatch aborts
with exit 1 and emits nothing.

Output is one value per line, all lowercase:

```
rsw_modulus_n_hex=...        # n, exactly 512 hex chars (256 bytes)
rsw_modulus_n_base64=...     # the same n, canonical standard base64 (the config value)
rsw_lambda_hex=...           # lambda, minimal hex without leading zeros
rsw_lambda_base64=...        # lambda as canonical standard base64 of its minimal bytes
rsw_modulus_n_sha256=...     # sha256 of the canonical 256-byte n, 64 hex chars
```

`--diagnostic` appends `rsw_p_hex` and `rsw_q_hex`, the two 1024-bit
primes (256 hex chars each). Never store these next to the deployed
configuration; their purpose is a one-time record for key escrow or
destruction proof. Without the flag the primes never leave the
process.

The hex and base64 lines are two encodings of the same bytes. Deploy
`rsw_modulus_n_base64` and `rsw_lambda_base64` as `rsw_modulus_n` and
`rsw_lambda`; record `rsw_modulus_n_sha256` as the identity of the
deployed modulus, and verify it later with the fingerprint mode.

## Check a pair

```sh
rsw-keygen --check N_HEX LAMBDA_HEX
```

Runs the same rule list as the configuration validators of the PHP and
Rust cores, reusing the shipped validation primitives, and prints
every applicable rejection:

- `n` is not exactly 256 bytes, or its top bit is clear (not exactly
  2048 bits),
- `n` is even,
- `n` is divisible by a small prime at or below 1000,
- `n` is a probable prime (a genuine modulus is composite),
- `lambda` is odd, larger than 256 bytes, or empty,
- `lambda` fails the Euler self-test `base^lambda == 1 (mod n)` for
  the bases 2, 3 and 5, which is the exact condition for the trapdoor
  shortcut to match sequential squaring at every cost T.

Exit 0 with an OK line and the modulus fingerprint means the pair
passes the shipped validation everywhere. Exit 1 lists the reasons.

## Fingerprint a deployed modulus

```sh
rsw-keygen --fingerprint N_HEX
```

Prints the sha256 of the canonical 256-byte `n` (64 lowercase hex
chars). Use it to confirm that a running deployment holds the recorded
modulus.

## Operational rules

- Generate pairs on an offline, trusted machine and deploy the pair
  through a secrets channel.
- `lambda` is the trapdoor: it must never ride a challenge, a log, a
  client bundle, or any record. Only `n` is public.
- `p` and `q` must never be stored in the repository, the deployment,
  or any artifact except the explicit `--diagnostic` output of a
  generation run.
- The configuration boundary rejects weak material (see `--check`),
  but no validator can prove that `n` came from two large primes:
  provenance is the tool. Record `rsw_modulus_n_sha256` at deploy
  time so a later audit can tie the running modulus to a keygen run.

## Test

```sh
cargo test
```

The suite covers the generator invariants (exact 2048-bit product,
minimal lambda hex, fingerprints), the self-test, the CLI shapes
(including the diagnostic gate around the primes) and the `--check`
rule list against committed fixture material, including the shared
2048-bit probable-prime constant of the core suites.
