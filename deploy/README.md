# KiwiCaptcha reference deployment (Docker + Valkey)

A self-contained reference deployment of the PHP core: a small
`php -S` request surface (`GET /healthz`, `POST /challenge`,
`POST /verify`) backed by the REAL core storage
(`KiwiCaptcha\Storage\RedisStorage` on Valkey/Redis, the same backend
the Symfony bundle wires from its `redis_dsn` setting) and the REAL
core issuer and verifier. No file in `deploy/` carries a fixed secret,
a test credential or a trapdoor value: every setting comes from the
environment. The production deployment surface is the published
Symfony bundle; this image exists so the exact core library code paths
(issuance, verification, atomic one-shot storage) are exercised as a
self-contained unit.

The image and the compose stack are exercised end to end in CI by the
`Docker reference deployment e2e` job in `.github/workflows/ci.yml`:
build, `docker compose up`, `/healthz` until 200, issue a challenge,
solve the SHA-256 proof inside the container (the `deploy/app/solve.php`
helper, which replicates the canonical solver loop of the browser
worker), verify the token, assert the replay rejection of the same
token, restart the captcha container, and issue/solve/verify again
against the persistent Valkey volume.

## Build and run

    docker build -f deploy/Dockerfile -t kiwicaptcha/reference-deployment .

Or through compose, which builds the image for you:

    cp deploy/.env.example deploy/.env
    # fill in KIWI_SECRET_KEY: openssl rand -hex 32
    docker compose -f deploy/docker-compose.yml up -d

Then:

    curl http://localhost:8080/healthz
    curl -X POST -H 'Content-Type: application/json' \
      -d '{"scope":"login"}' http://localhost:8080/challenge
    # solve the challenge (browser worker loop), then:
    curl -X POST -H 'Content-Type: application/json' \
      -d '{"token":"<solution token>","scope":"login"}' \
      http://localhost:8080/verify

The challenge document is the canonical widget wire shape: `nonce`,
`challenge`, `salt`, `algorithm`, `mKib`, `t`, `p`, `targetBits`,
`ttlSecs`, `minDurationMs`, `prefix`, plus `execution_program` when
the execution key is set and `rsw_modulus` for rsw challenges. The
challenge POST accepts `scope`, `request_binding` and `algorithm`;
the last is compatibility metadata only (the widget advertises the
profile it expects), and the issued `algorithm` always equals the
`KIWI_ALGORITHM` profile. The verify answer is
`{"ok":true,"code":""}` for a fresh valid redemption and
`{"ok":false,"code":"<error>"}` for every failure; the verify POST
accepts `token`, `scope` and `request_binding`, where the presented
`request_binding` is the expected transaction binding of the
redemption (a challenge minted bound to a transaction redeems only
under that binding, and a mismatch is refused without consuming the
record, so the correct redemption still succeeds afterwards); a second
POST with the same token answers `code: "already_consumed"` because
the core storage consumed the record. `/healthz` answers 200 only
after a real store round trip (write, read, delete-if-pending) and
503 with `{"ok":false,"code":"storage_probe_failed"}` otherwise (the
backend detail of a failed probe stays in the server log); the
container HEALTHCHECK requires the 200.

## Environment variables

Required:

- `KIWI_SECRET_KEY` — the challenge-signing secret; at least 32 bytes
  of random data (`openssl rand -hex 32`). Never commit a real value.
- `KC_REDIS_URL` — the challenge-store connection. The compose file
  sets it to the bundled Valkey service
  (`redis://valkey:6379`); a standalone deployment points it at any
  Redis-compatible server (e.g. `redis://127.0.0.1:6379`).

Optional:

- `KIWI_EXECUTION_KEY` — at least 32 bytes when set. When set, every
  issued challenge arms the browser-execution dimension (the core
  `execution_key` of the bundle); unset stays execution-unarmed.
- `KIWI_RSW_MODULUS_N` / `KIWI_RSW_LAMBDA` — the rsw time-lock
  trapdoor pair. Both must be configured together; setting exactly one
  refuses startup with
  `KIWI_RSW_MODULUS_N and KIWI_RSW_LAMBDA must be configured
  together`. When both are set, `KIWI_ALGORITHM=rsw` is the selectable
  issuance profile; the modulus is public, lambda is the secret
  trapdoor.
- `KIWI_ALGORITHM` — selects the issuance profile (`sha256`,
  `argon2id` or `rsw`; default `sha256`). The browser may advertise
  the profile it expects in the challenge request, but request input
  never changes the server-selected algorithm: the issued challenge
  always carries the configured profile, and a deployment stays on its
  configured algorithm regardless of what a caller asks for.
- `KIWI_SHA_TARGET_BITS` — SHA-256 difficulty, 1..20 (default 18, the
  bundle baseline; the CI e2e runs 8 for a low-cost solve).
- `KIWI_ARGON2_TARGET_BITS` — Argon2id difficulty, 1..10 (default 8).
- `KIWI_ARGON2_M_KIB` — the Argon2id memory envelope in KiB, 8..65536
  (default 65536, the documented argon64 rung).
- `KIWI_TTL_SECS` — challenge lifetime in seconds, 1..300 (default
  120).
- `KIWI_MIN_DURATION_MS` — optional server-measured solve-time floor in
  ms; unset derives the floor from the difficulty (the bundle
  behavior), 0 disables it.
- `KIWI_RSW_T` — the rsw sequential-squaring cost, 10,000..300,000
  (default 75,000).

## Security note

This reference deployment runs `php -S`, the single-threaded PHP
development server: it is a reference and a CI target, NOT a
production serving surface. Production deployments use the Symfony
bundle (`bel-consulting/kiwicaptcha-symfony`), which brings the
framework-grade HTTP stack, the hardened controllers and the
documented deployment model. `KIWI_SECRET_KEY` and
`KIWI_EXECUTION_KEY` are credentials: keep them out of version
control, rotate them like any signing key, and treat
`KIWI_RSW_LAMBDA` as the trapdoor secret it is.
