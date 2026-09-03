# KiwiCaptcha reference deployment (Docker + Valkey)

A self-contained stand-in for the production deployment while the
public package chain is published: the PHP core plus the quick-start
server, backed by Valkey with persistence and a healthcheck.

- `docker compose up -d` then POST to `http://localhost:8080/challenge`
  (the fixture route set mirrors the bundle controller's semantics).
- The production Symfony deployment follows the published
  `bel-consulting/kiwicaptcha-symfony` recipe once Packagist
  publication lands; this bundle keeps the same storage, PoW,
  execution and replay code paths.
