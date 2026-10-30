# KiwiCaptcha Adaptive Risk Engine (PHP)

Privacy-first, self-hosted risk scoring for proof-of-work challenge
issuance decisions. Protocol-identical mirror of the cross-language
risk-v1 contract shared with the Rust engine
([`kiwicaptcha-risk`](https://github.com/Bel-Consulting-OU/kiwicaptcha)).

This package is the risk layer used by the standalone Symfony bundle
[`bel-consulting/kiwicaptcha-symfony`](https://github.com/Bel-Consulting-OU/kiwicaptcha-symfony).
It embeds the same canonical Lua scripts and is held to machine-checked
scoring parity with the Rust engine.

## Install

```bash
composer require kiwicaptcha/kiwicaptcha-risk-php
```

Requires `kiwicaptcha/kiwicaptcha-php` `^1.0` and Predis. The package is
distributed as a standalone Git repository (this repo); once registered
on Packagist, Composer resolves it from the Packagist metadata and this
repository's tagged releases.

## What this is not

Not a third-party scoring service. No outbound network calls are made
by the engine itself. No third-party tracking. Adaptive signals are
self-hosted and first-party only.

## License

MIT — see [LICENSE](LICENSE).

Issues and pull requests for the whole product live in the monorepo:
[Bel-Consulting-OU/kiwicaptcha](https://github.com/Bel-Consulting-OU/kiwicaptcha).
