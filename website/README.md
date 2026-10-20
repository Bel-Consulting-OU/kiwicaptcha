# KiwiCaptcha product website

The ten-page product website from `KiwiCaptcha_Website.pdf` (edition 4),
implemented statically: **Zola generates the HTML, an Axum binary serves
it, and no page ships JavaScript.** The identity comes from the
repository's own masters (`packages/kiwicaptcha/design/IDENTITY.md`,
`packages/kiwicaptcha/resources/*.svg`), so the site and the product
render the same artwork.

## Pages

| Path | Job |
| --- | --- |
| `/` | Home: mechanism, control, widget, privacy, economics, start, faq, identity |
| `/how-it-works/` | Sequence, algorithms, gates, single use, binding, factors, extensions |
| `/integration/` | Layer roles, Symfony, cores, SDKs, browser, native, sidecar, migration, status |
| `/security/` | Model, profiles, carriers, operation, outcomes, economics, resources |
| `/privacy/` | First-party defaults, evidence, strict posture, retention, claims |
| `/docs/` | Operator documentation map into the repository guides |
| `/playground/` | Widget: ten states, widths, text scales, languages, recovery — all static |
| `/brand/` | Identity board, masters, palette with measured contrast, type, downloads |
| `/faq/` | The deployment-changing questions with grounded answers |
| `/reference/` | Current edition and the dated prior-edition reference |

Every section carries **Source notes** linking the repository paths the
content is grounded in. The "Copy example" affordance is JavaScript-free:
the example sits in a readonly field and the label focuses it, so copying
is select-all plus the platform copy key.

## Build

```sh
website/build.sh          # assemble assets, zola build, run the site checks
```

`build.sh` copies the canonical fonts, brand masters, widget stylesheet
and design PDFs into `website/zola/static/` (generated, not committed),
runs `zola build`, then `tools/ci/website-site-check.py` over the output.
The checks fail the build on any script tag, inline event attribute,
`javascript:` URI, external resource host, or dangling local reference.

## Serve

```sh
cargo run -p kiwicaptcha-website            # serves website/zola/public on 127.0.0.1:8090
KIWI_WEBSITE_ROOT=/tmp/site KIWI_WEBSITE_BIND=0.0.0.0:8080 cargo run -p kiwicaptcha-website
```

The server stamps a script-free Content-Security-Policy
(`script-src 'none'`, `default-src 'none'`) plus `nosniff`, `DENY`
framing and a strict-origin referrer policy on every response, falls
back to the built 404 page for unknown paths, and exposes `/healthz`.
Tests: `cargo test -p kiwicaptcha-website`.

## Layout

```
website/
  build.sh              assemble + zola build + site checks
  zola/                 the Zola project (config, templates, content, static)
  server/               the Axum static server (workspace member)
```

`website/zola/static/{fonts,brand,pdf,css/widget.css}` are build-time
copies of repository files. The committed sources of truth are
`packages/kiwicaptcha/design/fonts/`, `packages/kiwicaptcha/resources/`,
`design/lettering.json` and the two root PDFs.

## Design source

The pages implement `KiwiCaptcha_Website.pdf` (edition 4, 12 October
2026) without design changes: Paper `#F3F5EF` surface, Ink `#08110C`
text, Alegreya Sans display/reading, IBM Plex Mono metadata, hairline
structure, quiet mint panels, banded contrast tables and the ten-state
widget language from `design/IDENTITY.md`.
