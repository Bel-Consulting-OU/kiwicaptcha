# KiwiCaptcha logo and UI refinement

Open preview.html for the interactive preview. It is self-contained and works offline.
Choose light/dark themes, widget states, 240–352 px widths, six languages, and 100%/200% text sizes.
Preview states are simulated; no challenge or token is issued.

The source/ directory contains all 29 changed files, with their repository paths preserved.
The canonical logo is source/packages/kiwicaptcha/resources/kiwi-mark.svg.
The canonical widget skin is source/packages/kiwicaptcha-wasm/assets/widget.css.

## Apply to the existing repository

From the repository root, run:

```sh
git am /path/to/KiwiCaptcha-Spiral-Lock-UI.patch
```

Alternatively, copy source/ into the repository root, preserving its paths.
The patch includes the preview PNG and all source changes. The Git bundle preserves the complete commit.

Base commit: 6532cc7a88d2e25592159ba558cef31b373415d7
Change commit: d5a94ffb09ecb537bf636c48a1e27ac13e7f976d
Branch: codex/spiral-lock-ui-refinement

## Changes

- Raised, narrowed shackle; lower spiral body; more open center. Two monochrome strokes on a 64x64 grid.
- Quiet widget card, readable typography, responsive spacing, coherent light/dark themes, clear progress and recovery controls.
- Correct framework SVG geometry, widget-local status announcements, and explicit theme overrides.
- Canonical SVG assets and development-only synchronization script for Rust, TypeScript, Symfony, compatibility loaders, and packaged mirrors.
- Fixed the obsolete bird-logo comment. The shield remains a secondary status emblem.
- Corrected an existing provider reset test race, reproduced on the unchanged base commit.

## Validation

90 browser tests passed in Chromium (37 widget/accessibility/responsive tests and 53 compatibility/theme tests).
21 client-core tests and the client build passed.
2 Rust logo tests passed in isolation. The complete pinned Rust workspace was not run locally.
Asset parity, brand synchronization, syntax checks and patch verification passed.
No physical mobile-device release gate was added.

The changes are committed locally; GitHub publishing was blocked by a repository-write permission error.
