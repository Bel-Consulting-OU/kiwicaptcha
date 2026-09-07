//! Regenerates the two machine-written worker artifacts of the browser
//! asset set from each other:
//!
//!   1. `assets/kiwicaptcha-wasm.js` (the wasm glue): its `workerSource`
//!      section — `window.__kiwiCaptchaWasm.workerSource`, the JSON string
//!      literal the inline tier reads to build its Blob worker — is
//!      regenerated from the worker solver source;
//!   2. `assets/kiwi-worker.js` (the release worker asset): its leading
//!      machine-written span — the `var window = self;` prelude followed by
//!      the complete glue text — is regenerated from `assets/kiwicaptcha-wasm.js`,
//!      so the worker asset carries the wasm runtime with it and every
//!      worker solve (SHA and Argon/RSW alike) has wasm at boot in every
//!      tier: inline mode (Blob worker: the page glue runs before this
//!      asset's source tail), files mode (the versioned worker.<hash>.js
//!      asset the driver preflight-verifies), and the legacy explicit
//!      data-kiwi-worker-src path.
//!
//! The worker solver source — the canonical, hand-edited part of
//! `assets/kiwi-worker.js` — is the file's tail after the
//! KIWI_WORKER_GLUE_END marker line. It is never rewritten by this tool,
//! and it is byte-identical to the glue's embedded `workerSource` copy
//! (the two can never drift by hand: regeneration derives both from the
//! same source).
//!
//! The tool is part of the pure-Rust build pipeline — build.sh invokes it
//! (--locked) after the glue is generated, so both artifacts are written
//! from a fresh `kiwicaptcha-wasm.js`:
//!
//! ```sh
//! cargo run --locked --manifest-path tools/embed-worker/Cargo.toml --            # regenerate
//! cargo run --locked --manifest-path tools/embed-worker/Cargo.toml -- --check    # exit 1 on drift (CI)
//! ```
//!
//! Both generated sections are delimited by explicit sentinel comments
//! (KIWI_WORKER_SRC_BEGIN … KIWI_WORKER_SRC_END in the glue;
//! KIWI_WORKER_GLUE_BEGIN … KIWI_WORKER_GLUE_END in the worker asset) —
//! each whole span is replaced wholesale, so no JavaScript token parsing
//! can ever misfire. The embedded values are JSON string literals (quotes
//! and backslashes escaped), so the executed bytes are identical to the
//! standalone source. A closing-script-tag sequence in the worker source
//! is rejected with an ASCII case-insensitive scan: the glue (which
//! embeds that source) is inlined into pages by the renderers, so
//! `</script>` in any casing would terminate the page's script element.

use std::{env, fs, path::PathBuf, process};

/// Sentinel comments delimiting the machine-written section in
/// `kiwicaptcha-wasm.js` (the `workerSource` literal). Both are unique in
/// the glue.
const BEGIN: &str = "// KIWI_WORKER_SRC_BEGIN";
const END: &str = "// KIWI_WORKER_SRC_END";

/// Sentinel comments delimiting the machine-written span in
/// `assets/kiwi-worker.js`: from the KIWI_WORKER_GLUE_BEGIN marker through
/// the KIWI_WORKER_GLUE_END marker line the whole span is generated (the
/// prelude plus the full glue text). The canonical worker solver source —
/// the hand-edited tail of the file — follows the KIWI_WORKER_GLUE_END
/// marker line and is never rewritten here.
const WORKER_GLUE_BEGIN: &str = "// KIWI_WORKER_GLUE_BEGIN";
const WORKER_GLUE_END: &str = "// KIWI_WORKER_GLUE_END";

/// Escape a string for embedding as a JSON string literal.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The `workerSource` section appended to the glue: the whole span between
/// (and including) the KIWI_WORKER_SRC_BEGIN and KIWI_WORKER_SRC_END
/// marker lines, ending with the trailing "from the KIWI_WORKER_SRC_BEGIN
/// marker" comment line. Note: the prose names the markers without the
/// `// ` line prefix (the tool locates the markers by exact
/// "// KIWI_WORKER_SRC_..." matches, so a prefixed mid-line mention would
/// break the sentinel scan).
fn worker_source_section(worker_src: &str) -> String {
    format!(
        "{BEGIN} — generated section (tools/embed-worker): the whole span\n\
         // from this marker to the KIWI_WORKER_SRC_END marker is machine-written.\n\
         window.__kiwiCaptchaWasm = window.__kiwiCaptchaWasm || {{}};\n\
         window.__kiwiCaptchaWasm.workerSource = \"{escaped}\";\n\
         {END} — generated section (tools/embed-worker): the whole span\n\
         // from the KIWI_WORKER_SRC_BEGIN marker to this marker is machine-written.\n",
        escaped = json_escape(worker_src)
    )
}

/// The machine-written span at the head of the release worker asset
/// `assets/kiwi-worker.js`: the `var window = self;` prelude followed by
/// the complete glue text (`assets/kiwicaptcha-wasm.js`, verbatim), with
/// the KIWI_WORKER_GLUE_END marker line as the span's final line — the
/// canonical solver source follows it immediately, so the tool's
/// extraction (everything after that marker line) is exact. A worker
/// executing this span runs the glue before the solver source, so
/// `window.__kiwiCaptchaWasm` (and its wasm) is in scope from boot.
/// Note: the generated prose never repeats the marker tokens verbatim —
/// the tool locates the markers by exact line-anchored matches, so a
/// mid-line mention would break extraction.
fn worker_glue_span(glue_full: &str) -> String {
    format!(
        "{WORKER_GLUE_BEGIN} — generated section (tools/embed-worker): the whole span\n\
         // from this marker to the matching end marker line below the whole span is\n\
         // machine-written: the `var window = self;` prelude followed by the full\n\
         // assets/kiwicaptcha-wasm.js glue text, so the worker boots with the wasm\n\
         // runtime in scope (no runtime fetch of its own in any tier).\n\
         var window = self;\n\
         {glue_full}\
         {WORKER_GLUE_END} — generated section (tools/embed-worker): the whole span\n"
    )
}

/// Find a marker at the start of a line (position 0 or right after a
/// newline). The generated glue text and the generated prose never
/// contain the worker-asset markers at a line start, so the first
/// line-anchored occurrence is always the machine-written marker.
fn find_line_anchored(haystack: &str, marker: &str) -> Option<usize> {
    if haystack.starts_with(marker) {
        return Some(0);
    }
    let needle = format!("\n{marker}");
    haystack.find(&needle).map(|i| i + 1)
}

/// Replace the span between the glue's workerSource sentinels (from the
/// BEGIN-marker line start through the END marker line AND its trailing
/// continuation line) with a fresh section; when the sentinels are absent
/// (glue freshly generated by tools/embed) the section is appended at the
/// end.
fn regenerate_glue(glue: &str, worker_src: &str) -> Result<String, String> {
    let section = worker_source_section(worker_src);
    let err = |m: &str| Err(m.to_string());
    match glue.find(BEGIN) {
        Some(begin_idx) => {
            let end_idx = glue
                .find(END)
                .ok_or_else(|| "kiwicaptcha-wasm.js: KIWI_WORKER_SRC_END sentinel not found")?;
            if begin_idx >= end_idx {
                return err("kiwicaptcha-wasm.js: sentinels out of order (BEGIN must precede END)");
            }
            let between = &glue[begin_idx..end_idx];
            if !between.contains("window.__kiwiCaptchaWasm.workerSource = \"")
                || !between.trim_end().ends_with(';')
            {
                return err("kiwicaptcha-wasm.js: generated section between the sentinels does not match the workerSource assignment");
            }
            let begin_line_start = glue[..begin_idx].rfind('\n').map_or(0, |i| i + 1);
            let end_line_end = end_idx + glue[end_idx..].find('\n').expect("newline after END");
            let mut tail_start = end_line_end + 1;
            if glue[tail_start..].starts_with("// from the KIWI_WORKER_SRC_BEGIN marker") {
                tail_start += glue[tail_start..].find('\n').map_or(0, |i| i + 1);
            }
            let head = &glue[..begin_line_start];
            let tail = &glue[tail_start..];
            Ok(format!("{head}{section}{tail}"))
        }
        None => {
            if glue.contains("KIWI_WORKER_SRC_END") {
                return err("kiwicaptcha-wasm.js: KIWI_WORKER_SRC_END present without KIWI_WORKER_SRC_BEGIN");
            }
            Ok(format!("{glue}{section}"))
        }
    }
}

/// Extract the canonical worker solver source from the release worker
/// asset: everything after the KIWI_WORKER_GLUE_END marker line. A worker
/// asset that predates the glue embedding (or a hand-recreated pure-source
/// file) carries no markers and IS the source itself.
fn extract_worker_logic(worker_asset: &str) -> Result<String, String> {
    let err = |m: &str| Err(m.to_string());
    match find_line_anchored(worker_asset, WORKER_GLUE_END) {
        Some(idx) => {
            let after_marker = idx + WORKER_GLUE_END.len();
            let line_end = worker_asset[after_marker..]
                .find('\n')
                .map_or(worker_asset.len(), |i| after_marker + i + 1);
            let logic = &worker_asset[line_end..];
            if find_line_anchored(logic, WORKER_GLUE_END).is_some() {
                return err("kiwi-worker.js: the worker solver source (after the KIWI_WORKER_GLUE_END marker) must not contain the KIWI_WORKER_GLUE_END marker");
            }
            if find_line_anchored(logic, WORKER_GLUE_BEGIN).is_some() {
                return err("kiwi-worker.js: the worker solver source (after the KIWI_WORKER_GLUE_END marker) must not contain the KIWI_WORKER_GLUE_BEGIN marker");
            }
            Ok(logic.to_string())
        }
        None => {
            if worker_asset.contains(WORKER_GLUE_END) || worker_asset.contains(WORKER_GLUE_BEGIN) {
                return err("kiwi-worker.js: a KIWI_WORKER_GLUE marker is present but not at the start of its own line");
            }
            // Transition state (or a hand-recreated pure source): the
            // whole file is the canonical solver source.
            Ok(worker_asset.to_string())
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let check = args.iter().any(|a| a == "--check");

    // tools/embed-worker -> packages/kiwicaptcha-wasm
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let worker_path = root.join("assets/kiwi-worker.js");
    let glue_path = root.join("assets/kiwicaptcha-wasm.js");

    let worker_asset = fs::read_to_string(&worker_path).expect("read assets/kiwi-worker.js");
    let glue = fs::read_to_string(&glue_path).expect("read assets/kiwicaptcha-wasm.js");

    // The canonical solver source: the worker asset's tail. It is embedded
    // into the glue (escaped) and shipped inside the glue-embedded worker
    // asset (raw), so both regenerations below derive from this one text.
    let worker_src = extract_worker_logic(&worker_asset).unwrap_or_else(|e| die(&e));

    // ASCII case-insensitive scan: `</ScRiPt>` must be rejected too — HTML
    // script end tags are case-insensitive. The solver source rides inside
    // the glue, which the renderers inline into pages.
    if worker_src.to_ascii_lowercase().contains("</script") {
        die("kiwi-worker.js must not contain a closing-script-tag sequence (the glue is inlined into pages)");
    }

    let regenerated_glue = regenerate_glue(&glue, &worker_src).unwrap_or_else(|e| die(&e));
    let regenerated_worker = {
        let span = worker_glue_span(&regenerated_glue);
        if let Some(begin_idx) = find_line_anchored(&worker_asset, WORKER_GLUE_BEGIN) {
            // The machine-written span sits at the head of the asset: the
            // opening marker line starts the span and the
            // KIWI_WORKER_GLUE_END marker line ends it. Replace the whole
            // span wholesale; the solver source tail is preserved.
            let end_idx = find_line_anchored(&worker_asset, WORKER_GLUE_END)
                .expect("KIWI_WORKER_GLUE_END present with KIWI_WORKER_GLUE_BEGIN");
            if end_idx < begin_idx {
                die("kiwi-worker.js: worker asset markers out of order (GLUE_BEGIN must precede GLUE_END)");
            }
            let after_marker = end_idx + WORKER_GLUE_END.len();
            let end_line_end = worker_asset[after_marker..]
                .find('\n')
                .map_or(worker_asset.len(), |i| after_marker + i + 1);
            format!(
                "{}{}{}",
                &worker_asset[..begin_idx],
                span,
                &worker_asset[end_line_end..]
            )
        } else {
            // No markers: the file is the pure solver source (transition),
            // so the glue-embedded span is simply prepended.
            format!("{span}{worker_asset}")
        }
    };

    if check {
        let mut drift = false;
        if regenerated_glue != glue {
            eprintln!("DRIFT: assets/kiwicaptcha-wasm.js embeds a stale copy of the worker solver source");
            drift = true;
        }
        if regenerated_worker != worker_asset {
            eprintln!("DRIFT: assets/kiwi-worker.js does not embed the current assets/kiwicaptcha-wasm.js glue");
            drift = true;
        }
        if drift {
            eprintln!("run: cargo run --locked --manifest-path tools/embed-worker/Cargo.toml --  (or packages/kiwicaptcha-wasm/build.sh)");
            process::exit(1);
        }
        println!("worker source in sync (kiwicaptcha-wasm.js <-> kiwi-worker.js)");
    } else {
        fs::write(&glue_path, &regenerated_glue).expect("write assets/kiwicaptcha-wasm.js");
        fs::write(&worker_path, &regenerated_worker).expect("write assets/kiwi-worker.js");
        println!("kiwicaptcha-wasm.js workerSource + kiwi-worker.js glue span updated from the worker solver source");
    }
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}
