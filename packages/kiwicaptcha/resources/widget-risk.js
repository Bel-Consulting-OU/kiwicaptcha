(function () {
  var encoder = new TextEncoder();
  // The solver protocol/ABI generation label, identical to the eager
  // core's constant (widget-driver.js declares the same literal; the
  // browser test suite asserts the copies agree). The worker reports
  // the SAME id in its `ready`/`done` handshake messages AND verifies
  // the wasm glue's exported solver_protocol_id() before ready; this
  // module refuses any worker whose id differs (a stale cached worker
  // must never contribute a solution). This establishes
  // driver+worker+wasm protocol compatibility ONLY — exact-artifact
  // identity is guaranteed by the release tag + SHA256SUMS + SRI +
  // attestation, never by this string. Integrators must serve the
  // driver, worker and wasm from the SAME release (see SECURITY.md —
  // versioned-resource expectation).
  var KIWI_SOLVER_PROTOCOL_ID = "2026-09-r1";
  // The hard cap of the bounded search, identical to the eager core's
  // constant (the pure-JS SHA-256 solver enforces it there; the worker
  // solve message carries it here).
  var MAX_SHA_HASHES = 5000000;
  function b64decode(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    return Uint8Array.from(atob(str), function(c) { return c.charCodeAt(0); });
  }

  // ── widget-risk.js: the lazy risk-tier module ──────────────────────
  // The configuration- and server-armed machinery of the widget driver,
  // split out of the always-loaded eager core (widget-driver.js) so an
  // ordinary SHA-256 bootstrap pays nothing for it. Loaded ONLY when
  // the relevant server response or configuration needs it:
  //
  //   - data-kiwi-algorithm="argon2id"|"rsw" on the widget (the
  //     adaptive-risk solve tier: memory-hard and sequential time-lock
  //     challenges ALWAYS run in the same-origin worker — construction,
  //     the files-mode versioned worker/runtime asset fetches with
  //     their cryptographic preflights, and the build-id handshake all
  //     live here),
  //   - a challenge response carrying an argon2id/rsw challenge while a
  //     weaker one was requested (adaptive escalation),
  //   - a challenge response carrying a server-issued decoy (honeypot)
  //     field name or a strategy hint,
  //   - a challenge response carrying an execution_program (the
  //     ExecutionChallengeV1 dimension: decoy + execution arms are
  //     issued together by the risk-armed server and share the lazy
  //     trigger).
  //
  // The coarse client-context descriptor (the explicit
  // data-kiwi-risk-context="coarse" opt-in) moved INTO the eager core
  // (audit finding 1): the core builds it and exposes it plus the
  // byte-bounded truncation helper on the internal bridge
  // (bridge.core.buildClientContext / bridge.core.boundBytes), so the
  // issuance never waits for this module and this module can still
  // READ the context and reuse the truncation for its decoy evidence.
  //
  // The core delivers this file the way it delivers the worker asset in
  // files mode: the page issues the versioned content-addressed URL and
  // its sha256 SRI digest as data-kiwi-risk-src /
  // data-kiwi-risk-integrity on the widget container (the inline asset
  // tier embeds this module instead), and the core injects a same-origin
  // <script src integrity=...> element when a trigger fires (the
  // browser's native SRI verification fails closed: a digest mismatch
  // never executes). The module registers its API on the internal core
  // bridge the moment it executes; widget state is passed in per call
  // (the widget record's private decoy state and the token element), so
  // the module is stateless across widgets.
  //
  // Failure semantics: decoy/honeypot evidence is probabilistic
  // signals, never gates — an unloadable module degrades to their
  // default absent state (console.warn). The solve tiers are
  // different: a memory-hard challenge whose module cannot load enters
  // the controlled kiwi:worker-unavailable state, and an armed program
  // that cannot run enters the controlled kiwi:execution-unavailable
  // state — never a silent success and never a weaker-profile fallback.

  // ── ExecutionChallengeV1: the lazy execution interpreter ────
  // The Cap-style dimension: when a challenge response carries an
  // execution_program, the driver lazily loads the FIXED audited
  // interpreter asset (execution.<sha256>.js) and runs the program in a
  // SANDBOXED EPHEMERAL IFRAME (srcdoc with a minimal document,
  // sandbox="allow-scripts allow-same-origin" — allow-same-origin is
  // REQUIRED because an opaque-origin sandboxed document cannot load a
  // same-origin script under the recommended CSP `script-src 'self'`,
  // and the loaded content is the SRI-pinned audited asset plus
  // bytecode data, never untrusted code). The interpreter computes the
  // execution digest (hex HMAC-SHA256 keyed by the program bytes over
  // the challenge context + the deterministic canonical op trace) and
  // the driver appends it to the solution token; the server recomputes
  // the expected digest from the STORED program and rejects a mismatch
  // with the deterministic execution-mismatch outcome. The dimension is
  // supplementary evidence only — never the sole acceptance boundary.
  //
  // Lazy invariant: a SHA-only challenge without a program pays ZERO
  // bytes for the interpreter. The iframe's <script src integrity=...>
  // is THE single fetch (same-origin, CSP-clean): the browser's native
  // SRI verification is the fail-closed preflight (a digest mismatch
  // never executes), and the browser's memory/HTTP cache dedups the
  // asset across the page — a page with several armed challenges
  // performs exactly ONE network fetch of the interpreter (asserted by
  // the request-accounting spec). There is deliberately NO driver-side
  // fetch of the interpreter: it would add a second request without
  // adding a check the native SRI pin does not already perform.
  // The iframe is created per armed challenge and REMOVED after the run
  // (a fresh document per run keeps the DOM state machine
  // deterministic).
  //
  // Every failure — missing/refused asset, SRI mismatch (no ready
  // handshake), iframe or interpreter failure, timeout — enters the
  // controlled kiwi:execution-unavailable state (the worker-unavailable
  // pattern): never a silent success, never a weaker-profile fallback.
  var kiwiExecutionRunCounter = 0;
  var KIWI_EXECUTION_TIMEOUT_MS = 10000;
  // Run one execution program in a fresh sandboxed ephemeral iframe and
  // resolve with the 64-hex execution digest. Rejects with a reason
  // string on every failure (fail closed).
  function kiwiRunExecution(program, nonce, container, W) {
    return new Promise(function (resolve, reject) {
      var executionSrc = (container.getAttribute ? container.getAttribute("data-kiwi-execution-src") : null)
        || (W.getAttribute ? W.getAttribute("data-kiwi-execution-src") : null);
      var executionIntegrity = (container.getAttribute ? container.getAttribute("data-kiwi-execution-integrity") : null)
        || (W.getAttribute ? W.getAttribute("data-kiwi-execution-integrity") : null);
      if (!executionSrc || !executionIntegrity) {
        // An armed challenge without a configured interpreter asset
        // URL is a deployment mismatch: fail closed.
        reject("execution-asset-unconfigured");
        return;
      }
      var iframe = document.createElement("iframe");
      iframe.setAttribute("sandbox", "allow-scripts allow-same-origin");
      iframe.setAttribute("aria-hidden", "true");
      iframe.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden;";
      // The interpreter runs via a SAME-ORIGIN script src with the SRI
      // pin (CSP `script-src 'self'` clean — no new directive, never an
      // inline script): the browser fetches the asset ONCE per page
      // (cache-deduped), verifies the integrity attribute BEFORE any
      // byte executes (fail closed: a mismatch never runs), and a wrong
      // asset simply never sends the ready handshake, so the driver
      // times out into the controlled error state.
      iframe.srcdoc = "<!doctype html><html><head><meta charset=\"utf-8\"></head><body><script src=\"" +
        executionSrc.replace(/&/g, "&amp;").replace(/"/g, "&quot;") +
        "\" integrity=\"" + executionIntegrity.replace(/"/g, "&quot;") + "\"><\/script><\/body><\/html>";
      // The run message targets the iframe with the PAGE'S OWN ORIGIN
      // (the srcdoc iframe is same-origin — never a "*" wildcard): the
      // message carries the program + nonce, and only the driver-created
      // iframe can be the target.
      // The per-run id is channel hygiene (defense in depth): the
      // authoritative gate is the event.source === iframe.contentWindow
      // check below. A monotonic counter suffices — no randomness is
      // needed anywhere in the execution plumbing, and none exists in
      // the interpreter's op semantics.
      kiwiExecutionRunCounter = (kiwiExecutionRunCounter + 1) >>> 0;
      var runId = "kiwi-exec-" + kiwiExecutionRunCounter.toString(36) + "-" + nonce.slice(0, 8);
      var settled = false;
      var timeout = setTimeout(function () {
        if (settled) return;
        settled = true;
        cleanup();
        reject("execution-timeout");
      }, KIWI_EXECUTION_TIMEOUT_MS);
      var onMessage = function (event) {
        // ONLY the driver-created iframe may answer: the source must be
        // this iframe's contentWindow (forged page traffic — event.source
        // is the page window — is ignored, exactly like the existing
        // no-page-listener posture) and the per-run id must match.
        if (event.source !== iframe.contentWindow) return;
        var data = event.data;
        if (!data || !data.protocol || data.protocol !== "kiwi-execution-v1") return;
        if (data.type === "kiwi-execution-ready") {
          try {
            iframe.contentWindow.postMessage({
              type: "kiwi-execution-run",
              protocol: "kiwi-execution-v1",
              id: runId,
              program: program,
              nonce: nonce
            }, window.location.origin);
          } catch (e) { fail("execution-iframe"); }
          return;
        }
        if (data.type === "kiwi-execution-result" && data.payload && data.payload.id === runId) {
          var digest = data.payload.digest;
          var trace = data.payload.trace;
          if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) {
            fail("execution-digest-malformed");
            return;
          }
          if (typeof trace !== "string" || trace.length < 1 || trace.length > 8192) {
            fail("execution-trace-malformed");
            return;
          }
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          cleanup();
          resolve({ digest: digest, trace: trace });
          return;
        }
        if (data.type === "kiwi-execution-error" && data.payload && data.payload.id === runId) {
          fail("execution-interpreter-" + (data.payload.reason || "error"));
        }
      };
      function fail(reason) {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        cleanup();
        reject(reason);
      }
      function cleanup() {
        try { window.removeEventListener("message", onMessage); } catch (e) {}
        try { if (iframe.parentNode) iframe.parentNode.removeChild(iframe); } catch (e) {}
      }
      // The listener is attached BEFORE the iframe is appended: the
      // interpreter's ready handshake can arrive as soon as the script
      // loads, and a late listener would miss it (the race the
      // request-accounting spec pins down).
      window.addEventListener("message", onMessage);
      document.body.appendChild(iframe);
    });
  }

  // ── Same-origin Argon2id/rsw Web Worker (the solve tier) ──────
  // The memory-hard (argon2id) and sequential time-lock (rsw) solver
  // ALWAYS runs off the main thread: a missing or failed worker enters
  // the controlled kiwi:worker-unavailable state — no main-thread
  // Argon2 hash and no weaker-profile retry, ever. postMessage BOUNDARY:
  // this module NEVER posts to the parent page — all postMessage usage
  // is worker-internal (the driver <-> worker solve traffic and the
  // worker's own progress/done/failed reports); no cross-origin target
  // exists and forged page traffic is ignored (the browser test suite
  // asserts forged postMessage payloads never mint a token).
  //
  //  - inline mode constructs the historical Blob worker from local code
  //    (the glue's embedded workerSource plus the inline glue source) —
  //    zero requests, byte-identical behavior; the glue bytes come from
  //    the eager core's extraction helpers (bridge.core.findGlueSource /
  //    bridge.core.embeddedWorkerSource) or, on the external /api.js
  //    compat route, from the glue part the widget-compat.js chunk
  //    publishes on the bridge;
  //  - files mode constructs a SAME-ORIGIN Worker from the versioned
  //    worker.<hash>.js asset the module fetched and preflight-verified
  //    (the fetched bytes are hashed and compared against the
  //    page-issued digest, then the content-addressed URL is handed to
  //    the browser's Worker constructor) — no Blob URL, so files mode
  //    needs worker-src 'self' (never blob:), and the glue rides the
  //    worker's own importScripts of the verified runtime asset (the
  //    { type: "glue" } handshake below);
  //  - the legacy explicit data-kiwi-worker-src URL (without an
  //    integrity digest) keeps its historical direct-construction path,
  //    and the module derives the runtime URL from the worker's own URL
  //    and hands it over through the SAME { type: "glue" } handshake —
  //    the worker never eagerly imports a relative runtime on its own.
  // The worker NEVER probes an unversioned runtime at startup in any
  // path: it boots with no runtime and the driver always supplies the
  // runtime URL explicitly. A subsequent attempt (Retry button, click,
  // re-init) retries the worker from scratch.
  var kiwiActiveBlobUrl = null; // shared so reset/unavailable paths can revoke
  function kiwiRevokeActiveBlobUrl() {
    if (kiwiActiveBlobUrl) { URL.revokeObjectURL(kiwiActiveBlobUrl); kiwiActiveBlobUrl = null; }
  }
  // ── Files-mode lazy asset loading (runtime + worker) ─────
  // In files mode (data-kiwi-runtime-src + data-kiwi-worker-src) the WASM
  // runtime glue and the Argon worker asset are fetched ONLY when a
  // memory-hard challenge arrives: a SHA-256 solve pays no request at all,
  // the pure-JS solver runs. Both fetches are bounded (two retries),
  // deduplicated per URL across every widget on the page (a shared
  // promise), and cryptographically preflight-verified against the
  // page-issued digests
  // (data-kiwi-runtime-integrity / data-kiwi-worker-integrity) BEFORE the
  // bytes are used: the fetched bytes are hashed with crypto.subtle and
  // compared to the digest; only then is the content-addressed URL loaded
  // by the browser APIs (the Worker constructor / the worker's
  // importScripts). A failure enters the controlled worker-unavailable
  // state, never a main-thread Argon hash and never a weaker-profile
  // retry. The integrity verification FAILS CLOSED: when a digest IS
  // demanded but the page cannot compute it (no crypto.subtle.digest),
  // the fetch is refused with the integrity-unverifiable reason — an
  // unverifiable asset is never an implicit success.
  var kiwiRuntimeGlueCache = {};
  var kiwiWorkerAssetCache = {};
  function kiwiVerifyIntegrity(src, integrity) {
    if (!integrity) return Promise.resolve({ ok: true });
    var expected = integrity.indexOf("sha256-") === 0 ? integrity.slice(7) : null;
    if (!expected) return Promise.resolve({ ok: false, reason: "integrity-malformed" });
    if (!window.crypto || !window.crypto.subtle || !window.crypto.subtle.digest) {
      // An integrity value IS demanded but this page cannot compute the
      // digest: fail closed. The fetched bytes can never be proven to be
      // the pinned bytes, so they must never run.
      return Promise.resolve({ ok: false, reason: "integrity-unverifiable" });
    }
    return crypto.subtle.digest("SHA-256", encoder.encode(src)).then(function (buf) {
      var bytes = new Uint8Array(buf);
      var bin = "";
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin) === expected ? { ok: true } : { ok: false, reason: "integrity-mismatch" };
    }).catch(function () { return { ok: false, reason: "integrity-unverifiable" }; });
  }
  function kiwiFetchRuntimeGlue(url, integrity) {
    if (kiwiRuntimeGlueCache[url]) return kiwiRuntimeGlueCache[url];
    var promise = new Promise(function (resolve) {
      var attempt = 0;
      var lastReason = "runtime-unavailable";
      function tryFetch() {
        fetch(url, { cache: "force-cache", credentials: "same-origin" })
          .then(function (r) { if (!r.ok) { lastReason = "runtime-fetch-" + r.status; throw new Error("KiwiCaptcha runtime fetch failed"); } return r.text(); })
          .then(function (src) {
            if (src.indexOf("var KIWI_WASM_B64") === -1 || src.indexOf("__kiwiCaptchaWasm") === -1) {
              lastReason = "runtime-malformed";
              throw new Error("KiwiCaptcha runtime asset malformed");
            }
            return kiwiVerifyIntegrity(src, integrity).then(function (res) {
              if (!res.ok) { lastReason = res.reason; throw new Error("KiwiCaptcha runtime integrity failure"); }
              return src;
            });
          })
          .then(function (src) { resolve({ src: src }); })
          .catch(function () {
            if (attempt < 2) { attempt++; setTimeout(tryFetch, 250 * attempt); }
            else { resolve({ error: lastReason }); }
          });
      }
      tryFetch();
    });
    kiwiRuntimeGlueCache[url] = promise;
    return promise;
  }
  function kiwiFetchWorkerAsset(url, integrity) {
    if (kiwiWorkerAssetCache[url]) return kiwiWorkerAssetCache[url];
    var promise = new Promise(function (resolve) {
      var attempt = 0;
      var lastReason = "worker-unavailable";
      function tryFetch() {
        fetch(url, { cache: "force-cache", credentials: "same-origin" })
          .then(function (r) { if (!r.ok) { lastReason = "worker-fetch-" + r.status; throw new Error("KiwiCaptcha worker asset fetch failed"); } return r.text(); })
          .then(function (src) {
            if (src.indexOf("KiwiCaptcha worker solver") === -1) {
              lastReason = "worker-malformed";
              throw new Error("KiwiCaptcha worker asset malformed");
            }
            return kiwiVerifyIntegrity(src, integrity).then(function (res) {
              if (!res.ok) { lastReason = res.reason; throw new Error("KiwiCaptcha worker integrity failure"); }
              return src;
            });
          })
          .then(function (src) { resolve({ src: src }); })
          .catch(function () {
            if (attempt < 2) { attempt++; setTimeout(tryFetch, 250 * attempt); }
            else { resolve({ error: lastReason }); }
          });
      }
      tryFetch();
    });
    kiwiWorkerAssetCache[url] = promise;
    return promise;
  }
  function solveWithWorker(data, onProgress, container, deadline) {
    var terminateHandle = function () {};
    var workerSrc = container.getAttribute("data-kiwi-worker-src");
    var workerIntegrity = container.getAttribute("data-kiwi-worker-integrity");
    var runtimeSrc = container.getAttribute("data-kiwi-runtime-src");
    var runtimeIntegrity = container.getAttribute("data-kiwi-runtime-integrity");
    // Files-mode worker asset: a versioned worker URL WITH its integrity
    // digest is the theme-emitted lazy worker asset (fetched and
    // preflight-verified below and
    // run as a same-origin Worker). A worker URL WITHOUT the integrity
    // attribute keeps the legacy explicit static-worker path.
    var lazyWorkerAsset = !!(workerSrc && workerIntegrity);
    // The worker glue source: the inline script element (inline mode), the
    // compat loader's fetched glue (/api.js), or the lazy runtime fetch of
    // files mode (data-kiwi-runtime-src).
    var glue = workerSrc ? null : (kiwiBridge.core.findGlueSource() || kiwiBridge.compatGlue);
    // The runtime URL handed to the worker through the { type: "glue" }
    // handshake. The driver ALWAYS directs the worker's runtime: files
    // mode passes the page-issued versioned runtime asset
    // (driver-preflight-verified by
    // the driver's fetch below); the legacy static-worker path derives the
    // runtime URL from the worker's own URL — the exact resolution the
    // worker's historical relative importScripts used, now supplied
    // explicitly so the worker never probes an unversioned URL on its own.
    var glueRuntimeSrc = null;
    if (lazyWorkerAsset) {
      glueRuntimeSrc = runtimeSrc;
    } else if (workerSrc) {
      try {
        glueRuntimeSrc = new URL("kiwicaptcha-wasm.js", new URL(workerSrc, window.location.href).href).href;
      } catch (e) {}
    }
    var glueReady;
    if (workerSrc) {
      // URL-constructed worker: the same-origin worker loads the glue
      // itself (importScripts of the runtime URL the driver supplies via
      // the { type: "glue" } message). For files mode the driver STILL
      // fetches + cryptographically preflight-verifies the runtime glue:
      // the immutable
      // content-addressed URL then serves the identical bytes to the
      // worker's importScripts from the HTTP cache, so the runtime is
      // downloaded exactly once per page across widgets. The legacy
      // static-worker path (no integrity attribute) needs no driver-side
      // runtime fetch — the worker importScripts the derived URL — but the
      // driver still supplies that URL explicitly.
      glueReady = lazyWorkerAsset && runtimeSrc
        ? kiwiFetchRuntimeGlue(runtimeSrc, runtimeIntegrity)
        : Promise.resolve({ src: null });
    } else {
      glueReady = glue
        ? Promise.resolve({ src: glue })
        : (runtimeSrc ? kiwiFetchRuntimeGlue(runtimeSrc, runtimeIntegrity) : Promise.resolve({ src: null }));
    }
    var workerReady = lazyWorkerAsset
      ? kiwiFetchWorkerAsset(workerSrc, workerIntegrity)
      : Promise.resolve({ src: null });
    var promise = Promise.all([glueReady, workerReady]).then(function (both) {
      var glueResult = both[0];
      var workerResult = both[1];
      if (glueResult && glueResult.error) {
        // The lazy runtime fetch failed after its bounded retries (or its
        // preflight digest check could not be verified): fail closed —
        // never a main-thread
        // Argon hash, never a weaker-profile retry.
        return { unavailable: true, reason: glueResult.error };
      }
      if (workerResult && workerResult.error) {
        // The lazy worker asset fetch failed after its bounded retries (or
        // its preflight digest check could not be verified): fail closed the same way.
        return { unavailable: true, reason: workerResult.error };
      }
      var resolvedGlue = glueResult ? glueResult.src : null;
      return new Promise(function(resolve) {
        if (typeof Worker === "undefined") { resolve({ unavailable: true, reason: "no-worker-support" }); return; }
        var worker = null;
        var blobUrl = null;
        try {
          if (workerSrc) {
            // Files mode: a SAME-ORIGIN Worker constructed from the
            // content-addressed URL of the fetched + preflight-verified
            // asset. The Worker constructor
            // loads the script through the browser's worker-script
            // fetcher — a platform fetch of the SAME content-addressed
            // URL, which can only ever serve the exact verified bytes
            // (the hash is in the URL and an unknown hash is a 404), so
            // the running worker IS the preflight-verified source; a Blob is never
            // created, so files mode needs worker-src 'self', not blob:.
            // The driver's lazy fetch stays deduplicated per URL (the
            // page issues exactly one window.fetch for worker.<hash>.js);
            // the constructor's platform worker-script load of the same
            // immutable URL is the browser loading the verified asset.
            worker = new Worker(workerSrc);
          } else {
            // Inline mode (historical Blob worker): the glue's embedded
            // workerSource plus the inline glue source, byte-identical.
            var workerSource = kiwiBridge.core.embeddedWorkerSource();
            if (!workerSource) { resolve({ unavailable: true, reason: "worker-source-unavailable" }); return; }
            var blobSrc = (resolvedGlue ? "var window = self;" + resolvedGlue + "\n" : "") + workerSource;
            blobUrl = URL.createObjectURL(new Blob([blobSrc], { type: "application/javascript" }));
            worker = new Worker(blobUrl);
          }
        } catch (e) { if (blobUrl) URL.revokeObjectURL(blobUrl); resolve({ unavailable: true, reason: "worker-creation-failed" }); return; }
        if (!worker) { if (blobUrl) URL.revokeObjectURL(blobUrl); resolve({ unavailable: true, reason: "worker-creation-failed" }); return; }
        if (kiwiActiveBlobUrl) { URL.revokeObjectURL(kiwiActiveBlobUrl); kiwiActiveBlobUrl = null; }
        kiwiActiveBlobUrl = blobUrl;
        // A cancelled generation terminates the worker outright — revoking
        // the blob URL alone would NOT stop it.
        terminateHandle = function () {
          try { worker.terminate(); } catch (e) {}
          teardown();
        };
        window.__kiwiWorkerUsed = true;
        var workerStart = performance.now();
        // The progress denominator: an rsw solve reports squarings done
        // (the proof has no probabilistic target), every other solve
        // reports hashes tried against the 2^target_bits expectation.
        var expectedUnits = (data.algorithm || "sha256") === "rsw"
          ? (data.t || 1)
          : Math.pow(2, data.targetBits);
        var settled = false;
        // Blob-URL cleanup: the object URL is revoked exactly once on EVERY
        // terminal path — done, failed, build-id mismatch, worker error, and
        // postMessage failure. Revoking never kills the worker itself
        // (terminate() does that); it only releases the URL, so a stale
        // blob URL can never leak for the page's lifetime. Files mode never
        // creates a blob URL, so the teardown is a no-op there.
        function teardown() {
          if (blobUrl) {
            URL.revokeObjectURL(blobUrl);
            if (kiwiActiveBlobUrl === blobUrl) kiwiActiveBlobUrl = null;
            blobUrl = null;
          }
        }
        // The solve deadline (challenge expiry − margin): a memory-hard
        // solve that would outlive the challenge is pure waste and the
        // token would be rejected anyway, so the worker is TERMINATED at
        // the deadline — the same mechanics as generation cancellation
        // (terminate() + teardown, exactly once). The driver's retry flow
        // then re-acquires a fresh challenge.
        var deadlineTimer = null;
        if (deadline && deadline > performance.now()) {
          deadlineTimer = setTimeout(function () {
            if (settled) return;
            settled = true;
            clearTimeout(deadlineTimer);
            try { worker.terminate(); } catch (e) {}
            teardown();
            resolve({ deadline: true });
          }, deadline - performance.now());
        }
        // The worker is CREATED BY THIS DRIVER (a Blob URL built from local
        // code, or the same-origin asset URL), so no cross-origin
        // postMessage target exists and no rate-limit window is needed here
        // — admission rate limiting lives on the challenge endpoint,
        // server-side. The shape guard below is defense-in-depth for the
        // worker port: any message that is not a versioned
        // progress/done/failed solution message with the expected payload is
        // ignored outright, never acted on.
        worker.onmessage = function(ev) {
          var msg = ev.data;
          if (!msg || typeof msg !== "object" || msg.v !== 1) return;
          if (msg.type === "ready") {
            // Startup handshake: the worker must report the SAME solver
            // protocol id as this driver. A stale cached worker is refused —
            // it never contributes a solution and there is no fallback.
            if (typeof msg.buildId !== "string" || msg.buildId !== KIWI_SOLVER_PROTOCOL_ID) {
              if (!settled) {
                console.error("KiwiCaptcha worker protocol mismatch: ready buildId", msg.buildId);
                settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true });
              }
            }
            return;
          }
          if (msg.type === "progress") {
            if (typeof msg.counter !== "number" || !isFinite(msg.counter)) return;
            onProgress(Math.min(95, (msg.counter * 100) / expectedUnits));
          } else if (msg.type === "done") {
            if (typeof msg.buildId !== "string" || msg.buildId !== KIWI_SOLVER_PROTOCOL_ID) {
              if (!settled) { settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true }); }
              return;
            }
            var isRsw = (data.algorithm || "sha256") === "rsw";
            // An rsw solve reports the final value (proof), never a
            // counter: a stale worker answering with a counter is a
            // protocol failure, not a solution.
            if (isRsw) {
              if (typeof msg.proof !== "string" || !/^[0-9a-f]{512}$/.test(msg.proof)) {
                if (!settled) { settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true }); }
                return;
              }
            } else if (typeof msg.counter !== "number" || !isFinite(msg.counter)) {
              return;
            }
            settled = true;
            clearTimeout(deadlineTimer);
            worker.terminate();
            teardown();
            resolve(isRsw
              ? { proof: msg.proof, duration: Math.round(performance.now() - workerStart) }
              : { counter: msg.counter, duration: Math.round(performance.now() - workerStart) });
          } else if (msg.type === "failed") {
            if (typeof msg.reason !== "string") return;
            // The worker verifies the wasm glue's exported protocol version
            // BEFORE ready and reports protocol-mismatch when the wasm/worker
            // generations differ — surfaced as the controlled
            // solver-mismatch state (a stale worker or a mixed-generation
            // deployment; same UX as a worker reporting the wrong protocol
            // id in its ready handshake).
            if (msg.reason === "protocol-mismatch") {
              if (!settled) {
                console.error("KiwiCaptcha worker protocol mismatch: wasm/worker generation differ");
                settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true });
              }
              return;
            }
            settled = true;
            clearTimeout(deadlineTimer);
            worker.terminate();
            teardown();
            console.error("KiwiCaptcha worker failed:", msg.reason);
            resolve({ unavailable: true, reason: "worker-failed-" + msg.reason });
          }
        };
        worker.onerror = function(ev) {
          if (settled) return;
          settled = true;
          clearTimeout(deadlineTimer);
          worker.terminate();
          teardown();
          console.error("KiwiCaptcha worker error:", ev && ev.message, ev && ev.filename, ev && ev.lineno);
          resolve({ unavailable: true, reason: "worker-error" });
        };
        var prefixBytes = encoder.encode(data.prefix);
        var saltBytes = b64decode(data.salt);
        var isRsw = (data.algorithm || "sha256") === "rsw";
        try {
          // Hand the runtime URL to the worker BEFORE the solve — the
          // worker importScripts it, verifies the wasm protocol version
          // and only then solves; the solve message (posted right after)
          // is queued behind the glue handshake. The driver ALWAYS
          // supplies the runtime URL explicitly (files mode: the
          // driver-preflight-verified versioned runtime asset; legacy
          // static-worker
          // path: the URL derived from the worker's own URL), so the
          // worker never probes an unversioned runtime on its own. The
          // worker only ever accepts a same-origin runtime URL (parsed
          // origin equality, never a string prefix).
          if (glueRuntimeSrc) {
            worker.postMessage({ v: 1, type: "glue", runtimeSrc: glueRuntimeSrc });
          }
          // The solve message carries the full field set for every
          // algorithm; an rsw solve adds the nonce and the base64
          // modulus (the worker derives the base from prefix||nonce and
          // squares modulo the modulus). The rsw solver never touches
          // the wasm module, so a missing glue still solves.
          var solveMsg = {
            v: 1,
            type: "solve",
            algorithm: isRsw ? "rsw" : "argon2id",
            prefix: data.prefix,
            prefixLen: prefixBytes.length,
            salt: data.salt,
            saltLen: saltBytes.length,
            targetBits: data.targetBits,
            mKib: data.mKib || 0,
            t: isRsw ? (data.t || 1) : (data.t || 1),
            p: data.p || 1,
            startCounter: 0,
            maxHashes: MAX_SHA_HASHES,
          };
          if (isRsw) {
            solveMsg.nonce = data.nonce;
            solveMsg.modulus = data.rsw_modulus;
          }
          worker.postMessage(solveMsg);
        } catch (e) {
          if (!settled) { settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ unavailable: true, reason: "post-failed" }); }
        }
      });
    });
    return { promise: promise, terminate: terminateHandle };
  }
  // ── Server-issued decoy (honeypot) field ───────────────────────────
  // After a successful challenge response, the server may name a decoy
  // field (bounded [A-Za-z0-9_-]{1,64} — validated before trusting; a
  // malformed name is ignored). The module renders ONE hidden text input
  // with that name inside the same form/host as the token input, so the
  // protected form submission carries it. The presentation is
  // POLYMORPHIC: a bounded set of rendering strategies is chosen per
  // challenge INDEPENDENTLY of the name — each challenge draws its
  // strategy from the client-side CSPRNG (crypto.getRandomValues), so
  // the strategy is a separate random dimension a bot cannot derive from
  // the served name. The fixture's /challenge response may carry an
  // optional NON-AUTHENTICATED `strategy` hint (an integer 0-5) that the
  // module honors when present (production responses omit it;
  // deterministic tests use it to force each variant). Every strategy
  // keeps the input invisible to humans, non-interactive (tabindex=-1,
  // aria-hidden, no focus) and off the browser's autofill candidate
  // surface (autocomplete off or new-password, never a labelled visible
  // field). The module NEVER auto-fills it: a human never types into it
  // — a bot's filler is exactly the evidence.
  // The wrapper/container class names of the wrapped variants vary from
  // a small bounded set (a client-side choice per challenge), and every
  // variant remains accessible and autofill-safe; the cleanup logic is
  // class-agnostic and never depends on the class names.
  // The strategy choice is presentation-only: a bot that learned to
  // classify every rendering gains nothing, because the decoy
  // evidence, the proof-of-work, the state machine and the replay and
  // risk controls are all independent of it.
  // The six strategies: 0 = bare input, display:none, after the token;
  // 1 = the same input inside a wrapper span; 2 = bare input with the
  // hidden attribute, before the token; 3 = bare offscreen input after
  // the token; 4 = wrapped input with the hidden attribute, before the
  // token; 5 = the strategy-0 look, but created only once the first
  // solve completes (deferred creation timing).
  var KIWI_DECOY_VARIANT_COUNT = 6;
  var KIWI_DECOY_WRAP_CLASSES = ["kiwi-form-aux", "kiwi-form-aux-alt", "kiwi-field-aux", "kiwi-aux-group"];
  // A client-side CSPRNG word (crypto.getRandomValues). The fallback on
  // engines without it is presentation-only: the strategy and the
  // wrapper class are never security boundaries — the authenticated
  // decoy name and the server-side checks are.
  function kiwiCspUint32() {
    if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      var buf = new Uint32Array(1);
      window.crypto.getRandomValues(buf);
      return buf[0] >>> 0;
    }
    return Math.floor(Math.random() * 4294967296) >>> 0;
  }
  function kiwiDecoyVariantFor(data) {
    var hint = data && typeof data.strategy === "number" ? data.strategy : null;
    if (hint !== null && hint >= 0 && hint < KIWI_DECOY_VARIANT_COUNT && hint === Math.floor(hint)) {
      return hint;
    }
    return kiwiCspUint32() % KIWI_DECOY_VARIANT_COUNT;
  }
  // The owned decoy input of a widget's private decoy state, or null when
  // none is (still) rendered. The owned set is authoritative: a
  // same-named application field is never found, never read, never
  // removed. The owned node may be the wrapper span of a wrapped
  // variant, so the input is resolved through it.
  function kiwiOwnedDecoyInput(state) {
    var nodes = state.nodes || [];
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      if (!node || !node.parentNode) continue;
      if (node.tagName === "INPUT") return node;
      var inner = node.querySelector ? node.querySelector("input") : null;
      if (inner && inner.parentNode) return inner;
    }
    return null;
  }
  // Remove the owned decoy nodes of a state: ONLY the nodes in the
  // widget's private owned set. A node is never identified or removed by
  // name match, so an application field with the same name is never
  // touched.
  function kiwiRemoveOwnedDecoys(state) {
    var nodes = state.nodes || [];
    state.nodes = [];
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      if (!node || !node.parentNode) continue;
      try { node.parentNode.removeChild(node); } catch (e) {}
    }
  }
  function kiwiInsertDecoyInput(host, decoyName, variant, state, tokenEl) {
    var input = document.createElement("input");
    input.type = "text";
    input.name = decoyName;
    input.value = "";
    input.setAttribute("tabindex", "-1");
    input.setAttribute("aria-hidden", "true");
    var before = variant === 2 || variant === 4;
    var el = input;
    if (variant === 1 || variant === 4) {
      var wrap = document.createElement("span");
      if (!state.className) state.className = KIWI_DECOY_WRAP_CLASSES[kiwiCspUint32() % KIWI_DECOY_WRAP_CLASSES.length];
      wrap.className = state.className;
      wrap.appendChild(input);
      el = wrap;
    }
    host.insertBefore(el, before ? tokenEl : tokenEl.nextSibling);
    state.nodes.push(el);
    if (variant === 0 || variant === 1 || variant === 5) {
      input.style.display = "none";
      input.setAttribute("autocomplete", "off");
    } else if (variant === 2 || variant === 4) {
      input.setAttribute("hidden", "");
      input.setAttribute("autocomplete", "off");
    } else {
      input.setAttribute("autocomplete", "new-password");
      input.setAttribute("aria-label", "off-screen field");
      input.style.position = "absolute";
      input.style.left = "-9999px";
      input.style.width = "1px";
      input.style.height = "1px";
      input.style.margin = "-1px";
      input.style.padding = "0";
      input.style.border = "0";
      input.style.overflow = "hidden";
      input.style.whiteSpace = "nowrap";
      input.style.clip = "rect(0 0 0 0)";
      input.style.clipPath = "inset(50%)";
    }
  }
  // Render the server-issued decoy input into the widget's form host.
  // The decoy state object is the widget record's PRIVATE decoy state
  // (it survives re-inits — an expiry-triggered re-solve must still see
  // a filled decoy as evidence, and the owned nodes must stay
  // removable).
  function kiwiRenderDecoy(data, decoyState, tokenEl) {
    var decoyName = data && typeof data.decoy_field === "string" ? data.decoy_field : null;
    if (decoyName === null || !/^[A-Za-z0-9_-]{1,64}$/.test(decoyName)) return;
    if (!tokenEl) return;
    var host = tokenEl.parentNode;
    if (!host) return;
    // A re-issued challenge carries a NEW per-issuance decoy name: any
    // decoy nodes owned under the earlier name are removed so the form
    // never accumulates stale honeypot fields.
    var previous = decoyState.name;
    if (previous && previous !== decoyName) {
      kiwiRemoveOwnedDecoys(decoyState);
      decoyState.className = null;
    }
    decoyState.name = decoyName;
    // A same-name reissue finds the owned input already in the host:
    // the rendering never duplicates it. The owned set decides — never
    // a name query, so a same-named application field cannot be
    // mistaken for the decoy.
    if (kiwiOwnedDecoyInput(decoyState)) {
      decoyState.deferred = false;
      return;
    }
    var variant = kiwiDecoyVariantFor(data);
    decoyState.variant = variant;
    if (variant === 5) {
      // The deferred strategy records the name now and creates the
      // input when the first solve completes (kiwiFlushDecoy), so the
      // decoy surface appears only after a real solve attempt.
      decoyState.deferred = true;
      return;
    }
    decoyState.deferred = false;
    kiwiInsertDecoyInput(host, decoyName, variant, decoyState, tokenEl);
  }
  // The deferred strategy (variant 5) creates its input only once the
  // first solve completes: called by the core right after the token is
  // written, so the decoy surface appears only after a real solve
  // attempt.
  function kiwiFlushDecoy(decoyState, tokenEl) {
    if (!tokenEl || !decoyState.deferred) return;
    decoyState.deferred = false;
    var decoyName = decoyState.name;
    if (!decoyName) return;
    var host = tokenEl.parentNode;
    if (!host) return;
    kiwiInsertDecoyInput(host, decoyName, 5, decoyState, tokenEl);
  }
  // The filled-decoy honeypot markers for the NEXT challenge request:
  // when the widget's own decoy input is still in the form and FILLED,
  // the decoy field name + a bounded value ride the request as honeypot
  // evidence — NEVER a gate, and the value is truncated to the server's
  // 256-byte bound by the core's kiwiBoundBytes (bridge.core.boundBytes,
  // the truncation helper the eager core owns since audit finding 1).
  // An empty decoy contributes nothing. The read is ownership-based (the
  // widget's own decoy node, never a name query).
  function kiwiReadHoneypot(decoyState, tokenEl) {
    if (!decoyState || !decoyState.name || !tokenEl) return null;
    var decoyInput = kiwiOwnedDecoyInput(decoyState);
    if (decoyInput && decoyInput.parentNode && typeof decoyInput.value === "string" && decoyInput.value !== "") {
      var truncate = (kiwiBridge && kiwiBridge.core && typeof kiwiBridge.core.boundBytes === "function")
        ? kiwiBridge.core.boundBytes
        : function (s) { return s; };
      return { name: decoyState.name, value: truncate(decoyInput.value, 256) };
    }
    return null;
  }

  // The module registers itself with the internal core bridge the moment
  // it executes (the core injects this file as a same-origin SRI-pinned
  // script only when a trigger fired); a module script that somehow ran
  // before the core is inert.
  var kiwiBridge = (typeof window !== "undefined" && window.__kiwiCaptchaCore) || null;
  if (kiwiBridge && typeof kiwiBridge.register === "function") {
    kiwiBridge.register("risk", {
      readHoneypot: kiwiReadHoneypot,
      renderDecoy: kiwiRenderDecoy,
      flushDecoy: kiwiFlushDecoy,
      runExecution: function (program, nonce, container, W) { return kiwiRunExecution(program, nonce, container, W); },
      solveWorker: function (data, onProgress, container, deadline) { return solveWithWorker(data, onProgress, container, deadline); },
      revokeWorkerUrl: kiwiRevokeActiveBlobUrl
    });
  }
})();
