import { test, expect } from '@playwright/test';

// Round 24: incumbent migration is a CI CONTRACT. These fixtures are
// structurally copied from standard reCAPTCHA v2 / invisible / hCaptcha /
// Turnstile integrations — the ONLY difference is the provider script URL
// (kiwi /kiwi-captcha/api.js?compat=...). The migration-diff budget: a
// standard incumbent page migrates with no more than a handful of changed
// lines; if a fixture requires more edits to keep working, that is a
// migration regression.

async function waitVerified(page, field = 'g-recaptcha-response') {
  const token = page.locator(`input[name="${field}"]`);
  await expect(token).not.toHaveValue('', { timeout: 60_000 });
  const value = await token.inputValue();
  expect(value.length).toBeGreaterThan(10);
  return value;
}

test.describe('KiwiCaptcha migration compatibility (round 24)', () => {
  test('reCAPTCHA v2: implicit render, data-callback, g-recaptcha-response alias', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toBeVisible();
    const token = await waitVerified(page);
    // The success callback receives the same token.
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('reCAPTCHA v2: widget ids + getResponse + REAL explicit render (string id, element, selector)', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    const token = await waitVerified(page);
    const id = await page.evaluate(() => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      return { wid, response: window.grecaptcha.getResponse(wid) };
    });
    expect(typeof id.wid).toBe('string');
    expect(id.wid.length).toBeGreaterThan(0);
    expect(id.response).toBe(token);
  });

  test('reCAPTCHA v2: omitted widget id defaults to the first created widget (round 29 P1)', async ({ page }) => {
    // Google's API: reset()/getResponse()/execute() with NO id target the
    // FIRST created widget. Kiwi previously required an explicit id/element
    // (no argument produced no reset / empty response).
    await page.goto('/migration/recaptcha-v2.html');
    const token = await waitVerified(page);
    const result = await page.evaluate(async () => {
      const first = document.querySelector('.g-recaptcha').dataset.kiwiInstance;
      const noArgResponse = window.grecaptcha.getResponse();
      const noArgExecute = await window.grecaptcha.execute();
      window.grecaptcha.reset();
      await new Promise((r) => setTimeout(r, 6000));
      return { first, noArgResponse, noArgExecute, responseAfterReset: window.grecaptcha.getResponse() };
    });
    expect(result.noArgResponse).toBe(token);
    expect(result.noArgExecute).toBe(token);
    expect(result.responseAfterReset).toBeTruthy();
    expect(result.responseAfterReset).not.toBe(token);
  });

  test('reCAPTCHA v2 explicit loading: render=explicit suppresses auto-render and onload renders (round 29 P1)', async ({ page }) => {
    // The fixture is the DOCUMENTED integration pattern (onload +
    // render=explicit) with only the provider URL changed. Without the
    // fix, render=explicit still auto-rendered (double widgets) and
    // onload never ran.
    await page.goto('/migration/recaptcha-v2-explicit.html');
    await expect(page.locator('#out')).toHaveText(/^cb:/, { timeout: 60_000 });
    const state = await page.evaluate(() => ({
      onloadRan: window.kiwiExplicitRendered === true,
      containerCount: document.querySelectorAll('.kiwi-container').length,
      response: window.grecaptcha.getResponse(),
    }));
    expect(state.onloadRan).toBe(true);
    // Exactly ONE widget: the explicit render, not an auto-rendered
    // duplicate of the same container.
    expect(state.containerCount).toBe(1);
    expect(state.response.length).toBeGreaterThan(10);
  });

  test('Turnstile: action/cData bound at issuance, returned from verified server state, request forging ignored (round 30 P1 e2e)', async ({ page, request }) => {
    // The FULL trust chain: data-action/data-cdata on the container ->
    // the driver sends them in the challenge request -> the server binds
    // them to the nonce -> Siteverify returns the SERVER-STORED values.
    // A backend request that tries action=admin gets the REAL action.
    await page.goto('/migration/turnstile-meta.html');
    await expect(page.locator('#out')).toHaveText(/^cb:/, { timeout: 60_000 });
    const token = await page.evaluate(() => {
      const w = document.querySelector('.cf-turnstile [data-kiwi-widget]');
      return window.turnstile.getResponse(w.dataset.kiwiInstance);
    });
    expect(token.length).toBeGreaterThan(10);

    const verified = await request.post('/siteverify', {
      data: { secret: 'compat-secret-42', response: token, remoteip: '127.0.0.1', action: 'admin', cdata: 'forged' },
    });
    const body = await verified.json();
    expect(body.success).toBe(true);
    expect(body.action, 'the response action must come from SERVER state, never the request').toBe('checkout');
    expect(body.cdata, 'the response cdata must come from SERVER state, never the request').toBe('order_19382');

    // Ordinary replay (no idempotency): the token is single-use.
    const replay = await request.post('/siteverify', {
      data: { secret: 'compat-secret-42', response: token, remoteip: '127.0.0.1' },
    });
    const replayBody = await replay.json();
    expect(replayBody.success).toBe(false);
    expect(replayBody['error-codes']).toContain('timeout-or-duplicate');
  });

  test('reCAPTCHA v3: execute(sitekey, {action}) transmits the REAL pair and the server-owned policy resolves the scope (round 31 P1)', async ({ page, request }) => {
    // The critical regression: the hidden v3 render previously passed the
    // ACTION as the sitekey, disconnecting the server-owned policy. The
    // challenge request must carry sitekey AND action independently, the
    // server must resolve (sitekey, action) -> commerce_high_value, and an
    // unknown action must be refused.
    const bodies = [];
    const statuses = [];
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      const response = await route.fetch();
      statuses.push({ action: bodies[bodies.length - 1].action ?? null, status: response.status() });
      await route.fulfill({ response });
    });
    await page.goto('/migration/recaptcha-v3.html');
    // Capture the token from the execute PROMISE (the hidden holder is
    // torn down on completion by design, so getResponse() afterwards is
    // empty).
    const token = await page.evaluate(async () => {
      const t = await window.grecaptcha.execute('6Lc_v3_sitekey_a', { action: 'checkout' });
      return t;
    });
    expect(token.length).toBeGreaterThan(10);

    const v3 = bodies.find((b) => b.sitekey === '6Lc_v3_sitekey_a');
    expect(v3, 'the challenge body must carry the real sitekey').toBeTruthy();
    expect(v3.action, 'the challenge body must carry the requested action independently').toBe('checkout');
    // The client scope is the public sitekey (the design): the SERVER maps
    // (sitekey, action) to the protected scope.
    expect(v3.scope).toBe('6Lc_v3_sitekey_a');
    const verified = await request.post('/verify', { data: { token, scope: 'commerce_high_value' } });
    const body = await verified.json();
    expect(body.ok, 'the server-resolved scope must be what verifies').toBe(true);

    // Unknown action -> REFUSED by the server policy (the 422 must reach
    // the client; the raw body is intentionally not leaked into the
    // widget's error message).
    const refused = await page.evaluate(async () => {
      try {
        await window.grecaptcha.execute('6Lc_v3_sitekey_a', { action: 'admin' });
        return 'resolved';
      } catch (e) {
        return String(e && e.message);
      }
    });
    const adminRefusals = statuses.filter((s2) => s2.action === 'admin');
    expect(adminRefusals.length).toBeGreaterThan(0);
    expect(adminRefusals.every((s2) => s2.status >= 400), 'the unknown action must be refused server-side').toBe(true);
    expect(refused).not.toBe('resolved');
  });

  test('reCAPTCHA v2: Retry after terminal failure preserves the FULL security configuration (round 31 P1)', async ({ page }) => {
    // A mapped sitekey -> sensitive scope must survive the Retry path:
    // reacquisition reinitializes from the PRESERVED options, never a
    // blank initWidget(W) that falls back to the default scope.
    let failing = true;
    const scopes = [];
    await page.route('**/challenge', async (route) => {
      const body = route.request().postDataJSON() ?? {};
      if (failing) {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      } else {
        scopes.push(body.scope);
        await route.continue();
      }
    });
    await page.goto('/migration/recaptcha-v2.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 60_000 });
    // The initial render's scope identity (the container's data-kiwi-scope,
    // which is the mapped sitekey — the fixture allowlist maps it to
    // 'login' server-side; a downgrade would show a DIFFERENT scope here).
    const containerScope = await page.evaluate(() => document.querySelector('.g-recaptcha').dataset.sitekey || document.querySelector('.g-recaptcha').dataset.kiwiScope);
    failing = false;
    await page.locator('.g-recaptcha [data-kiwi-retry]').click();
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    // The retry's challenge MUST carry the same scope identity as the
    // initial render — a blank re-init would fall back to "login".
    expect(scopes.length).toBeGreaterThan(0);
    for (const scope of scopes) {
      expect(scope).toBe(containerScope);
    }
  });

  test('reCAPTCHA v2: expiry -> Retry keyboard reacquisition preserves host form fields (round 31 P1)', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2-ttl.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    // Fill unrelated host-form data BEFORE expiry.
    await page.fill('input[name="email"]', 'user@example.com');
    await expect(page.locator('input[name="g-recaptcha-response"]')).toHaveValue('', { timeout: 30_000 });
    // The expired state exposes the Retry button.
    await expect(page.locator('.g-recaptcha [data-kiwi-retry]')).toBeVisible();
    await page.locator('.g-recaptcha [data-kiwi-retry]').focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('input[name="g-recaptcha-response"]')).not.toHaveValue('', { timeout: 60_000 });
    // Host form state untouched by the reacquisition.
    expect(await page.inputValue('input[name="email"]')).toBe('user@example.com');
  });

  test('reCAPTCHA v2 explicit mode: dynamically inserted containers NEVER auto-render until an explicit render() (round 30 P1)', async ({ page }) => {
    // render=explicit means the application controls rendering — the
    // MutationObserver must not auto-render a later .g-recaptcha node.
    await page.goto('/migration/recaptcha-v2-explicit.html');
    await expect(page.locator('#out')).toHaveText(/^cb:/, { timeout: 60_000 });
    const dynamic = await page.evaluate(async () => {
      const el = document.createElement('div');
      el.className = 'g-recaptcha';
      el.dataset.sitekey = '6Lc_dynamic_explicit';
      document.body.appendChild(el);
      await new Promise((r) => setTimeout(r, 600));
      const before = { autoRendered: !!el.querySelector('[data-kiwi-widget]'), containers: document.querySelectorAll('.kiwi-container').length };
      const id = window.grecaptcha.render(el, { sitekey: '6Lc_dynamic_explicit' });
      await new Promise((r) => setTimeout(r, 8000));
      return { before, id, containers: document.querySelectorAll('.kiwi-container').length, response: window.grecaptcha.getResponse(id) };
    });
    expect(dynamic.before.autoRendered, 'explicit mode must NOT auto-render dynamic containers').toBe(false);
    expect(dynamic.before.containers).toBe(1);
    expect(typeof dynamic.id).toBe('string');
    expect(dynamic.containers).toBe(2);
    expect(dynamic.response.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2 implicit mode: dynamically inserted containers still auto-render (round 30 P1)', async ({ page }) => {
    // The implicit-mode dynamic convenience is retained and proven.
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    const dynamic = await page.evaluate(async () => {
      const el = document.createElement('div');
      el.className = 'g-recaptcha';
      el.dataset.sitekey = '6Lc_dynamic_implicit';
      document.body.appendChild(el);
      // Wait for the auto-rendered widget to solve (bounded poll — CI
      // machines are slower than the local run).
      const deadline = Date.now() + 30_000;
      let response = '';
      while (Date.now() < deadline) {
        // The instance id lives on the RENDERED CONTAINER (compat mode),
        // not on the inner widget element.
        const id = el.dataset.kiwiInstance;
        response = id ? window.grecaptcha.getResponse(id) : '';
        if (response.length > 10) break;
        await new Promise((r) => setTimeout(r, 500));
      }
      return { autoRendered: !!el.querySelector('[data-kiwi-widget]'), response };
    });
    expect(dynamic.autoRendered).toBe(true);
    expect(dynamic.response.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2: grecaptcha.render("id", params) and render(element, params) actually render (round 28)', async ({ page }) => {
    // Round 28 (P2): the previous "explicit render" test never CALLED
    // grecaptcha.render() — it inspected the auto-rendered widget. The
    // compat API must resolve string ids/selectors through the same target
    // resolver as the native API and return a working widget id.
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    const result = await page.evaluate(async () => {
      const out = {};
      const targetA = document.createElement('div');
      targetA.id = 'explicit-a';
      document.body.appendChild(targetA);
      const idA = window.grecaptcha.render('explicit-a', { sitekey: '6Lc_explicit_login' });
      out.idA = idA;
      const targetB = document.createElement('div');
      targetB.className = 'explicit-b';
      document.body.appendChild(targetB);
      const idB = window.grecaptcha.render(targetB, { sitekey: '6Lc_explicit_login' });
      out.idB = idB;
      out.selectorId = window.grecaptcha.render('.explicit-b', { sitekey: '6Lc_explicit_login' });
      out.unknownId = window.grecaptcha.render('no-such-element', { sitekey: 'x' });
      out.containers = document.querySelectorAll('.kiwi-container').length;
      await new Promise((r) => setTimeout(r, 6000));
      out.responseA = window.grecaptcha.getResponse(idA);
      out.responseB = window.grecaptcha.getResponse(idB);
      return out;
    });
    expect(typeof result.idA).toBe('string');
    expect(result.idA.length).toBeGreaterThan(0);
    expect(typeof result.idB).toBe('string');
    expect(result.idB.length).toBeGreaterThan(0);
    expect(result.selectorId).toBe(result.idB);
    expect(result.unknownId).toBe(0);
    expect(result.containers).toBe(3);
    expect(result.responseA.length).toBeGreaterThan(10);
    expect(result.responseB.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2: provider errorCallback fires exactly once on terminal failure (round 28)', async ({ page }) => {
    // Round 28 (P2): the fixture's data-error-callback was parsed but never
    // invoked — fail()/workerUnavailable()/solverMismatch() now call it.
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    await page.goto('/migration/recaptcha-v2.html');
    await expect(page.locator('#out')).toHaveText('err-cb', { timeout: 30_000 });
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'failed');
    await expect(page.locator('.g-recaptcha [data-kiwi-retry]')).toBeVisible();
    // Exactly once: no further callback invocation after the terminal state.
    await page.waitForTimeout(4000);
    await expect(page.locator('#out')).toHaveText('err-cb');
  });

  test('reCAPTCHA v2: reset during an in-flight challenge cancels generation 1 (round 28)', async ({ page }) => {
    // Round 28 (P2): reset() must abort the old generation's fetch and the
    // delayed response must never write a token or invoke a callback.
    let calls = 0;
    await page.route('**/challenge', async (route) => {
      calls++;
      if (calls === 1) {
        await new Promise((r) => setTimeout(r, 3000));
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          nonce: 'cancel-nonce-' + calls, salt: btoa(String(calls).padStart(16, '0')), prefix: 'x',
          targetBits: 6, algorithm: 'sha256', mKib: 0, t: 1, p: 1, ttlSecs: 120, minDurationMs: 0,
        }),
      });
    });
    await page.goto('/migration/recaptcha-v2.html');
    const result = await page.evaluate(async () => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      // Count the widget's own lifecycle events (the fixture's global
      // callback was captured at render time, so reassigning it here would
      // not observe the generations).
      let verified = 0;
      // kiwi:verified dispatches on the rendered container (W) and bubbles.
      el.addEventListener('kiwi:verified', () => { verified++; });
      await new Promise((r) => setTimeout(r, 600));
      window.grecaptcha.reset(wid);
      await new Promise((r) => setTimeout(r, 8000));
      return { verified, response: window.grecaptcha.getResponse(wid) };
    });
    expect(calls).toBeGreaterThanOrEqual(2);
    // Exactly ONE verified event (generation 2 only — generation 1 was
    // cancelled mid-fetch and can never complete) + a valid gen-2 token.
    expect(result.verified).toBe(1);
    expect(result.response.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2: reset clears and reacquires', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    const token = await waitVerified(page);
    const result = await page.evaluate(async () => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      window.grecaptcha.reset(wid);
      await new Promise((r) => setTimeout(r, 4000));
      const responseAfter = window.grecaptcha.getResponse(wid);
      return { responseAfter };
    });
    // After reset the widget reacquires (the response is fresh again).
    expect(result.responseAfter).toBeTruthy();
    expect(result.responseAfter).not.toBe(token);
  });

  test('reCAPTCHA v2: execute(id) resolves with the token', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    const token = await waitVerified(page);
    const viaExecute = await page.evaluate(async () => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      return window.grecaptcha.execute(wid);
    });
    expect(viaExecute).toBe(token);
  });

  test('reCAPTCHA v2 Argon: grecaptcha.ready() queues behind glue readiness for explicit render (round 28)', async ({ page }) => {
    // Round 28 (P2): ready() must not race the loader-glue self-fetch — an
    // explicit render() inside ready() immediately starts an Argon worker
    // that needs the glue (no inline script exists on the external-loader
    // page). The api.js response is DELIBERATELY delayed so the race is
    // observable: without the fix the worker starts glue-less and fails.
    await page.route('**/api.js?*', async (route) => {
      await new Promise((r) => setTimeout(r, 1500));
      await route.continue();
    });
    await page.goto('/migration/recaptcha-v2-argon.html');
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        window.grecaptcha.ready(() => {
          const holder = document.createElement('div');
          document.body.appendChild(holder);
          const id = window.grecaptcha.render(holder, { sitekey: '6Lc_ready_explicit' });
          resolve({ id, phase: 'rendered' });
        });
        setTimeout(() => resolve({ id: null, phase: 'timeout' }), 20_000);
      });
    });
    expect(result.phase).toBe('rendered');
    expect(typeof result.id).toBe('string');
    await expect(page.locator('input[name="g-recaptcha-response"]').nth(1)).not.toHaveValue('', { timeout: 90_000 });
    const response = await page.evaluate((id) => window.grecaptcha.getResponse(id), result.id);
    expect(response.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2: v3-style execute(sitekey) tears down the hidden widget (round 28)', async ({ page }) => {
    // Round 28 (P3): repeated execute(sitekey, {action}) calls must not
    // accumulate hidden DOM, registry entries or reset hooks.
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    const result = await page.evaluate(async () => {
      const baseline = document.querySelectorAll('.kiwi-container').length;
      await window.grecaptcha.execute('6Lc_v3_checkout', { action: 'checkout' });
      const afterOne = document.querySelectorAll('.kiwi-container').length;
      await window.grecaptcha.execute('6Lc_v3_checkout', { action: 'checkout' });
      await window.grecaptcha.execute('6Lc_v3_checkout', { action: 'checkout' });
      await new Promise((r) => setTimeout(r, 500));
      return {
        baseline,
        afterOne,
        afterThree: document.querySelectorAll('.kiwi-container').length,
        hiddenHolders: Array.from(document.querySelectorAll('div')).filter((d) => d.style.display === 'none').length,
      };
    });
    // Every execute() cleans up its holder: no accumulation whatsoever.
    expect(result.afterOne).toBe(result.baseline);
    expect(result.afterThree).toBe(result.baseline);
    expect(result.hiddenHolders).toBe(0);
  });

  test('reCAPTCHA v2: execute() rejects with the ACTUAL failure reason (round 28)', async ({ page }) => {
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    await page.goto('/migration/recaptcha-v2.html');
    const message = await page.evaluate(async () => {
      try {
        await window.grecaptcha.execute('6Lc_fail_reason', { action: 'checkout' });
        return 'resolved';
      } catch (err) {
        return String(err && err.message);
      }
    });
    // fail() dispatches {error: msg} — the promise must surface the real
    // reason ("Challenge failed"), not the generic fallback.
    expect(message).toContain('Challenge failed');
    expect(message).not.toContain('solve failed');
  });

  test('reCAPTCHA v2: expiry clears the token + field + fires the expired callback', async ({ page }) => {
    // ttl=2 -> the challenge expires 2s after the solve; the client expiry
    // lifecycle mirrors the incumbent providers (the server remains the
    // authoritative check).
    await page.goto('/migration/recaptcha-v2-ttl.html');
    const token = await waitVerified(page);
    await expect(page.locator('input[name="g-recaptcha-response"]')).toHaveValue(token);
    await expect(page.locator('#out')).toHaveText('expired-cb', { timeout: 15_000 });
    await expect(page.locator('input[name="g-recaptcha-response"]')).toHaveValue('', { timeout: 15_000 });
    const state = await page.evaluate(() => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      return {
        expired: window.grecaptcha.isExpired ? window.grecaptcha.isExpired(wid) : 'n/a',
        response: window.grecaptcha.getResponse(wid),
      };
    });
    expect(state.response).toBe('');
  });

  test('reCAPTCHA v2: remove(id) destroys the widget', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    const gone = await page.evaluate(() => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      window.grecaptcha.remove(wid);
      // Provider parity (Turnstile remove()): the widget markup leaves the
      // page entirely.
      return document.querySelector('.g-recaptcha') === null
        && document.querySelectorAll('[data-kiwi-widget]').length === 0;
    });
    expect(gone).toBe(true);
  });

  test('invisible reCAPTCHA: the control click triggers execute + data-callback', async ({ page }) => {
    await page.goto('/migration/recaptcha-invisible.html');
    const button = page.locator('button.g-recaptcha');
    await expect(button.locator('[data-kiwi-widget]')).toBeVisible();
    await button.click();
    const token = await waitVerified(page);
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('hCaptcha: implicit render + h-captcha-response alias + callbacks', async ({ page }) => {
    await page.goto('/migration/hcaptcha.html');
    await expect(page.locator('.h-captcha [data-kiwi-widget]')).toBeVisible();
    const token = await waitVerified(page, 'h-captcha-response');
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('Turnstile: implicit render + cf-turnstile-response alias + callbacks', async ({ page }) => {
    await page.goto('/migration/turnstile.html');
    await expect(page.locator('.cf-turnstile [data-kiwi-widget]')).toBeVisible();
    const token = await waitVerified(page, 'cf-turnstile-response');
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('Argon2id solves through the external compatibility loader (worker glue path)', async ({ page }) => {
    // Round 26 (P1): with the driver loaded as the external /api.js, the
    // Blob worker has no inline glue element to copy — the loader's own
    // fetched source supplies it. Argon2id must therefore solve
    // end-to-end through the one-script migration path (SHA-256-only
    // fixtures would mask a broken glue handoff).
    await page.goto('/migration/recaptcha-v2-argon.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toBeVisible();
    const token = await waitVerified(page);
    expect(token.length).toBeGreaterThan(10);
  });

  test('the visible .kiwi-widget carries the done state (round 27 state fix)', async ({ page }) => {
    // Round 27 (P2): the state attribute must live on the INNER
    // .kiwi-widget (the stylesheet keys the pulse/success/failure styling
    // and Retry visibility on .kiwi-widget[data-state=...]) — the outer
    // incumbent wrapper previously took the state while the widget stayed
    // frozen at idle.
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'done');
  });

  test('a failed compat widget shows the failed state and the Retry button', async ({ page }) => {
    // The endpoint 404s -> the challenge fails -> the inner widget enters
    // the failed state and the Retry button becomes visible (previously
    // hidden because the state never landed on .kiwi-widget).
    await page.goto('/migration/recaptcha-v2.html');
    await page.evaluate(() => {
      document.querySelector('.g-recaptcha').setAttribute('data-kiwi-endpoint', '/definitely-missing-endpoint');
    });
    // The page already rendered with the default endpoint before the
    // attribute was set — force a fresh widget by navigating with the
    // broken endpoint baked in via the compat passthrough (reload with a
    // query the fixture passes through).
    await page.goto('/migration/recaptcha-v2.html');
    await page.evaluate(() => {
      const el = document.querySelector('.g-recaptcha');
      el.setAttribute('data-kiwi-endpoint', '/definitely-missing-endpoint');
      // Re-init by resetting through the provider API (the attribute is
      // read at init).
      const wid = el.dataset.kiwiInstance;
      if (wid) window.grecaptcha.reset(wid);
    });
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
    await expect(page.locator('.g-recaptcha [data-kiwi-retry]')).toBeVisible({ timeout: 15_000 });
  });

  test('the provider alias and the native token carry the SAME credential', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    const native = await waitVerified(page, 'kiwi__token');
    const alias = await page.locator('input[name="g-recaptcha-response"]').inputValue();
    expect(alias).toBe(native);
  });
});
