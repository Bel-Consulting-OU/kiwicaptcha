import { test, expect } from '@playwright/test';

// Audit finding 1: an enabled telemetry mode (data-kiwi-telemetry="full"
// or "minimal" on the container) starts the lazy widget-telemetry.js
// module load OPPORTUNISTICALLY at init, but the challenge flow NEVER
// awaits it. The session attaches only when the module registers BEFORE
// this generation's challenge request went out (the driver's requestSent
// flag, checked in the load's .then()); once the request is sent, the
// generation solves with the normal empty "{}" telemetry stub — never a
// half-session mid-solve. An unloadable module degrades to the same
// stub. The files tier delivers the module descriptor
// (data-kiwi-telemetry-src/-integrity), so these cases drive the real
// lazy load; the fixture emits the opt-in attribute through the
// ?telemetry=full|minimal knob.

const TELEMETRY_URL_MARKER = '/assets/telemetry.';

function telemetryRequests(page) {
  const requests = [];
  page.on('request', (request) => {
    if (request.url().includes(TELEMETRY_URL_MARKER)) requests.push(request);
  });
  return requests;
}

// The token wire shape: base64(nonce.counter.duration.telemetry[.evidence]).
// Segment 3 is the JSON telemetry blob.
function tokenTelemetry(token) {
  const parts = atob(token).split('.');
  expect(parts.length, 'the token must carry the telemetry segment').toBeGreaterThanOrEqual(4);
  return JSON.parse(parts[3]);
}

test.describe('Lazy telemetry module acquisition (audit finding 1)', () => {
  test('an enabled mode never gates the challenge request: the POST fires while the module request is held, and the late module is refused for this generation', async ({ page }) => {
    const held = [];
    await page.route('**/assets/telemetry*.js', async (route) => {
      held.push(route);
    });
    const challengeSeen = page.waitForRequest(
      (r) => r.method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'),
      { timeout: 30_000 }
    );
    await page.goto('/?assets=files&telemetry=full', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the telemetry fetch must be in flight').toBe(1);

    // The challenge request is sent while the module request is still
    // held: issuance never waits for the session module.
    await challengeSeen;
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the solve must mint a token while the module is held').toBeGreaterThan(0);
    expect(tokenTelemetry(token), 'a generation that sent its request before the module registered must embed the empty telemetry stub').toEqual({});

    // Release the module: it registers AFTER the request was sent, so
    // the requestSent guard refuses the attach for this generation.
    for (const route of held.splice(0)) {
      await route.continue().catch(() => {});
    }
    await page.waitForLoadState('load');
    const injected = await page.evaluate(() => {
      const script = document.querySelector('script[data-kiwi-module="telemetry"]');
      return script ? script.getAttribute('src') : null;
    });
    expect(injected, 'the released module script must exist in the page').toBeTruthy();
    expect(injected, 'the released module script must be the telemetry asset').toContain('/assets/telemetry.');
    // The token is a written credential: its telemetry segment cannot
    // change after the fact, and the stub is the generation's record.
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe(token);
  });

  test('a hung or missing telemetry module degrades to the empty stub: three bounded attempts, no page error, the solve is unaffected', async ({ page }) => {
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    let hits = 0;
    await page.route('**/assets/telemetry*.js', async (route) => {
      hits++;
      await route.fulfill({ status: 404, contentType: 'application/javascript', body: 'not found' });
    });
    await page.goto('/?assets=files&telemetry=minimal');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect.poll(() => hits, 'the missing module must repeat through the bounded retries').toBe(3);

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the widget must solve without the telemetry module').toBeGreaterThan(0);
    expect(tokenTelemetry(token), 'the unloadable module must leave the empty telemetry stub').toEqual({});
    expect(pageErrors, 'the telemetry degradation must raise no page error').toEqual([]);

    const resp = await page.request.post('http://127.0.0.1:8085/verify', {
      data: { token, scope: 'login' },
    });
    const body = await resp.json();
    expect(body.ok, `the telemetry-off solve must verify (got ${body.code})`).toBe(true);
  });

  test('an enabled mode with the module present still loads exactly once and never delays the solve', async ({ page }) => {
    const requests = telemetryRequests(page);
    await page.goto('/?assets=files&telemetry=full');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect.poll(() => requests.length, 'the module must load exactly once').toBe(1);
    expect(requests[0].resourceType(), 'the module must ride a script element load').toBe('script');
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    // The auto-run generation sent its request before the module could
    // register (the local asset usually lands mid-solve at the earliest),
    // so the stub semantics hold; the module itself is registered.
    expect(tokenTelemetry(token)).toEqual({});
  });
});
