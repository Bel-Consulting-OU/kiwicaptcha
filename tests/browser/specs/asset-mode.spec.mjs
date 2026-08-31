import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';

// The files-mode asset delivery tier (kiwi_captcha.asset_mode "files"):
// versioned immutable first-party asset URLs with exact content hashes,
// long cache lifetimes, SRI, once-per-page dedup, and the lazy heavy
// module — the driver fetches the WASM runtime only when a memory-hard
// challenge arrives, so a plain SHA-256 page pays nothing for the Argon
// machinery. The inline mode stays the default everywhere else; this
// spec pins the files tier end to end against the fixture's asset route.
test.describe('KiwiCaptcha files-mode asset delivery', () => {
  // Collects the asset request URLs into a live array; the assertions
  // filter it at check time (a snapshot at collection time would be
  // empty, since the requests arrive after the page load).
  function collectAssetRequests(page) {
    const urls = [];
    page.on('request', (req) => {
      if (req.url().includes('/kiwi-captcha/assets/')) urls.push(req.url());
    });
    return urls;
  }

  function runtimeCount(all) {
    return all.filter((u) => u.includes('/assets/runtime.')).length;
  }

  function sha256Base64(text) {
    return 'sha256-' + createHash('sha256').update(text, 'utf8').digest('base64');
  }

  test('asset requests carry immutable headers, exact hashes and SRI', async ({ page }) => {
    const assetResponses = [];
    page.on('response', (res) => {
      if (res.url().includes('/kiwi-captcha/assets/')) assetResponses.push(res);
    });
    await page.goto('/?assets=files');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });

    // The page references exactly two assets: the stylesheet and the driver.
    const hrefs = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll('link[rel="stylesheet"]')).map((l) => l.getAttribute('href'));
      const scripts = Array.from(document.querySelectorAll('script[src]')).map((s) => s.getAttribute('src'));
      return links.concat(scripts);
    });
    const assetUrls = hrefs.filter((h) => h.includes('/kiwi-captcha/assets/'));
    expect(assetUrls).toHaveLength(2);
    expect(assetUrls.some((u) => u.endsWith('.css'))).toBe(true);
    expect(assetUrls.some((u) => u.includes('driver.') && u.endsWith('.js'))).toBe(true);

    for (const url of assetUrls) {
      const res = await page.request.get(url);
      expect(res.status(), `the referenced asset must exist: ${url}`).toBe(200);
      const body = await res.body();
      const fullHash = createHash('sha256').update(body).digest('hex');
      const expectedUrl = url.replace(/\.([0-9a-f]{12})\./, '.' + fullHash.slice(0, 12) + '.');
      expect(expectedUrl).toBe(url);

      const headers = res.headers();
      expect(headers['cache-control']).toContain('immutable');
      expect(headers['cache-control']).toContain('max-age=31536000');
      expect(headers['cache-control']).toContain('public');
      expect(headers.etag).toBe(`"${fullHash}"`);
      expect(Number(headers['content-length'])).toBe(body.length);
      expect(headers['content-type']).toMatch(/^(text\/css|application\/javascript)/);

      // The SRI integrity of the emitted tag matches the served bytes.
      const integrity = await page.evaluate(
        (assetUrl) => {
          const el = document.querySelector(`link[href="${assetUrl}"]`) || document.querySelector(`script[src="${assetUrl}"]`);
          return el ? el.getAttribute('integrity') : null;
        },
        url,
      );
      expect(integrity, `the emitted tag must carry the SRI of ${url}`).toBe(sha256Base64(body.toString('utf8')));
    }
  });

  test('an unknown hash is a 404 and a matching ETag revalidates to 304', async ({ page }) => {
    await page.goto('/?assets=files');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const driverUrl = await page.evaluate(() => {
      const s = document.querySelector('script[src*="/kiwi-captcha/assets/driver."]');
      return s ? s.getAttribute('src') : null;
    });
    expect(driverUrl).toBeTruthy();

    const good = await page.request.get(driverUrl);
    expect(good.status()).toBe(200);
    const etag = good.headers().etag;
    const body = await good.body();

    // A wrong hash under the same asset name is a 404 (never stale bytes).
    const wrongHash = body.toString('utf8').slice(0, 12).replace(/[0-9a-f]/g, (c) => (c === '0' ? '1' : '0'));
    const badUrl = driverUrl.replace(/\.([0-9a-f]{12})\./, '.' + wrongHash + '.');
    const bad = await page.request.get(badUrl);
    expect(bad.status()).toBe(404);

    // Revalidation: the content-hash ETag returns 304 with no body.
    const revalidated = await page.request.get(driverUrl, { headers: { 'If-None-Match': etag } });
    expect(revalidated.status()).toBe(304);
    expect((await revalidated.body()).length).toBe(0);
  });

  test('each emitted asset appears exactly once on a two-widget page (dedup)', async ({ page }) => {
    await page.goto('/?assets=files&widgets=2');
    await expect(page.locator('[data-kiwi-widget]')).toHaveCount(2);

    const counts = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll('link[rel="stylesheet"][href*="/kiwi-captcha/assets/"]'));
      const scripts = Array.from(document.querySelectorAll('script[src*="/kiwi-captcha/assets/"]'));
      const runtimeTags = Array.from(document.querySelectorAll('script[src*="/assets/runtime."]'));
      return {
        css: links.length,
        driver: scripts.filter((s) => s.getAttribute('src').includes('driver.')).length,
        runtimeTags: runtimeTags.length,
        runtimeSrc: Array.from(document.querySelectorAll('[data-kiwi-runtime-src]')).map((el) => el.getAttribute('data-kiwi-runtime-src')),
      };
    });
    expect(counts.css).toBe(1);
    expect(counts.driver).toBe(1);
    expect(counts.runtimeTags).toBe(0);
    expect(counts.runtimeSrc).toHaveLength(2);
    expect(new Set(counts.runtimeSrc).size).toBe(1);

    await expect(page.locator('[data-kiwi-widget]').first()).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    await expect(page.locator('[data-kiwi-widget]').nth(1)).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
  });

  test('a SHA challenge triggers no runtime asset fetch (lazy)', async ({ page }) => {
    const all = collectAssetRequests(page);
    await page.goto('/?assets=files');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
    expect(runtimeCount(all), 'a SHA-256 solve must never download the Argon machinery').toBe(0);
  });

  test('an Argon challenge triggers exactly one runtime fetch and verifies', async ({ page }) => {
    const all = collectAssetRequests(page);
    await page.goto('/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    expect(runtimeCount(all), 'exactly one runtime fetch for the memory-hard challenge').toBe(1);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('adaptive escalation: a SHA page receiving an Argon challenge fetches the runtime exactly once and verifies', async ({ page }) => {
    const all = collectAssetRequests(page);
    // The page asks for sha256; the fixture escalates to argon2id (the
    // server-side adaptive decision). The driver accepts the stronger
    // algorithm and lazily fetches the runtime only now.
    await page.goto('/?assets=files&escalate=argon');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    expect(runtimeCount(all), 'the runtime fetch must happen exactly once, at the Argon challenge').toBe(1);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('two Argon widgets share exactly one runtime fetch', async ({ page }) => {
    const all = collectAssetRequests(page);
    await page.goto('/?assets=files&widgets=2&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]').first()).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(page.locator('[data-kiwi-widget]').nth(1)).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    expect(runtimeCount(all), 'the shared per-URL promise must deduplicate the runtime fetch').toBe(1);
    const tokens = [];
    for (const el of await page.locator('[data-kiwi-token]').all()) {
      tokens.push(await el.inputValue());
    }
    expect(new Set(tokens).size).toBe(2);
    for (const token of tokens) {
      const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
      expect((await resp.json()).ok).toBe(true);
    }
  });

  test('a failing runtime fetch is a controlled worker-unavailable state with bounded retries', async ({ page }) => {
    let runtimeHits = 0;
    await page.route('**/assets/runtime*.js', async (route) => {
      runtimeHits++;
      await route.fulfill({ status: 500, contentType: 'application/javascript', body: 'boom' });
    });
    await page.goto('/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:worker-unavailable', { timeout: 60_000 });

    // The bounded retry: the initial attempt plus two retries, then the
    // controlled state — never an infinite loop, never a main-thread
    // Argon hash.
    expect(runtimeHits).toBe(3);
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
  });
});
