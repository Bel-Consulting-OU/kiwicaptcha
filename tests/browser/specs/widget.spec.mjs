import { test, expect } from '@playwright/test';

test.describe('KiwiCaptcha browser solver', () => {
  async function solveAndVerify(page, algorithm) {
    await page.goto(`/?algorithm=${algorithm}`);
    const tokenInput = page.locator('[data-kiwi-token]');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await tokenInput.inputValue();
    expect(token.length).toBeGreaterThan(0);

    const resp = await page.request.post('http://127.0.0.1:8085/verify', {
      data: { token },
    });
    const body = await resp.json();
    expect(body.ok, `verify must accept the browser-solved ${algorithm} token (${body.code})`).toBe(true);
  }

  test('SHA-256 WASM solve verifies end-to-end', async ({ page }) => {
    await solveAndVerify(page, 'sha256');
  });

  test('SHA-256 JS fallback solves without WASM (strict CSP without wasm-unsafe-eval)', async ({ page }) => {
    // The strict-CSP page lacks 'wasm-unsafe-eval': WebAssembly compilation is
    // blocked, so the driver must fall back to the pure-JS SHA-256 solver.
    await page.goto('/?csp=strict');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 90_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('Argon2id WASM solve verifies end-to-end', async ({ page }) => {
    await solveAndVerify(page, 'argon2id');
  });

  test('Privacy Strict: zero external requests and empty telemetry', async ({ page }) => {
    const external = [];
    page.on('request', (req) => {
      const url = new URL(req.url());
      if (url.origin !== 'http://127.0.0.1:8085') external.push(req.url());
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const parts = atob(token).split('.');
    expect(JSON.parse(parts[3])).toEqual({});
    expect(external).toEqual([]);
  });
});
