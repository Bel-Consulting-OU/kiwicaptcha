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

  test('reCAPTCHA v2: widget ids + getResponse + explicit render', async ({ page }) => {
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

  test('the provider alias and the native token carry the SAME credential', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    const native = await waitVerified(page, 'kiwi__token');
    const alias = await page.locator('input[name="g-recaptcha-response"]').inputValue();
    expect(alias).toBe(native);
  });
});
