import { test, expect } from '@playwright/test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Nonce-only Content-Security-Policy qualification for the lazy module
// loader. The page below is served from the fixture origin under a real
// response header whose script-src allows script elements only through
// a nonce: every inline script carries it, and the driver must capture
// its own nonce and copy it onto the <script> element it injects for
// widget-locales.js. (The policy also carries 'wasm-unsafe-eval' so the
// inline glue can compile its wasm; it grants no script source.)
//
// The page is hand-written here (rather than reusing the fixture's
// ?assets= profile) because the fixture has no nonce-only mode and the
// task's spec scope is tests/browser/specs. It reproduces the inline
// tier's asset set from the same files the fixture serves: the wasm
// glue, the driver and the risk module inline with the nonce, the
// widget stylesheet through the content-addressed route, and the
// container markup the driver scans. Only the locales module is lazy,
// so the French label can appear only if the driver's injected script
// carried the nonce.
//
// If the nonce propagation regresses, Chrome refuses the injected
// script (script-src has no 'self'/'unsafe-inline'), the locale pack
// never registers, and both the French label assertion and the
// zero-violation assertion fail.

const specDir = path.dirname(fileURLToPath(import.meta.url));
const ASSETS = path.resolve(specDir, '../../../packages/kiwicaptcha-wasm/assets');

function asset(name) {
  return fs.readFileSync(path.join(ASSETS, name), 'utf8');
}

function assetUrl(key, file, ext) {
  const body = fs.readFileSync(path.join(ASSETS, file), 'utf8');
  const full = crypto.createHash('sha256').update(body, 'utf8').digest('hex');
  return {
    url: `/kiwi-captcha/assets/${key}.${full}.${ext}`,
    sri: 'sha256-' + crypto.createHash('sha256').update(body, 'utf8').digest('base64'),
  };
}

function buildPage(nonce) {
  const locales = assetUrl('locales', 'widget-locales.js', 'js');
  const css = assetUrl('widget', 'widget.css', 'css');

  const inline = (name) => `<script nonce="${nonce}">${asset(name)}</script>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<title>KiwiCaptcha nonce-only CSP page</title>
<link rel="stylesheet" href="${css.url}" integrity="${css.sri}">
</head>
<body>
<div class="kiwi-container" id="kiwicaptcha-root"
 data-kiwi-endpoint="/challenge"
 data-kiwi-scope="login"
 data-kiwi-lang="fr"
 data-kiwi-locales-src="${locales.url}"
 data-kiwi-locales-integrity="${locales.sri}">
  <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
  <div class="kiwi-widget" data-kiwi-widget data-state="idle" role="group" aria-label="KiwiCaptcha security check">
    <div class="kiwi-main">
      <div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>
      <div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>
      <div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
    </div>
    <span class="kiwi-sr-only" data-kiwi-status role="status" aria-live="polite"></span>
  </div>
</div>
${inline('kiwicaptcha-wasm.js')}
${inline('widget-driver.js')}
${inline('widget-risk.js')}
</body>
</html>`;
}

test.describe('lazy module loading under a nonce-only script-src', () => {
  test('the driver copies its CSP nonce onto the injected locales script', async ({ page }) => {
    const nonce = crypto.randomBytes(18).toString('base64');
    const policy = [
      "default-src 'none'",
      // Scripts are nonce-only: no 'self' and no 'unsafe-inline', so the
      // injected locale <script> is allowed solely by the copied nonce.
      // 'wasm-unsafe-eval' lets the inline glue compile its wasm; it
      // grants no script-source permission.
      `script-src 'nonce-${nonce}' 'wasm-unsafe-eval'`,
      "style-src 'self'",
      "connect-src 'self'",
      "img-src 'self' data:",
      "worker-src 'self' blob:",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join('; ');

    // Collect every CSP refusal in the page realm; any violation means
    // a resource the widget needs was blocked (the injected module is
    // the one this spec exists to cover).
    await page.addInitScript(() => {
      window.__cspViolations = [];
      document.addEventListener('securitypolicyviolation', (event) => {
        window.__cspViolations.push({
          directive: event.violatedDirective,
          blockedURI: event.blockedURI,
          source: event.sourceFile,
        });
      });
    });

    const html = buildPage(nonce);
    await page.route('**/nonce-csp-page', async (route) => {
      await route.fulfill({
        status: 200,
        headers: {
          'content-type': 'text/html; charset=UTF-8',
          'content-security-policy': policy,
        },
        body: html,
      });
    });

    const response = await page.goto('/nonce-csp-page');
    expect(response.headers()['content-security-policy']).toContain(`script-src 'nonce-${nonce}'`);

    // A SHA-256 solve runs on the inline glue in this tier; the only
    // dynamic script is the locale pack. Its load is what the nonce
    // propagation makes possible.
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
      timeout: 60_000,
    });

    // The lazy pack registered: the visible label switched from the
    // English fallback to the French pack.
    await expect(page.locator('[data-kiwi-label]')).toHaveText('Contr\u00f4le de s\u00e9curit\u00e9', {
      timeout: 10_000,
    });

    // The injected element carries the page nonce; without the
    // propagation this would be empty and the load would have been
    // refused.
    const injected = await page.evaluate(() => {
      const el = document.querySelector('script[data-kiwi-module="locales"]');
      return el ? { nonce: el.nonce } : null;
    });
    expect(injected, 'the lazy locales script must stay in the document after its load').not.toBeNull();
    // Chrome's nonce hiding empties the content attribute after the IDL
    // property is set; the property is the value CSP matched.
    expect(injected.nonce).toBe(nonce);

    // The solve produced a token and no script load was refused. A
    // wasm-eval refusal (an engine that does not implement
    // 'wasm-unsafe-eval') is not a script-source refusal and still
    // leaves the pure-JS solve intact, so it is not a failure here.
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const violations = await page.evaluate(() => window.__cspViolations);
    expect(violations.filter((v) => v.blockedURI !== 'wasm-eval')).toEqual([]);
  });
});
