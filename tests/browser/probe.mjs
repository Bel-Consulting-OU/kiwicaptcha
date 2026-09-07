import { chromium } from '@playwright/test';

// Direct probe: SHA bits=20 solve band + worker usage + token verification.
const base = process.argv[2] || 'http://127.0.0.1:8091';
const query = process.argv[3] || '?assets=files&bits=20';
const label = process.argv[4] || query;

const browser = await chromium.launch();
const page = await browser.newPage();
const assets = [];
page.on('request', (req) => {
  const u = req.url();
  if (u.includes('/kiwi-captcha/assets/')) assets.push(u.replace(/^http:\/\/[^/]+/, ''));
});
const t0 = Date.now();
await page.goto(base + query);
await page.waitForFunction(() => {
  const el = document.querySelector('[data-kiwi-widget]');
  if (!el) return false;
  const st = el.getAttribute('data-state');
  return st === 'done' || st === 'failed' || st === 'kiwi:worker-unavailable' || st === 'kiwi:execution-unavailable' || st === 'kiwi:solver-mismatch';
}, null, { timeout: 120000 });
const ms = Date.now() - t0;
const state = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').getAttribute('data-state'));
const token = await page.evaluate(() => document.querySelector('[data-kiwi-token]').value);
const workerUsed = await page.evaluate(() => window.__kiwiWorkerUsed === true);
let durations = null;
if (token) {
  try {
    const parts = Buffer.from(token, 'base64').toString('utf8').split('.');
    durations = { parts: parts.length, duration: parts.length >= 3 ? parts[2] : null };
  } catch (e) {}
}
let verify = null;
if (token) {
  const r = await page.request.post(base + '/verify', { data: { token } });
  verify = await r.json();
}
console.log(JSON.stringify({ label, state, ms, tokenLength: token.length, workerUsed, durations, verify, fetches: assets }, null, 1));
await browser.close();
