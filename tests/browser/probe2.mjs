import { chromium } from '@playwright/test';
const base = process.argv[2] || 'http://127.0.0.1:8091';
const query = process.argv[3] || '?assets=files&bits=20';
const label = process.argv[4] || query;
const browser = await chromium.launch();
const page = await browser.newPage();
const errs = [];
page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') errs.push(m.type() + ': ' + m.text()); });
page.on('pageerror', (e) => errs.push('PAGEERROR: ' + e));
const t0 = Date.now();
await page.goto(base + query);
await page.waitForFunction(() => {
  const el = document.querySelector('[data-kiwi-widget]');
  if (!el) return false;
  const st = el.getAttribute('data-state');
  return st === 'done' || st === 'failed';
}, null, { timeout: 120000 });
const ms = Date.now() - t0;
const token = await page.evaluate(() => document.querySelector('[data-kiwi-token]').value);
let dur = null;
if (token) { try { dur = Buffer.from(token, 'base64').toString('utf8').split('.')[2]; } catch (e) {} }
console.log(JSON.stringify({ label, state: await page.evaluate(() => document.querySelector('[data-kiwi-widget]').getAttribute('data-state')), ms, dur, errs }, null, 1));
await browser.close();
