import { chromium } from '@playwright/test';
const base = process.argv[2] || 'http://127.0.0.1:8091';
const query = process.argv[3] || '?assets=files&bits=20';
const browser = await chromium.launch();
const page = await browser.newPage();
const logs = [];
page.on('console', (m) => logs.push(m.type() + ': ' + m.text()));
page.on('pageerror', (e) => logs.push('PAGEERROR: ' + e));
const reqs = [];
page.on('request', (r) => reqs.push(r.method() + ' ' + r.url().replace(/^http:\/\/[^/]+/, '')));
await page.goto(base + query, { waitUntil: 'domcontentloaded' }).catch((e) => logs.push('GOTO: ' + e));
const states = [];
for (let i = 0; i < 40; i++) {
  await page.waitForTimeout(2000);
  const snap = await page.evaluate(() => {
    const el = document.querySelector('[data-kiwi-widget]');
    const tokenEl = document.querySelector('[data-kiwi-token]');
    const bar = document.querySelector('[data-kiwi-bar]');
    const labelEl = document.querySelector('[data-kiwi-label]');
    return {
      html: document.documentElement ? document.documentElement.outerHTML.slice(0, 200) : null,
      state: el ? el.getAttribute('data-state') : null,
      started: el ? el.dataset.kiwiStarted || null : null,
      progress: bar ? bar.getAttribute('data-progress') : null,
      label: labelEl ? labelEl.textContent : null,
      token: tokenEl ? tokenEl.value.length : null,
    };
  }).catch((e) => ({ evalError: String(e) }));
  states.push(snap);
  if (snap.state === 'done' || snap.state === 'failed' || snap.evalError) break;
}
console.log(JSON.stringify({ url: page.url(), states, logs: logs.slice(0, 40), reqs: reqs.slice(0, 40) }, null, 1));
await browser.close();
