import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Polymorphic decoy rendering: the driver renders the
// authenticated server-issued decoy (honeypot) name with one of six
// bounded rendering strategies chosen per challenge as a pure function of
// the name (FNV-1a 32-bit hash, mirrored from the driver). This spec
// drives every strategy deterministically through the fixture's
// ?decoy=1&decoyname=<name> knob and asserts the invariants that hold
// for ALL of them:
//  - exactly ONE decoy input carrying the authenticated name
//  - invisible to humans (display:none, hidden attribute, or offscreen)
//  - non-interactive: tabindex=-1, aria-hidden, never in the tab order
//  - autofill-safe: never a labelled visible field, autocomplete off or
//    new-password
//  - axe-clean (no WCAG violations) per strategy
//  - lifecycle: reset removes the decoy, reissue replaces it with
//    exactly one fresh decoy, unarmed issuance renders no decoy at all
// The evidence semantics (filled exact name rides the next challenge
// request as honeypot markers) are covered by risk-v2.spec.mjs.

const specDir = path.dirname(fileURLToPath(import.meta.url));

function assetPath(name) {
  const candidates = [
    path.resolve(specDir, '../../../packages/kiwicaptcha-wasm/assets', name),
    path.resolve(specDir, '../../../assets', name),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(`cannot locate ${name}; tried ${candidates.join(', ')}`);
}

// One grammar name per strategy, precomputed with the driver's exact
// FNV-1a variant function (verified below before any DOM assertion).
const STRATEGIES = [
  { id: 0, name: 'secondary_contact_number' },
  { id: 1, name: 'secondary_contact_email' },
  { id: 2, name: 'secondary_contact_name' },
  { id: 3, name: 'secondary_contact_phone' },
  { id: 4, name: 'secondary_contact_url' },
  { id: 5, name: 'secondary_contact_line' },
];

function fnv1a32(name) {
  let h = 0x811c9dc5;
  for (let i = 0; i < name.length; i++) {
    h ^= name.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

const AXE_RULES = [
  'color-contrast', 'aria-allowed-attr', 'aria-hidden-body', 'aria-hidden-focus',
  'aria-progressbar-name', 'button-name', 'focus-order-semantics', 'html-has-lang',
  'label', 'link-in-text-block', 'select-name', 'valid-lang', 'document-title',
];

async function solve(page, timeout = 60_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

// The decoy element facts a strategy must satisfy, read in one browser
// round trip so the assertions below are race-free.
async function decoyFacts(page, name) {
  return page.evaluate((n) => {
    const token = document.querySelector('[data-kiwi-token]');
    const input = document.querySelector(`input[name="${n}"]`);
    if (!input) return { present: false };
    const cs = getComputedStyle(input);
    const host = token ? token.parentNode : null;
    const wrap = input.parentNode;
    return {
      present: true,
      type: input.getAttribute('type'),
      tabIndex: input.tabIndex,
      ariaHidden: input.getAttribute('aria-hidden'),
      autocomplete: input.getAttribute('autocomplete'),
      value: input.value,
      display: cs.display,
      position: cs.position,
      left: cs.left,
      hiddenAttr: input.hasAttribute('hidden'),
      wrapped: !!(host && wrap !== host && wrap.className === 'kiwi-form-aux'),
      inHost: !!(host && host.contains(input)),
      // beforeToken: true when the decoy (or its wrapper) precedes the
      // token input among the host's element children.
      beforeToken: (() => {
        if (!host) return false;
        const els = Array.prototype.slice.call(host.children);
        return els.indexOf(input.parentNode === host ? input : wrap) < els.indexOf(token);
      })(),
      tokenParentChildren: token ? token.parentNode.children.length : 0,
    };
  }, name);
}

test.describe('KiwiCaptcha polymorphic decoy rendering', () => {
  for (const strategy of STRATEGIES) {
    test(`strategy ${strategy.id}: one authenticated decoy input, invisible, non-interactive, axe-clean`, async ({ page }) => {
      expect(fnv1a32(strategy.name) % 6, 'the strategy fixture must match the driver variant function').toBe(strategy.id);
      await page.goto(`/?decoy=1&decoyname=${strategy.name}`);
      await solve(page);

      // The tracked name on the widget is the authenticated name, and
      // exactly one input carries it.
      const tracked = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiDecoyName);
      expect(tracked).toBe(strategy.name);
      await expect(page.locator(`input[name="${strategy.name}"]`)).toHaveCount(1);

      const facts = await decoyFacts(page, strategy.name);
      expect(facts.present).toBe(true);
      expect(facts.type).toBe('text');
      expect(facts.tabIndex).toBe(-1);
      expect(facts.ariaHidden).toBe('true');
      expect(facts.value).toBe('');
      expect(facts.inHost, 'the decoy must live inside the token form host').toBe(true);

      // Invisible to humans under every strategy.
      const invisible = facts.display === 'none' || facts.hiddenAttr || facts.position === 'absolute';
      expect(invisible, `the decoy must be invisible (display=${facts.display}, hidden=${facts.hiddenAttr}, position=${facts.position})`).toBe(true);

      // Strategy-specific shape.
      if (strategy.id === 0) {
        expect(facts.display).toBe('none');
        expect(facts.autocomplete).toBe('off');
        expect(facts.wrapped).toBe(false);
        expect(facts.beforeToken).toBe(false);
      } else if (strategy.id === 1) {
        expect(facts.display).toBe('none');
        expect(facts.autocomplete).toBe('off');
        expect(facts.wrapped).toBe(true);
        expect(facts.beforeToken).toBe(false);
      } else if (strategy.id === 2) {
        expect(facts.hiddenAttr).toBe(true);
        expect(facts.autocomplete).toBe('off');
        expect(facts.wrapped).toBe(false);
        expect(facts.beforeToken).toBe(true);
      } else if (strategy.id === 3) {
        expect(facts.position).toBe('absolute');
        expect(facts.left).toBe('-9999px');
        expect(facts.autocomplete).toBe('new-password');
        expect(facts.wrapped).toBe(false);
      } else if (strategy.id === 4) {
        expect(facts.hiddenAttr).toBe(true);
        expect(facts.autocomplete).toBe('off');
        expect(facts.wrapped).toBe(true);
        expect(facts.beforeToken).toBe(true);
      }

      // Axe-clean: no WCAG violations from the rendered strategy.
      const results = await new AxeBuilder({ page }).withRules(AXE_RULES).analyze();
      expect(results.violations, `strategy ${strategy.id}: ${JSON.stringify(results.violations, null, 2)}`).toEqual([]);
    });
  }

  test('strategy 5 (deferred): the decoy input appears only after the first solve completes', async ({ page }) => {
    // The deferred strategy records the name at issuance but creates the
    // input only when the solve completes. With an argon2id challenge the
    // solving window is long enough to prove the input is absent during
    // the solve and present afterwards.
    const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
    const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<form id="f" action="/form-submit" method="post">
<div class="kiwi-container" id="kiwicaptcha-root" data-kiwi-endpoint="/challenge?decoy=1&decoyname=secondary_contact_line" data-kiwi-scope="login" data-kiwi-algorithm="argon2id">
  <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
  <div class="kiwi-widget" data-kiwi-widget data-state="idle" role="status" aria-live="polite">
    <div class="kiwi-icon-wrapper"><svg></svg><div class="kiwi-glow"></div></div>
    <div class="kiwi-main">
      <div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>
      <div class="kiwi-track"><div class="kiwi-bar" data-kiwi-bar></div></div>
      <div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
    </div>
  </div>
</div>
</form>
<script>${glue}</script><script>${driver}</script></body></html>`;
    await page.route('**/argon-form', (route) =>
      route.fulfill({ contentType: 'text/html', body: html })
    );
    await page.goto('/argon-form');

    // While the widget is solving, the deferred input must not exist.
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'solving',
      null,
      { timeout: 60_000 }
    );
    const duringSolve = await page.evaluate(() => !!document.querySelector('input[name="secondary_contact_line"]'));
    expect(duringSolve, 'the deferred decoy must not exist during the first solve').toBe(false);

    await solve(page);
    await expect(page.locator('input[name="secondary_contact_line"]'), 'the deferred decoy appears after the solve').toHaveCount(1);
    await expect(page.locator('input[name="secondary_contact_line"]')).toHaveAttribute('tabindex', '-1');
  });

  test('unarmed issuance renders no decoy input and tracks no name', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const state = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      return {
        tracked: w.dataset.kiwiDecoyName || null,
        deferred: w.dataset.kiwiDecoyDeferred || null,
        // Decoy inputs are grammar-shaped names the driver rendered; the
        // kiwi_* inputs (token, request binding) are driver-owned fields,
        // never decoys.
        decoys: Array.from(document.querySelectorAll('input')).filter((el) => /^[a-z]+_[a-z]+_[a-z]+$/.test(el.name) && !/^kiwi_/.test(el.name)).length,
      };
    });
    expect(state.tracked).toBeNull();
    expect(state.deferred).toBeNull();
    expect(state.decoys).toBe(0);
  });

  test('reset removes the rendered decoy; reissue replaces it with exactly one fresh decoy', async ({ page }) => {
    // The reissue flow is driven by the fixture route override: the
    // first challenge response carries names[0], the re-solve after the
    // reset carries names[1]. The two names map to different rendering
    // strategies (2 and 4), so the replacement is proven across
    // strategies, not just within one.
    const names = ['secondary_contact_name', 'secondary_contact_url'];
    let issued = 0;
    await page.route('**/challenge*', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      data.decoy_field = names[issued % names.length];
      issued++;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    });

    await page.goto('/?decoy=1');
    await solve(page);
    const oldName = names[0];
    const stale = page.locator(`input[name="${oldName}"]`);
    await expect(stale).toHaveCount(1);
    await stale.evaluate((el) => {
      el.value = 'bot@example.com';
    });

    // Reset: the rendered decoy input leaves the form synchronously.
    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await expect(stale, 'the reset must remove the rendered decoy input').toHaveCount(0);

    // The reset-triggered re-solve auto-runs against the fixture: the
    // fresh challenge carries names[1] and renders exactly one decoy
    // input — never a stale echo of the prior one.
    await solve(page);
    const freshName = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiDecoyName);
    expect(freshName).toBe(names[1]);
    await expect(page.locator(`input[name="${freshName}"]`)).toHaveCount(1);
    await expect(page.locator(`input[name="${oldName}"]`), 'the stale decoy must never linger').toHaveCount(0);
    const totalDecoys = await page.evaluate(() => {
      const host = document.querySelector('[data-kiwi-token]').parentNode;
      return Array.from(host.querySelectorAll('input')).filter((el) => /^[a-z]+_[a-z]+_[a-z]+$/.test(el.name) && !/^kiwi_/.test(el.name)).length;
    });
    expect(totalDecoys, 'exactly one decoy input after the reissue').toBe(1);
  });
});
