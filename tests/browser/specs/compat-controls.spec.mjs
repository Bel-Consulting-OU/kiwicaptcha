import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

// The provider-control compatibility architecture.
//
// Invisible-class controls (a button, an input, or
// data-size="invisible") default to deferred execution: the challenge
// starts only when the control is activated, exactly like the
// incumbent invisible reCAPTCHA, and never at page render. The Kiwi
// tree renders into a Kiwi-owned holder adjacent to the control, so a
// void input or an interactive button (the host of Kiwi's native Retry
// control) never contains nested interactive content. The owned
// bindings resolve render/reset/execute/remove, and dynamic insertion
// renders and binds every nested container.
//
// Runs in Chromium, Firefox and WebKit via playwright.a11y.config.mjs
// (and in the default Chromium config too).

const AXE_RULES = [
  'color-contrast', 'aria-allowed-attr', 'aria-hidden-body', 'aria-hidden-focus',
  'aria-progressbar-name', 'button-name', 'focus-order-semantics', 'html-has-lang',
  'label', 'link-in-text-block', 'select-name', 'valid-lang', 'document-title',
];

function collectChallenges(page) {
  const urls = [];
  page.on('request', (req) => {
    if (req.url().includes('/kiwi-captcha/challenge')) urls.push(req.url());
  });
  return urls;
}

async function compatReady(page) {
  await page.waitForFunction(() => window.grecaptcha && typeof window.grecaptcha.execute === 'function');
}

test.describe('KiwiCaptcha provider-control compatibility', () => {
  test('invisible button: the challenge waits for the click, then runs exactly once', async ({ page }) => {
    const challenges = collectChallenges(page);
    await page.goto('/migration/recaptcha-invisible.html');
    const button = page.locator('button.g-recaptcha');
    const widget = page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });

    // Well beyond any normal SHA-256 solve time: nothing may have
    // started, no token may exist, no callback may have fired.
    await page.waitForTimeout(3000);
    expect(challenges.length, 'no challenge may be requested before activation').toBe(0);
    await expect(page.locator('input[name="g-recaptcha-response"]')).toHaveValue('');
    await expect(page.locator('#out')).toHaveText('');

    await button.click();
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    expect(challenges.length, 'exactly one challenge after activation').toBe(1);
    const token = await page.locator('input[name="g-recaptcha-response"]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('button control: the widget lives in an adjacent holder and the full provider surface works', async ({ page }) => {
    const challenges = collectChallenges(page);
    await page.goto('/migration/recaptcha-button.html');
    const control = page.locator('button.g-recaptcha');
    const widget = page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });

    // The control is never a Kiwi container: no widget and, above all,
    // no interactive content (Kiwi's Retry button) nested inside it.
    expect(await control.locator('[data-kiwi-widget]').count()).toBe(0);
    expect(await control.locator('button').count()).toBe(0);
    expect((await control.textContent()).trim()).toBe('Sign in');

    // render() on the already-rendered control returns the same id.
    const ids = await page.evaluate(() => {
      const el = document.querySelector('button.g-recaptcha');
      return { first: window.grecaptcha.render(el), again: window.grecaptcha.render(el) };
    });
    expect(ids.again).toBe(ids.first);
    const id = ids.first;

    await page.evaluate((widgetId) => window.grecaptcha.reset(widgetId), id);
    await expect(widget).toHaveAttribute('data-state', 'pending');
    await page.evaluate((widgetId) => window.grecaptcha.execute(widgetId), id);
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    expect(challenges.length).toBe(1);

    await page.evaluate((widgetId) => window.grecaptcha.remove(widgetId), id);
    await expect(page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]')).toHaveCount(0);
    expect(await control.count(), 'the provider control survives remove()').toBe(1);
    expect((await control.textContent()).trim()).toBe('Sign in');

    // The owned activation listener left with the widget: clicking the
    // control after remove() starts nothing.
    await control.click();
    await page.waitForTimeout(500);
    expect(challenges.length, 'a removed widget must not answer clicks').toBe(1);

    // Re-render through the provider API after remove(): a fresh widget.
    const reRendered = await page.evaluate(() => window.grecaptcha.render(document.querySelector('button.g-recaptcha')));
    expect(reRendered).not.toBe(0);
    await expect(page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]')).toHaveAttribute('data-state', 'pending');
  });

  test('submit input: the control keeps its semantics and the holder carries the widget', async ({ page }) => {
    await page.goto('/migration/recaptcha-input.html');
    const control = page.locator('input.g-recaptcha');
    const widget = page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });

    expect(await control.getAttribute('type')).toBe('submit');
    expect(await control.getAttribute('value')).toBe('Sign in');
    // The input is void: it cannot contain the widget at all.
    expect(await control.locator('[data-kiwi-widget]').count()).toBe(0);

    await control.click();
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await page.locator('input[name="g-recaptcha-response"]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('dynamic insertion: nested subtrees, multiple widgets, reinsertion and a late invisible control', async ({ page }) => {
    const challenges = collectChallenges(page);
    await page.goto('/migration/recaptcha-v2.html');
    await compatReady(page);
    const initial = await page.locator('[data-kiwi-widget]').count();

    // A framework inserting a subtree: the observer must find the
    // containers nested inside the added top-level node, and render
    // several of them from one insertion.
    await page.evaluate(() => {
      const section = document.createElement('section');
      section.id = 'dynamic-subtree';
      section.innerHTML = '<div><div class="g-recaptcha" data-sitekey="6Lc_dyn_one"></div>'
        + '<div class="g-recaptcha" data-sitekey="6Lc_dyn_two"></div></div>';
      document.body.appendChild(section);
    });
    await expect(page.locator('#dynamic-subtree .g-recaptcha [data-kiwi-widget]')).toHaveCount(2, { timeout: 30_000 });

    // Removal and reinsertion of the same subtree keeps the rendered
    // widget (idempotent render, no duplicate).
    await page.evaluate(() => {
      const section = document.getElementById('dynamic-subtree');
      section.remove();
      document.body.appendChild(section);
    });
    await expect(page.locator('#dynamic-subtree .g-recaptcha [data-kiwi-widget]')).toHaveCount(2);

    // A dynamically added invisible button gets the same deferred
    // render and the same owned activation listener as a static one.
    await page.evaluate(() => {
      const button = document.createElement('button');
      button.className = 'g-recaptcha';
      button.type = 'button';
      button.textContent = 'Dynamic sign in';
      button.setAttribute('data-sitekey', '6Lc_dyn_three');
      button.id = 'dynamic-invisible';
      document.body.appendChild(button);
    });
    const dynamicWidget = page.locator('#dynamic-invisible + [data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(dynamicWidget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });
    const before = challenges.length;
    await page.locator('#dynamic-invisible').click();
    await expect(dynamicWidget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    expect(challenges.length, 'the dynamically bound control starts exactly one challenge').toBe(before + 1);

    expect(await page.locator('[data-kiwi-widget]').count()).toBe(initial + 3);
  });

  test('axe: the control migration pages pass the widget-scope rules', async ({ page }) => {
    for (const path of ['/migration/recaptcha-button.html', '/migration/recaptcha-input.html', '/migration/recaptcha-invisible.html']) {
      await page.goto(path);
      await expect(page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]')).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });
      const results = await new AxeBuilder({ page })
        .include('[data-kiwi-compat-holder]')
        .withRules(AXE_RULES)
        .analyze();
      expect(results.violations, `${path}: ${JSON.stringify(results.violations.map((v) => v.id))}`).toEqual([]);
    }
  });

  test('settled execute() promises retire their cancellation hooks', async ({ page }) => {
    await page.goto('/migration/recaptcha-button.html');
    const widget = page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });
    const id = await page.locator('[data-kiwi-compat-holder]').first().evaluate((el) => el.dataset.kiwiInstance);
    expect(typeof id).toBe('string');

    // One deferred solve fanned out into hundreds of execute() callers:
    // every settled promise must remove its own cancellation hook, so
    // the record retains none after completion.
    const result = await page.evaluate(async (widgetId) => {
      const promises = [];
      for (let i = 0; i < 300; i++) promises.push(window.grecaptcha.execute(widgetId));
      const tokens = await Promise.all(promises);
      const record = window.__kiwiCaptchaCore.core.record(widgetId);
      return {
        unique: new Set(tokens).size,
        first: tokens[0],
        pending: record ? record.pendingExecute : 'no-record',
      };
    }, id);
    expect(result.unique, 'all callers must observe the same solution token').toBe(1);
    expect(result.first.length).toBeGreaterThan(0);
    expect(result.pending === null || (Array.isArray(result.pending) && result.pending.length === 0)).toBe(true);
  });
});
