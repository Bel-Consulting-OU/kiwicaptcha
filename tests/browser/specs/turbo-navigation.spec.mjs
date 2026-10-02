import { test, expect } from '@playwright/test';

// The idempotency guard must not break Turbo/htmx navigation. In files
// mode the driver script is emitted once per rendered page, but Turbo
// re-executes body scripts on every navigation, and htmx processes
// swapped subtrees. The first copy owns the API/bridge; every later
// copy must rescan the (new) DOM through the bridge instead of
// returning silently, or a widget reached via navigation never starts
// and the form submits an empty token.

async function driverSrc(page) {
  return page.evaluate(() => {
    const script = [...document.querySelectorAll('script[src]')].find((el) => el.src.includes('/driver.'));
    return script ? script.src : null;
  });
}

// A Turbo/htmx navigation replaces the container with the server's
// rendered markup (endpoint/runtime/module attributes AND the widget
// skeleton: status, hint, token input). Clone the live container's
// markup and strip only the per-instance initialization markers, which
// is exactly what the server re-render produces on the next page.
async function freshContainerMarkup(page, containerId) {
  await page.evaluate((id) => {
    const origin = document.querySelector('.kiwi-container');
    const clone = origin.cloneNode(true);
    clone.id = id;
    clone.querySelectorAll('[data-kiwi-instance]').forEach((el) => el.removeAttribute('data-kiwi-instance'));
    const widget = clone.querySelector('[data-kiwi-widget]');
    widget.removeAttribute('data-kiwi-started');
    // The server re-render ships an idle widget with no token: strip the
    // cloned finish state so the assertions can only pass if this
    // generation actually initialized and solved.
    widget.removeAttribute('data-state');
    for (const input of clone.querySelectorAll('[data-kiwi-token]')) input.value = '';
    document.body.appendChild(clone);
  }, containerId);
}

test.describe('driver reuse under Turbo/htmx navigation', () => {
  test('a Turbo navigation re-executes the driver and the newly parsed widget starts', async ({ page }) => {
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    await page.goto('/?assets=files&bits=4');
    await expect(page.locator('#kiwicaptcha-root [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    expect(await page.evaluate(() => typeof window.__kiwiCaptchaCore.core.scan)).toBe('function');

    // Turbo replaces the body and re-executes its scripts: a new widget
    // appears, then the driver copy runs again.
    await freshContainerMarkup(page, 'kiwicaptcha-turbo');
    const src = await driverSrc(page);
    expect(src, 'the files-mode page must emit a driver script src').toBeTruthy();
    await page.addScriptTag({ url: src });

    await expect(page.locator('#kiwicaptcha-turbo [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('#kiwicaptcha-turbo [data-kiwi-token]').inputValue();
    expect(token.length, 'the navigated widget must write a real token, never submit empty').toBeGreaterThan(0);
    expect(await page.evaluate(() => window.__kiwiDriverReused), 'the guard must have taken the reuse branch').toBe(1);
    // The original widget is untouched and still verified.
    expect(await page.locator('#kiwicaptcha-root [data-kiwi-widget]').getAttribute('data-state')).toBe('done');
    expect(pageErrors).toEqual([]);
  });

  test('an htmx body swap re-runs the driver and initializes the swapped widget', async ({ page }) => {
    await page.goto('/?assets=files&bits=4');
    await expect(page.locator('#kiwicaptcha-root [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    // htmx swaps the subtree's markup, then processes scripts inside it.
    await page.evaluate(() => {
      const container = document.querySelector('.kiwi-container');
      const replacement = container.cloneNode(true);
      replacement.id = 'kiwicaptcha-htmx';
      replacement.querySelectorAll('[data-kiwi-instance]').forEach((el) => el.removeAttribute('data-kiwi-instance'));
      const widget = replacement.querySelector('[data-kiwi-widget]');
      widget.removeAttribute('data-kiwi-started');
      widget.removeAttribute('data-state');
      for (const input of replacement.querySelectorAll('[data-kiwi-token]')) input.value = '';
      container.replaceWith(replacement);
    });
    const src = await driverSrc(page);
    await page.addScriptTag({ url: src });

    await expect(page.locator('#kiwicaptcha-htmx [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('#kiwicaptcha-htmx [data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    expect(await page.evaluate(() => window.__kiwiDriverReused)).toBe(1);
  });
});
