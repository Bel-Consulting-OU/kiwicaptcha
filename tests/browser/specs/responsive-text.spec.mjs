import { test, expect } from '@playwright/test';

// Narrow-container status-text regression gate (the mobile ellipsis
// defect). Meaningful status text must never be clipped with
// text-overflow: ellipsis or refused a wrap: a 240px sidebar on a
// desktop browser (or a small phone) must keep every localized word,
// such as "Kontrola bezpieczeństwa" or the long failure/help messages.
// Box-visibility and page-scrollbar checks alone cannot see ellipsized
// text; this suite proves real glyph fit:
//
// This suite measures the container box itself (not the viewport) at
// 240/280/320px, across English, German, French, Portuguese, Polish and
// Arabic, and proves real glyph fit:
//   - getComputedStyle(el).textOverflow !== 'ellipsis'
//   - white-space wraps (normal)
//   - el.scrollWidth <= el.clientWidth + 1
//   - el.scrollHeight <= el.clientHeight + 1
//   - a Range over the text yields client rects inside the visible box
//   - the widget box stays inside its container
// States: done, connecting (held challenge), failed, worker-unavailable
// and solver-mismatch ("solver-version-error"), plus a 2x font scale at
// the narrow widths. Runs on Chromium, Firefox and WebKit through
// playwright.a11y.config.mjs.

const WIDTHS = [240, 280, 320];
const ALL_LANGUAGES = ['en', 'de', 'fr', 'pt', 'pl', 'ar'];
const LONG_LANGUAGES = ['de', 'pl', 'ar'];

async function measureTextFit(page, selector) {
  return page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return { missing: true };
    const cs = getComputedStyle(el);
    const elRect = el.getBoundingClientRect();
    const range = document.createRange();
    range.selectNodeContents(el);
    const rects = [...range.getClientRects()];
    // Horizontal overflow is a hard 1px bound (wrapping must keep the
    // text inside the element). Vertically the glyph ink extents can
    // round a couple of pixels beyond the CSS line box in Firefox for
    // Arabic; a genuinely clipped line overflows by a full line-height
    // (13-28px), so 3px keeps the gate sharp.
    const clipped = rects.some(
      (r) => r.right > elRect.right + 1 || r.left < elRect.left - 1 || r.bottom > elRect.bottom + 3 || r.top < elRect.top - 3,
    );
    const container = el.closest('.kiwi-container');
    const widget = el.closest('[data-kiwi-widget]');
    return {
      text: (el.textContent || '').trim(),
      textOverflow: cs.textOverflow,
      whiteSpace: cs.whiteSpace,
      overflowVisible: cs.overflowY === 'visible',
      scrollFitsX: el.scrollWidth <= el.clientWidth + 1,
      // Vertical font-metric rounding: Firefox reports the Arabic glyph
      // ink extents a couple of pixels beyond the CSS line box even
      // though nothing is clipped (overflow stays visible and the Range
      // rects stay inside). A genuinely clipped line overflows by a
      // full line-height (13-28px), so a 3px tolerance keeps the gate
      // sharp while tolerating engine rounding.
      scrollFitsY: el.scrollHeight <= el.clientHeight + 3,
      clipped,
      rects: rects.length,
      widgetFits:
        widget && container
          ? widget.getBoundingClientRect().right <= container.getBoundingClientRect().right + 1
          : true,
    };
  }, selector);
}

async function assertTextFits(page, label) {
  for (const sel of ['[data-kiwi-label]', '[data-kiwi-info]']) {
    const m = await measureTextFit(page, sel);
    expect(m.missing, `${label} ${sel} exists`).not.toBe(true);
    expect(m.text.length, `${label} ${sel} carries real text`).toBeGreaterThan(0);
    expect(m.textOverflow, `${label} ${sel} never ellipsizes`).not.toBe('ellipsis');
    expect(m.whiteSpace, `${label} ${sel} wraps`).toBe('normal');
    expect(m.overflowVisible, `${label} ${sel} never hides overflow`).toBe(true);
    expect(m.scrollFitsX, `${label} ${sel} scrollWidth fits`).toBe(true);
    expect(m.scrollFitsY, `${label} ${sel} scrollHeight fits`).toBe(true);
    expect(m.clipped, `${label} ${sel} Range glyph rects stay inside the element`).toBe(false);
    expect(m.rects, `${label} ${sel} has measurable glyph rects`).toBeGreaterThan(0);
    expect(m.widgetFits, `${label} widget fits its container`).toBe(true);
  }
}

async function setContainerWidth(page, width) {
  await page.evaluate((w) => {
    const container = document.querySelector('.kiwi-container');
    container.style.width = `${w}px`;
    container.style.maxWidth = `${w}px`;
  }, width);
}

async function assertAcrossWidths(page, label) {
  for (const width of WIDTHS) {
    await setContainerWidth(page, width);
    await assertTextFits(page, `${label} @${width}px`);
  }
}

async function assertFontScale(page, label) {
  await page.evaluate(() => {
    document.querySelector('.kiwi-container').style.setProperty('--kiwi-font-scale', '2');
  });
  for (const width of [240, 320]) {
    await setContainerWidth(page, width);
    await assertTextFits(page, `${label} 2x-scale @${width}px`);
  }
}

test.describe('narrow-container status text never clips', () => {
  test('done state: 240/280/320px containers across six languages', async ({ page }) => {
    for (const lang of ALL_LANGUAGES) {
      await page.goto(`/?lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
      await assertAcrossWidths(page, `${lang} done`);
    }
  });

  test('connecting state: held challenge across RTL and long-word languages', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      let release;
      const held = new Promise((resolvePromise) => {
        release = resolvePromise;
      });
      const route = async (r) => {
        await held;
        await r.abort().catch(() => {});
      };
      await page.route('**/challenge', route);
      await page.goto(`/?lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'connecting', { timeout: 30_000 });
      await assertAcrossWidths(page, `${lang} connecting`);
      release();
      await page.unroute('**/challenge', route);
      await page.goto('about:blank');
    }
  });

  test('failed state: 503 challenge across RTL and long-word languages', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      await page.route('**/challenge', async (route) => {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      });
      await page.goto(`/?lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
      await assertAcrossWidths(page, `${lang} failed`);
      await page.unroute('**/challenge');
    }
  });

  test('worker-unavailable state: failing runtime fetch across RTL and long-word languages', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      await page.route('**/assets/runtime*.js', async (route) => {
        await route.fulfill({ status: 500, contentType: 'application/javascript', body: 'boom' });
      });
      await page.goto(`/?assets=files&algorithm=argon2id&lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:worker-unavailable', { timeout: 60_000 });
      await assertAcrossWidths(page, `${lang} worker-unavailable`);
      await page.unroute('**/assets/runtime*.js');
    }
  });

  test('solver-version-error state: stale worker build id across RTL and long-word languages', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      await page.goto(`/?worker-stale=1&algorithm=argon2id&lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:solver-mismatch', { timeout: 60_000 });
      await assertAcrossWidths(page, `${lang} solver-mismatch`);
    }
  });

  test('2x font scale at the narrowest container widths still fits', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      await page.goto(`/?lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
      await assertFontScale(page, `${lang} done`);
    }
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    await page.goto('/?lang=de');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
    await assertFontScale(page, 'de failed');
  });
});
