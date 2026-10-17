import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// The shipped WebAuthn ceremony asset is served by the bundle and by the
// release manifest, but no other spec executes it. This one runs the real
// asset against a mocked navigator.credentials for both ceremonies and
// asserts the exact base64url payload the server expects.
const here = dirname(fileURLToPath(import.meta.url));
const asset = readFileSync(
  resolve(here, '../../../packages/kiwicaptcha-wasm/assets/webauthn-ceremony.js'),
  'utf8',
);

for (const ceremony of ['creation', 'request']) {
  test(`the WebAuthn ${ceremony} ceremony posts the credential payload`, async ({ page }) => {
    await page.setContent(`
      <form id="kiwi-webauthn-form" action="/kiwi-captcha/step-up/complete" method="post">
        <input id="kiwi-webauthn-credential" type="hidden">
        <div id="kiwi-webauthn-status"></div>
      </form>
      <div id="kiwi-webauthn-options" data-options='${JSON.stringify({
        ceremony,
        public_key: {
          challenge: 'AAEC',
          rp: { id: 'example.test', name: 'KiwiCaptcha' },
          user: { id: 'AAEC', name: 'alice', displayName: 'Alice' },
          allowCredentials: [{ id: 'AAEC', type: 'public-key' }],
          excludeCredentials: [{ id: 'AAEC', type: 'public-key' }],
        },
      })}'></div>
    `);

    await page.evaluate(() => {
      const buffer = (bytes) => new Uint8Array(bytes).buffer;
      Object.defineProperty(navigator, 'credentials', {
        configurable: true,
        value: {
          create: async () => ({
            id: 'credential-id',
            rawId: buffer([1, 2, 3]),
            type: 'public-key',
            response: {
              clientDataJSON: buffer([4, 5]),
              attestationObject: buffer([6, 7]),
            },
          }),
          get: async () => ({
            id: 'credential-id',
            rawId: buffer([1, 2, 3]),
            type: 'public-key',
            response: {
              clientDataJSON: buffer([4, 5]),
              authenticatorData: buffer([6]),
              signature: buffer([7]),
              userHandle: buffer([8]),
            },
          }),
        },
      });
      HTMLFormElement.prototype.submit = function submit() {
        window.__kiwiSubmitted = this.querySelector('#kiwi-webauthn-credential').value;
      };
    });

    await page.addScriptTag({ content: asset });
    await page.waitForFunction(() => typeof window.__kiwiSubmitted === 'string');

    const payload = JSON.parse(await page.evaluate(() => window.__kiwiSubmitted));
    expect(payload.id).toBe('credential-id');
    expect(payload.rawId).toBe('AQID');
    expect(payload.type).toBe('public-key');
    expect(payload.response.clientDataJSON).toBe('BAU');
    if (ceremony === 'creation') {
      expect(payload.response.attestationObject).toBe('Bgc');
    } else {
      expect(payload.response.authenticatorData).toBe('Bg');
      expect(payload.response.signature).toBe('Bw');
      expect(payload.response.userHandle).toBe('CA');
    }
  });
}
