# @kiwicaptcha/angular

Angular KiwiCaptcha widget: the standalone `KiwiCaptcha` component
(Ivy, signals, OnPush, zone-safe) and the injectable
`KiwiCaptchaService`, both on the shared `@kiwicaptcha/client-core`.

## The four-setting quickstart

```ts
import { KiwiCaptcha } from "@kiwicaptcha/angular";

@Component({
  standalone: true,
  imports: [KiwiCaptcha],
  template: `
    <kiwi-captcha
      endpoint="/api/kcaptcha/challenge"
      sitekey="pk-live-1"
      scope="login"
      lang="en"
      (verified)="onVerified($event)"
      (failed)="onFailed($event)"
      (expired)="captcha.reset()"
    />
  `,
})
export class LoginForm {
  private readonly captcha = viewChild.required(KiwiCaptcha);

  onVerified(detail: KiwiVerifiedDetail): void {
    this.submit(detail.token);
  }
}
```

## Component and service

- Inputs: the four-setting quickstart (`endpoint`, `sitekey`, `scope`,
  `lang`), the core's remaining render options (`theme`, `action`,
  `cData`, `chainTicket`, `requestBinding`, `fetchTimeoutMs`,
  `algorithm`, `riskContext`, `responseField`, `execution`,
  `tokenFieldName`, `buildMarkup`), a preloaded `api`, and the loader
  controls (`scriptSrc`, `scriptIntegrity`, `scriptCrossorigin`,
  `scriptTimeoutMs`, `scriptNonce`). Changing any input destroys the
  live widget and rebuilds it from the new options.
- Outputs: `verified` (token detail), `failed` (message),
  `expired`, `widgetReady` (scope), `verifying` (scope), `retrying`,
  `workerUnavailable`, `executionUnavailable`. `failed` carries both
  terminal solve failures and render/load failures (the message says
  which; a solve failure is the driver's own error text). Driver work
  runs outside the Angular zone; every emission re-enters it, so
  OnPush parents see the change.
- `KiwiCaptchaService.load()/render()` is the injectable facade for
  layouts that manage their own DOM. Both accept the loader controls;
  `render()` also accepts a preloaded `api` (the same option the
  component exposes as an input) and then skips the script load.
- The component exposes `getResponse/isExpired/reset/execute` and a
  `ready` signal; teardown runs through `DestroyRef`, and a render
  landing after view death or after a newer rebuild is discarded.

## Tests

`src/kiwi-captcha.component.spec.ts` holds 12 TestBed specs: mount and
markup, verified/verifying emissions, failed/expired, destroy hygiene,
the imperative controls, the injectable service, the remaining render
inputs, `buildMarkup: false` failure reporting, loader-control
forwarding, the preloaded `api` input, and rebuild-on-input-change.

`npm test` runs the strict `tsc --noEmit` gate and then the vitest +
jsdom suite through the Angular AOT transform. `npm run test:unit`
runs the suite alone. The vitest config sets `jit: false` (the plugin's
test default is JIT, where `input()`/`viewChild()` metadata cannot be
reflected) and `tsconfig.spec.json` sets `noEmit: false` so the AOT
compiler can emit the transformed components. `ng test`
(karma.conf.cjs, angular.json) remains the optional browser-workspace
runner and launches the headless Chromium named by CHROME_BIN.

## Build

`npm run build` compiles the library with `ng-packagr` (partial
compilation mode) into `dist/`.
