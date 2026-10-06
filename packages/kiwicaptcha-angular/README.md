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

- Inputs: the four-setting quickstart plus the core's remaining
  options and the loader controls.
- Outputs: `verified` (token detail), `failed` (message), `expired`,
  `widgetReady` (scope), `retrying`, `workerUnavailable`,
  `executionUnavailable`. Driver work runs outside the Angular zone;
  every emission re-enters it, so OnPush parents see the change.
- `KiwiCaptchaService.load()/render()` is the injectable facade for
  layouts that manage their own DOM.
- The component exposes `getResponse/isExpired/reset/execute` and a
  `ready` signal; teardown runs through `DestroyRef`, and a render
  landing after view death is discarded.

## Tests and their status in this checkout

`src/kiwi-captcha.component.spec.ts` holds the TestBed specs
(mount and markup, verified emission, failed/expired, destroy hygiene,
the imperative controls, the injectable service). Two runners are
wired: `npm run test:unit` executes the suite under vitest + jsdom
with the Angular compiler transform, and `npm test` keeps the strict
`tsc --noEmit` gate. `ng test` (karma.conf.cjs, angular.json) is the
workspace runner and launches the headless Chromium named by
CHROME_BIN.

Status in this checkout: the vitest runner discovers and executes all
six specs (one passes; five fail on Angular's required view-query
signals never resolving under the jsdom transform chain, reproduced
with a minimal probe component with no project code involved). The
Karma runner launches the browser but the builder's bundle does not
attach to the karma file list in this container. Both symptoms are
environment-level, neither is a claim of passing: the suite is
expected to pass in an Angular CI image with a system Chrome, and no
pass is claimed here beyond the one assertion the vitest run proves.
