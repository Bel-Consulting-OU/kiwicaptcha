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
the imperative controls, the injectable service). Status in this
checkout: TYPECHECKED, NOT EXECUTED. The local toolchain has no Karma
browser launcher, so the specs compile under the strict `tsc
--noEmit` gate (`npm run typecheck`, part of `npm test`) and run in
the Angular workspace CI with `ng test`. No pass is claimed beyond the
typecheck.
