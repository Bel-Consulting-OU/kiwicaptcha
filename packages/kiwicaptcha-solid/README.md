# @kiwicaptcha/solid

SolidJS KiwiCaptcha widget on the shared `@kiwicaptcha/client-core`.

## The four-setting quickstart

```tsx
import { KiwiCaptcha, type KiwiSolidControls } from "@kiwicaptcha/solid";

let controls: KiwiSolidControls | undefined;

<KiwiCaptcha
  ref={(c) => (controls = c)}
  endpoint="/api/kcaptcha/challenge"
  sitekey="pk-live-1"
  scope="login"
  lang="en"
  onVerify={(token) => submit(token)}
  onError={(message) => show(message)}
  onExpire={() => controls?.reset()}
/>;
```

## Lifecycle

Config props (endpoint, sitekey, scope, lang is the four-setting
quickstart, plus theme/action/cData/execution/riskContext and the
loader controls `scriptSrc`, `scriptIntegrity`, `scriptCrossorigin`,
`scriptTimeoutMs`, `scriptNonce`) are captured when the widget mounts;
callback props stay live, so parents may pass fresh inline functions on
every render. Cleanup destroys the driver record when the component
unmounts. The `ref` prop receives the imperative controls
(`getResponse/isExpired/reset/execute/destroy`) once the widget is
mounted.

## Tests

`npm test` runs the vitest suite with vite-plugin-solid under
happy-dom and a faithful mock driver: mount and markup, verify/error/
expire/retry callbacks, theme/lang/action/execution/riskContext and
loader-control forwarding, the ref-delivered controls (including
`isExpired` and `destroy`), ref-once semantics, and dispose hygiene.
