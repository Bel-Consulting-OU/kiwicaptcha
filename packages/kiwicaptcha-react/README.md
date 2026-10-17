# @kiwicaptcha/react

React 18 KiwiCaptcha widget: the `<KiwiCaptcha>` component and the
`useKiwiCaptcha` hook, both on the shared `@kiwicaptcha/client-core`,
so the lifecycle semantics (fresh markup per mount, event-driven
callbacks, framework-owned containers) are the core's, verbatim.

## The four-setting quickstart

```tsx
import { KiwiCaptcha, type KiwiCaptchaRef } from "@kiwicaptcha/react";

const widgetRef = useRef<KiwiCaptchaRef>(null);

<KiwiCaptcha
  ref={widgetRef}
  endpoint="/api/kcaptcha/challenge" // 1
  sitekey="pk-live-1"                // 2
  scope="login"                      // 3
  lang="en"                          // 4
  theme="dark"
  onVerify={(token, detail) => submit(token)}
  onError={(message) => show(message)}
  onExpire={() => widgetRef.current?.reset()}
/>
```

## Component and hook

- `<KiwiCaptcha>` owns the whole lifecycle: driver load-once, fresh
  markup per mount, event mapping, teardown on unmount. Callback props
  stay live without a rebuild; only the config fields re-mount the
  widget. StrictMode's double mount is safe (one live record).
- `useKiwiCaptcha(props)` returns `containerRef` plus
  `execute/reset/getResponse/isExpired/destroy` for layouts that place
  the mount node themselves.
- The imperative handle (`ref`) exposes `getResponse`, `isExpired`,
  `reset`, `execute` and `destroy`; `execute` resolves the token (the
  driver's promise API) and rejects with the driver's failure reason,
  and `destroy` tears the widget down early (unmount also destroys it).

## Props

The four-setting shape plus the core's options: theme, action, cData,
chainTicket, requestBinding, fetchTimeoutMs, algorithm, riskContext,
responseField, execution, tokenFieldName, buildMarkup and api
(a preloaded driver), and the loader controls (scriptSrc,
scriptIntegrity, scriptCrossorigin, scriptTimeoutMs, scriptNonce).
Replacing `api` or any config field rebuilds the widget; className and
style only style the mount node.
Callbacks: onVerify, onError, onExpire, onReady, onVerifying, onRetry,
onWorkerUnavailable, onExecutionUnavailable.

## Tests

`npm test` runs the vitest suite under happy-dom with a faithful mock
driver: mount and markup, theme/lang/action/cData/execution/riskContext
forwarding, loader-control forwarding, token delivery,
error/expiry/retry/unavailable mapping, the imperative handle and
destroy, api replacement, StrictMode double-mount safety, config-change
re-mounts, callback-change stability, hook option stripping and unmount
listener hygiene.
