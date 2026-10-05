# @kiwicaptcha/client-core

The framework-free KiwiCaptcha widget client core: the script loader,
explicit render, the promise API and the event mapping on top of the
browser widget driver (`window.KiwiCaptcha`). The React, Vue, Svelte,
Solid and Angular packages all wrap this core, so lifecycle semantics
cannot drift between them.

## The four-setting quickstart

```ts
import { loadKiwiCaptcha, renderKiwiCaptcha } from "@kiwicaptcha/client-core";

const api = await loadKiwiCaptcha({ scriptSrc: "/kiwi.js" });
const handle = renderKiwiCaptcha(document.getElementById("mount")!, {
  endpoint: "/api/kcaptcha/challenge", // 1. the same-origin challenge POST
  sitekey: "pk-live-1",                // 2. the public sitekey
  scope: "login",                      // 3. the security scope
  lang: "en",                          // 4. the widget language
  onVerify: (token) => submit(token),
  onError: (message) => show(message),
  onExpire: () => handle.reset(),
});
```

Everything else is the driver's documented opt-ins: theme, action,
cData, chainTicket, requestBinding, fetchTimeoutMs, algorithm,
responseField, execution, tokenFieldName, buildMarkup.

## Lifecycle rules (identical in every framework wrapper)

- Each render builds FRESH markup inside the container, so a remount
  into a reused node never resurrects a destroyed widget.
- Lifecycle callbacks come from the driver's bubbling kiwi:* events
  (ready, verifying, verified, error, expired, retrying,
  worker-unavailable, execution-unavailable), never from the
  per-generation callback options.
- `handle.destroy()` detaches listeners and cancels the driver record
  while LEAVING the container node in place: the framework owns that
  node.
- `loadKiwiCaptcha` loads the driver once per source, dedupes
  concurrent callers, and refuses a loaded asset that never registers
  the global.

## Tests

`npm test` runs the vitest suite under happy-dom with a faithful mock
of the driver surface (render/reset/execute/getResponse/remove/
isExpired/destroy plus the kiwi:* events): 21 tests cover the loader,
the markup builder, the render lifecycle, token delivery, reset,
destroy hygiene and re-render safety.

The four-setting shape (endpoint, sitekey, scope, lang) is the client
mirror of the server's four-setting quickstart; the server's own
profile/secret/store/scopes live in the server SDKs.
