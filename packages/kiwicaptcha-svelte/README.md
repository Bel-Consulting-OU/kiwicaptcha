# @kiwicaptcha/svelte

Svelte 5 KiwiCaptcha widget: the `KiwiCaptcha` component and the
`kiwiCaptcha` action, both on the shared `@kiwicaptcha/client-core`.

## The four-setting quickstart

```svelte
<script lang="ts">
  import { KiwiCaptcha } from "@kiwicaptcha/svelte";
  let widget: KiwiCaptcha;
</script>

<form onsubmit={submit}>
  <KiwiCaptcha
    bind:this={widget}
    endpoint="/api/kcaptcha/challenge"
    sitekey="pk-live-1"
    scope="login"
    lang="en"
    onverify={(token) => (form.token = token)}
    onerror={(message) => (error = message)}
  />
  <button>Sign in</button>
</form>
```

## Component and action

- Callback props are Svelte 5 idiom (`onverify`, `onerror`,
  `onexpire`, `onready`, `onverifying`, `onretry`,
  `onworkerunavailable`, `onexecutionunavailable`); they read the
  current prop value at event time, so parents may pass fresh inline
  functions without rebuilding the widget.
- Bind the component for `reset/execute/getResponse/isExpired/destroy`.
- `use:kiwiCaptcha={{ scope: "login" }}` renders the widget into the
  element carrying the action (progressive enhancement); an options
  update rebuilds, and unmount destroys.
- Both the component and the action accept the full loader set:
  `scriptSrc`, `scriptIntegrity`, `scriptCrossorigin`,
  `scriptTimeoutMs`, `scriptNonce`. The render options include
  `theme`, `action`, `cData`, `execution` and `riskContext` (whose
  `"coarse"` value rides `data-kiwi-risk-context`).

Config fields are captured at mount; a changed config is expressed as
a keyed re-mount by the caller. Loader controls are captured the same
way and used when the driver is injected.

## Tests

`npm test` runs the vitest suite with vite-plugin-svelte under
happy-dom and a faithful mock driver: mount and markup, callback
payloads, theme/lang/action/execution/riskContext forwarding,
loader-control forwarding, the imperative controls (including
`isExpired` and `destroy`), and the action's
render/update/loader/destroy paths.
