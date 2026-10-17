# @kiwicaptcha/vue

Vue 3 KiwiCaptcha widget: the `KiwiCaptcha` SFC and the
`useKiwiCaptcha` composable, both on the shared
`@kiwicaptcha/client-core`, so the lifecycle semantics are the core's.

## The four-setting quickstart

```vue
<script setup lang="ts">
import { ref } from "vue";
import { KiwiCaptcha } from "@kiwicaptcha/vue";

const widget = ref();
</script>

<template>
  <form @submit.prevent="submit">
    <KiwiCaptcha
      ref="widget"
      endpoint="/api/kcaptcha/challenge"
      sitekey="pk-live-1"
      scope="login"
      lang="en"
      @verify="(token) => (form.token = token)"
      @error="(message) => (error = message)"
      @expire="widget?.reset()"
    />
    <button>Sign in</button>
  </form>
</template>
```

## Composable

```ts
import { useKiwiCaptcha } from "@kiwicaptcha/vue";

const { containerRef, ready, execute, reset, getResponse, isExpired, destroy } =
  useKiwiCaptcha(() => ({ scope: "login", onVerify: (t) => submit(t) }));
```

Pass a getter (`() => ({ ...props })`) so prop changes rebuild the
widget; callbacks stay live without a rebuild. The composable owns the
lifecycle: driver load-once, fresh markup per mount, destroy on
unmount, rebuild on any config change (including `api` and the loader
controls), and `destroy()` for an early teardown.

## Emits and template ref

Events: `verify`, `error`, `expire`, `ready`, `verifying`, `retry`,
`workerUnavailable`, `executionUnavailable`. The template ref exposes
`ready`, `execute`, `reset`, `getResponse`, `isExpired` and `destroy`.

Props are the core render options (including `riskContext: "coarse"`,
`api`, and the loader controls `scriptSrc`, `scriptIntegrity`,
`scriptCrossorigin`, `scriptTimeoutMs`, `scriptNonce`) plus the emit
side callbacks.

A note on props: the SFC gives the Boolean-capable props explicit
`undefined` defaults, so Vue's Boolean casting never turns an absent
`buildMarkup` into `false` and silently switch the render mode.

## Tests

`npm test` runs the vitest suite with @vue/test-utils under happy-dom
and a faithful mock driver: mount and markup, emit payloads (including
`verifying`), theme/lang/action/execution/riskContext forwarding,
loader-control forwarding, the template-ref controls and destroy,
config/api-change rebuilds, and composable lifecycle (mount, controls,
destroy on unmount and on demand).
