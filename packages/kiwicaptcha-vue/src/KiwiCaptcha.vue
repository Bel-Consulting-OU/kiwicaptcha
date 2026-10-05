<script setup lang="ts">
import { useKiwiCaptcha, type UseKiwiCaptchaOptions } from "./useKiwiCaptcha";
import type {
  KiwiErrorDetail,
  KiwiRetryDetail,
  KiwiVerifiedDetail,
} from "@kiwicaptcha/client-core";

/**
 * The KiwiCaptcha widget as a Vue 3 component.
 *
 * Props are the core render options (the four-setting quickstart is
 * endpoint, sitekey, scope, lang) plus the loader controls. Lifecycle
 * events surface as Vue emits; the widget handle is exposed through
 * template refs for reset/execute/getResponse/isExpired.
 */
const props = withDefaults(defineProps<UseKiwiCaptchaOptions>(), {
  // Vue casts absent Boolean-capable props to false; an explicit
  // undefined default keeps the core's own semantics instead
  // (buildMarkup must default to true, responseField to the alias write).
  buildMarkup: undefined,
  responseField: undefined,
  execution: undefined,
  api: undefined,
});

const emit = defineEmits<{
  ready: [scope: string];
  verifying: [scope: string];
  verify: [token: string, detail: KiwiVerifiedDetail];
  error: [message: string, detail: KiwiErrorDetail];
  expire: [scope: string];
  retry: [detail: KiwiRetryDetail];
  workerUnavailable: [reason: string, scope: string];
  executionUnavailable: [reason: string, scope: string];
}>();

const { containerRef, ready, execute, reset, getResponse, isExpired } =
  useKiwiCaptcha(() => ({
    ...props,
    onReady: (scope) => emit("ready", scope),
    onVerifying: (scope) => emit("verifying", scope),
    onVerify: (token, detail) => emit("verify", token, detail),
    onError: (message, detail) => emit("error", message, detail),
    onExpire: (scope) => emit("expire", scope),
    onRetry: (detail) => emit("retry", detail),
    onWorkerUnavailable: (reason, scope) => emit("workerUnavailable", reason, scope),
    onExecutionUnavailable: (reason, scope) => emit("executionUnavailable", reason, scope),
  }));

defineExpose({ ready, execute, reset, getResponse, isExpired });
</script>

<template>
  <div ref="containerRef" class="kiwi-vue"></div>
</template>
