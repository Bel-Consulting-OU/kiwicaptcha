<script setup lang="ts">
import { ref } from "vue";
import { KiwiCaptcha } from "@kiwicaptcha/vue";

const token = ref("");
const error = ref<string | null>(null);
const widget = ref<{ reset(): void } | null>(null);

function submit(): void {
  // POST the form with token in the kiwi__token field.
  void token.value;
}
</script>

<template>
  <form @submit.prevent="submit">
    <KiwiCaptcha
      ref="widget"
      endpoint="/api/kcaptcha/challenge"
      sitekey="pk-live-1"
      scope="login"
      lang="en"
      @verify="(t) => (token = t)"
      @error="(m) => (error = m)"
      @expire="widget?.reset()"
    />
    <p v-if="error" role="alert">{{ error }}</p>
    <input type="hidden" name="kiwi__token" :value="token" />
    <button type="submit" :disabled="!token">Sign in</button>
  </form>
</template>
