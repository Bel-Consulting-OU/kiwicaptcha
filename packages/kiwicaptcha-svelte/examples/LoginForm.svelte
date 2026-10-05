<script lang="ts">
  import { KiwiCaptcha } from "@kiwicaptcha/svelte";

  let token = $state("");
  let error = $state<string | null>(null);
  let widget: { reset(): void };

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    // POST the form with token in the kiwi__token field.
    void token;
  }
</script>

<form onsubmit={submit}>
  <KiwiCaptcha
    bind:this={widget}
    endpoint="/api/kcaptcha/challenge"
    sitekey="pk-live-1"
    scope="login"
    lang="en"
    onverify={(t) => (token = t)}
    onerror={(m) => (error = m)}
    onexpire={() => widget?.reset()}
  />
  {#if error}
    <p role="alert">{error}</p>
  {/if}
  <input type="hidden" name="kiwi__token" value={token} />
  <button disabled={token === ""}>Sign in</button>
</form>
