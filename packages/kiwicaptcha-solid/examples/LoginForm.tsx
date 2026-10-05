import { createSignal, Show } from "solid-js";
import { KiwiCaptcha, type KiwiSolidControls } from "@kiwicaptcha/solid";

/** The four-setting quickstart with a token field. */
export function LoginForm() {
  let controls: KiwiSolidControls | undefined;
  const [token, setToken] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        // POST the form with token in the kiwi__token field.
      }}
    >
      <KiwiCaptcha
        ref={(c) => (controls = c)}
        endpoint="/api/kcaptcha/challenge"
        sitekey="pk-live-1"
        scope="login"
        lang="en"
        onVerify={(t) => setToken(t)}
        onError={(m) => setError(m)}
        onExpire={() => controls?.reset()}
      />
      <Show when={error()}>
        <p role="alert">{error()}</p>
      </Show>
      <input type="hidden" name="kiwi__token" value={token()} />
      <button disabled={token() === ""}>Sign in</button>
    </form>
  );
}
