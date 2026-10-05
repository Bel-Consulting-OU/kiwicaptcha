import { useState } from "react";
import { KiwiCaptcha, useKiwiCaptcha, type KiwiCaptchaRef } from "@kiwicaptcha/react";

// Component: the four-setting quickstart with a token field.
export function LoginForm() {
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);

  return (
    <form onSubmit={(e) => e.preventDefault()}>
      <KiwiCaptcha
        endpoint="/api/kcaptcha/challenge"
        sitekey="pk-live-1"
        scope="login"
        lang="en"
        theme="dark"
        onVerify={(t) => {
          setToken(t);
          setError(null);
        }}
        onError={(message) => setError(message)}
        onExpire={() => setError("the check expired, press Retry")}
      />
      {error && <p role="alert">{error}</p>}
      <input type="hidden" name="kiwi__token" value={token} readOnly />
      <button disabled={!token}>Sign in</button>
    </form>
  );
}

// Hook: place the mount node yourself and keep the controls.
export function InlineWidget() {
  const kiwi = useKiwiCaptcha({ scope: "signup", onVerify: (t) => console.log(t) });
  return (
    <div>
      <div ref={kiwi.containerRef} />
      <button onClick={() => void kiwi.execute()}>Run the check</button>
      <button onClick={() => kiwi.reset()}>Reset</button>
    </div>
  );
}

// Imperative handle: read the token at submit time.
export function SubmitTimeWidget() {
  const ref = useRef<KiwiCaptchaRef>(null);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        const token = await ref.current?.execute();
        if (token) submit(token);
      }}
    >
      <KiwiCaptcha ref={ref} scope="login" execution="execute" />
      <button>Submit</button>
    </form>
  );
}

import { useRef } from "react";

function submit(token: string): void {
  // POST the form with the kiwi__token field; the backend verifies.
  void token;
}
