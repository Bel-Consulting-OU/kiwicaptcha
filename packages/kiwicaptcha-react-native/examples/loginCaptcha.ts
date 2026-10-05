import { useState } from "react";
import { acquireToken, KiwiSolveError } from "@kiwicaptcha/react-native";

/** The four-setting quickstart, native-thread edition. */
export function useLoginCaptcha() {
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(scope: string): Promise<string | null> {
    setBusy(true);
    setError(null);
    try {
      const t = await acquireToken({
        endpoint: "https://api.example.com/api/kcaptcha/challenge",
        sitekey: "pk-mobile-1",
        scope,
      });
      setToken(t);
      return t;
    } catch (err) {
      if (err instanceof KiwiSolveError) {
        // Machine-readable refusal: solver-unavailable means the native
        // module is not linked (or the difficulty needs it).
        setError(`${err.refusal}: ${err.message}`);
      } else {
        setError(String(err));
      }
      return null;
    } finally {
      setBusy(false);
    }
  }

  return { token, error, busy, run };
}

function submit(token: string): void {
  // POST the login request with the token; the backend runs siteverify.
  void token;
}
