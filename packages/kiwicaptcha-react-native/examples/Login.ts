// Example: the challenge request carries the request body; the token
// rides the app's own authenticated call and the backend verifies.
import { Platform } from "react-native";
import { acquireToken, KiwiSolveError } from "../src";

export async function login(email: string, password: string): Promise<void> {
  const token = await acquireToken({
    endpoint: "https://api.example.com/api/kcaptcha/challenge",
    scope: "login",
    sitekey: "pk-mobile-1",
  });

  const response = await fetch("https://api.example.com/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      password,
      kiwi__token: token,
      client: Platform.OS,
    }),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`login failed: ${detail}`);
  }
}

// Failure handling: the refusal is machine-readable.
export function describeFailure(err: unknown): string {
  if (err instanceof KiwiSolveError) {
    if (err.refusal === "solver-unavailable") {
      return "the native solver module is not linked; see docs/NATIVE.md";
    }
    return `the check could not complete (${err.refusal})`;
  }
  return String(err);
}
