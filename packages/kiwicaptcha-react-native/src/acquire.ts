import { KiwiSolveError, type AcquireTokenOptions, type KiwiSolution } from "./types.js";
import { validateChallenge } from "./validate.js";
import { encodeToken } from "./token.js";
import { solve } from "./solve.js";

/**
 * The documented JSON flow, native edition: POST the challenge request,
 * validate the document, dispatch the solve to the native thread (or
 * the low-difficulty JS fallback), pack the wire token. Verification is
 * a server-to-server call the app never performs; the token rides the
 * app's own authenticated request and the backend runs siteverify.
 */
export async function acquireToken(options: AcquireTokenOptions): Promise<string> {
  const started = Date.now();
  const doFetch = options.fetchImpl ?? fetch;
  const controller =
    typeof AbortController !== "undefined" ? new AbortController() : null;
  const timer =
    controller && options.fetchTimeoutMs !== 0
      ? setTimeout(() => controller.abort(), options.fetchTimeoutMs ?? 15000)
      : null;
  let response: Response;
  try {
    response = await doFetch(options.endpoint, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        scope: options.scope,
        ...(options.algorithm ? { algorithm: options.algorithm } : {}),
        ...(options.sitekey ? { sitekey: options.sitekey } : {}),
      }),
      ...(controller ? { signal: controller.signal } : {}),
    });
  } catch (err) {
    throw new KiwiSolveError("malformed", `the challenge request failed: ${String(err)}`);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
  if (!response.ok) {
    throw new KiwiSolveError("malformed", `the challenge endpoint answered ${response.status}`);
  }
  const document: unknown = await response.json();
  const challenge = validateChallenge(document);
  const solution: KiwiSolution = await solve(challenge);
  return encodeToken({
    nonce: challenge.nonce,
    counter: solution.counter,
    durationMs: solution.durationMs || Math.max(1, Date.now() - started),
    rswProof: solution.rswProof,
  });
}

/**
 * The provider-shaped siteverify body (secret, response, optional
 * remoteip), the same document packages/kiwicaptcha-solver builds. The
 * app never calls this itself; it is exported for a trusted backend
 * relay and for tests.
 */
export function verifyRequest(
  secret: string,
  response: string,
  remoteip?: string,
): { body: string } {
  const body: Record<string, string> = { secret, response };
  if (remoteip !== undefined) body["remoteip"] = remoteip;
  return { body: JSON.stringify(body) };
}
