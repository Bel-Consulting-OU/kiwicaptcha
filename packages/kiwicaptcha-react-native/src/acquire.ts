import { KiwiSolveError, type AcquireTokenOptions, type KiwiSolution } from "./types.js";
import { validateChallenge } from "./validate.js";
import { encodeToken } from "./token.js";
import { solve } from "./solve.js";
import { deliveryDecision } from "./lifecycle.js";

/**
 * The documented JSON flow, native edition: POST the challenge request,
 * validate the document, dispatch the solve to the native thread (or
 * the low-difficulty JS fallback), pack the wire token. Verification is
 * a server-to-server call the app never performs; the token rides the
 * app's own authenticated request and the backend runs siteverify.
 *
 * Delivery runs the Interactive-Client Lifecycle v1 gate: the expiry
 * clock anchors at parse time, a solve that finished after the
 * deadline is refused with the typed `expired` refusal (the token is
 * never handed out), and a solve that beat the minimum-duration floor
 * waits out the floor before the token is packed — the shared vectors
 * pin the decision this gate delegates to.
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
  // The lifecycle clock starts at parse time, never after the solve.
  const receivedAtMs = Date.now();
  const challenge = validateChallenge(document);
  const solution: KiwiSolution = await solve(challenge, { onProgress: options.onProgress });
  const solveFinishedAtMs = Date.now();

  // The delivery gate: expired is refused (never delivered), defer
  // waits out the min-duration floor (the wait is bounded: defer only
  // happens while both candidate instants are inside the deadline),
  // deliver packs the token.
  let decision = deliveryDecision(
    receivedAtMs,
    challenge.ttlSecs ?? 0,
    challenge.minDurationMs ?? 0,
    solveFinishedAtMs,
    Date.now(),
  );
  while (decision.reason === "defer") {
    const waitMs = decision.deliverAtMs - Date.now();
    if (waitMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
    decision = deliveryDecision(
      receivedAtMs,
      challenge.ttlSecs ?? 0,
      challenge.minDurationMs ?? 0,
      solveFinishedAtMs,
      Date.now(),
    );
  }
  if (decision.reason !== "deliver") {
    throw new KiwiSolveError(
      "expired",
      `the challenge was not deliverable: ${decision.reason}`,
    );
  }

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
