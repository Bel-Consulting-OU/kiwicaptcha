/**
 * The Zitadel Actions v2 script: a pre-creation guard that verifies
 * the kiwi proof-of-work token server-to-server against the kiwi
 * deployment. Attach it to the PreCreation trigger of the flow you
 * want to protect (Actions, Flows, add the script, select the
 * trigger); the action aborts the creation when the challenge did
 * not pass, and fails closed when the deployment is unreachable.
 *
 * Runtime contract (Actions v2): the script runs in Zitadel's JS
 * runtime with fetch available. The action reads the token the
 * client solved before the registration call: the shim widget writes
 * it into the hidden kiwi__token field (or the X-Kiwi-Token header
 * on the API flow), and the flow delivers it in the request payload
 * under "kiwiToken".
 *
 * Configuration constants (edit for the deployment):
 */
const KIWI_VERIFY_URL = "http://127.0.0.1:7371/verify";
const KIWI_BEARER = ""; // set when the deployment requires its bearer
const KIWI_SCOPE = "signup";

/**
 * The framework-free core: the wire request builder and the decision
 * table, exported so the node test exercises them without Zitadel.
 */
function buildRequest(url, token, scope, ip, bearer) {
  const headers = { "Content-Type": "application/json" };
  if (bearer) headers.Authorization = "Bearer " + bearer;
  return {
    url: url,
    headers: headers,
    body: JSON.stringify({ token: token, scope: scope, remoteip: ip }),
  };
}

function decide(status, body) {
  if (status === 0 || status >= 500 || status === 401 || status === 404) {
    return { ok: false, code: "verify_unavailable" };
  }
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    return { ok: false, code: "verify_unreadable" };
  }
  if (!parsed || typeof parsed !== "object") {
    return { ok: false, code: "verify_unreadable" };
  }
  return parsed.success === true
    ? { ok: true, code: "verified" }
    : { ok: false, code: "challenge_failed" };
}

async function verify(url, bearer, token, scope, ip) {
  if (!token || !String(token).trim()) {
    return { ok: false, code: "missing_token" };
  }
  const request = buildRequest(url, String(token).trim(), scope, ip, bearer);
  let response;
  try {
    response = await fetch(request.url, {
      method: "POST",
      headers: request.headers,
      body: request.body,
    });
  } catch (e) {
    return { ok: false, code: "verify_unavailable" };
  }
  let body = "";
  try {
    body = await response.text();
  } catch (e) {
    body = "";
  }
  return decide(response.status, body);
}

/**
 * The action entry point (Actions v2): runs on PreCreation. Zitadel
 * invokes the function bound to the trigger with the execution
 * context; the token arrives in the request payload under kiwiToken
 * (the shim widget wrote it into the hidden field or the header, and
 * the registration caller carries it). An absent token, a failed
 * challenge or an unreachable deployment aborts the creation.
 *
 * The context shape is defensive on purpose: the payload rides
 * ctx.request or ctx.payload depending on the trigger, and the abort
 * uses api.abort when present, throwing otherwise, so every non-OK
 * result blocks creation on either runtime shape.
 */
async function guardPreCreation(ctx, api) {
  const payload = (ctx && (ctx.request || ctx.payload)) || {};
  const token =
    payload.kiwiToken ||
    (payload.data && payload.data.kiwiToken) ||
    (ctx && ctx.headers && ctx.headers["x-kiwi-token"]);
  const ip = (ctx && ctx.request && ctx.request.ipAddress) || "127.0.0.1";

  const result = await verify(KIWI_VERIFY_URL, KIWI_BEARER, token, KIWI_SCOPE, ip);
  if (result.ok) {
    return;
  }
  const message =
    result.code === "verify_unavailable"
      ? "The security service is unavailable. Try again shortly."
      : "The security check did not pass. Solve the challenge and try again.";
  // Fail closed on every non-OK result: the action runtime aborts
  // through api.abort when it offers one, and otherwise by throwing
  // (the documented PreCreation abort), so a missing token, a failed
  // challenge or an unreachable verifier can never let user creation
  // continue.
  if (api && typeof api.abort === "function") {
    api.abort(message);
    return;
  }
  throw new Error("kiwi-captcha guard: " + result.code + " " + message);
}

module.exports = {
  buildRequest,
  decide,
  verify,
  guardPreCreation,
  KIWI_VERIFY_URL,
  KIWI_BEARER,
  KIWI_SCOPE,
};
