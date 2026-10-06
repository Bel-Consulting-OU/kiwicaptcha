/**
 * The execution delegation plane of the node SDK: an execution-armed
 * record demands the browser-trace walker, an oracle this SDK does not
 * carry. The default policy is fail-closed (every armed record answers
 * execution_mismatch, documented). The sidecar policy delegates that
 * single verification to a co-located kiwicaptcha-verifier sidecar
 * over HTTP: the sidecar carries the full Rust core with the real
 * execution verifier, consumes the record (single-use semantics
 * preserved: the sidecar consumes, this SDK never double-consumes) and
 * answers the provider-shaped verdict mapped back into this SDK's
 * vocabulary.
 *
 * Trust boundary: the sidecar decides acceptances, so it must be
 * co-located and trusted to the same standard as the verifier itself.
 * The bearer credential is sent per request, and a refused credential
 * denies instead of retrying into an untrusted verifier.
 */

import type { VerifyErrorCode } from './errors.js';

/** The execution-armed dimension policy of one verify call. */
export interface ExecutionPolicy {
  /** The kiwicaptcha-verifier base URL. Absent keeps fail-closed. */
  sidecarUrl?: string;
  /** The sidecar's own credential, sent as the Authorization bearer. */
  bearerToken?: string;
  /** The bounded budget of one delegation call in ms (default 5000). */
  timeoutMs?: number;
}

/** Whether the options select the delegation path for an armed record. */
export function delegationEnabled(
  record: { executionProgram: string | null },
  policy: ExecutionPolicy | null | undefined,
): boolean {
  return record.executionProgram !== null && typeof policy?.sidecarUrl === 'string' && policy.sidecarUrl.trim() !== '';
}

interface SidecarResponse {
  success?: boolean;
  'kiwi-code'?: string;
}

/**
 * Hand one execution-armed verification to the sidecar. The answer is
 * `{ ok, code }` in the SDK's own shapes: `ok` means the sidecar's
 * full-core pass accepted, and the caller completes its own valid
 * result from the local record; a failure maps the sidecar's
 * kiwi-code (the shared wire vocabulary) verbatim, with the transport
 * and trust failures fail-closed (storage_unavailable keeps the retry
 * disposition for an unreachable sidecar, whose record stays intact).
 */
export async function delegateToSidecar(
  rawToken: string,
  scope: string,
  clientIp: string | null,
  policy: ExecutionPolicy,
): Promise<{ ok: boolean; code: VerifyErrorCode | string }> {
  const base = policy.sidecarUrl!.trim().replace(/\/+$/, '');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), policy.timeoutMs && policy.timeoutMs > 0 ? policy.timeoutMs : 5000);
  let response: Response;
  try {
    response = await fetch(`${base}/verify`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(policy.bearerToken ? { authorization: `Bearer ${policy.bearerToken}` } : {}),
      },
      body: JSON.stringify({ token: rawToken, scope, remoteip: clientIp ?? undefined }),
      signal: controller.signal,
    });
  } catch {
    return { ok: false, code: 'storage_unavailable' };
  } finally {
    clearTimeout(timer);
  }
  if (response.status === 401 || response.status === 403) {
    // The sidecar refused the credential: never retry into an
    // untrusted verifier, fail closed with a deny.
    return { ok: false, code: 'execution_mismatch' };
  }
  if (response.status >= 500) {
    return { ok: false, code: 'storage_unavailable' };
  }
  if (response.status !== 200) {
    return { ok: false, code: 'execution_mismatch' };
  }
  let decoded: SidecarResponse;
  try {
    decoded = (await response.json()) as SidecarResponse;
  } catch {
    return { ok: false, code: 'execution_mismatch' };
  }
  if (decoded.success) {
    return { ok: true, code: 'ok' };
  }
  // The kiwi-code IS the shared wire vocabulary; a code this SDK does
  // not know stays a deny with the code carried verbatim.
  return { ok: false, code: decoded['kiwi-code'] || 'execution_mismatch' };
}
