import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { resolveClientIp } from '../clientip.js';
import { verify, type Disposition, type VerifyOptions } from '../verify.js';
import { headerTokenValues, resolveTokenValues, stringValues } from './token-source.js';

/**
 * The Express middleware: collects the configured token field from the
 * header, the form or body field and the query parameter under the
 * shared authority rule, verifies the one agreed token locally, and
 * answers a definitive denial with the configured denial response. A
 * retry decision answers 503 Service Unavailable so a backend outage
 * stays retryable. A verified request exposes kiwi.verify on the
 * request for downstream handlers (the decision handle, the price
 * rung, the binding). When trustedProxies is configured, the
 * middleware resolves the canonical client IP itself (the same
 * trusted-proxy walk every SDK ships) and fills clientIp on the
 * factory's options when the factory left it unset; express's own
 * trust proxy setting is never consulted, so the behavior stays
 * identical across frameworks.
 */

export const DEFAULT_TOKEN_FIELD = 'kiwi__token';

export interface ExpressVerifyOptions {
  /** Per-request VerifyOptions factory; receives the request. */
  verify: (req: Request) => VerifyOptions | Promise<VerifyOptions>;
  /** The body field carrying the token (default kiwi__token). */
  tokenField?: string;
  /** Failure status of a definitive denial (default 422). */
  failureStatus?: number;
  /** Status of a retry decision (default 503). */
  retryStatus?: number;
  /** Render a definitive denial as a redirect instead of the JSON
   * error. A retry decision always answers its status, never a
   * redirect. */
  failureRedirect?: string;
  /**
   * The trusted-proxy CIDR list. The default empty list trusts
   * nobody: X-Forwarded-For and X-Real-IP are ignored and the socket
   * peer is the client IP.
   */
  trustedProxies?: string[];
}

/** The canonical client IP of one request per the shared contract. */
export function clientIpFromRequest(req: Request, trustedProxies: string[] = []): string {
  const peer = req.socket?.remoteAddress ?? '';
  const xffLines = rawHeaderLines(req, 'x-forwarded-for');
  const realIpLines = rawHeaderLines(req, 'x-real-ip');
  // A repeated forwarding header is parser ambiguity (one intermediary
  // reads the first line, another the last): no header-derived identity
  // is trustworthy, so the peer wins. Never pick a line of a repeated
  // X-Real-IP, matching the shared resolver contract.
  if (xffLines.length > 1 || realIpLines.length > 1) {
    return peer;
  }
  return resolveClientIp({
    peer,
    xffLines,
    realIp: realIpLines[0] ?? null,
    trustedProxies,
  });
}

/** Every header line for one name, preserving duplicates and case. */
function rawHeaderLines(req: Request, name: string): string[] {
  const raw = req.rawHeaders ?? [];
  const lines: string[] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const key = raw[i];
    const value = raw[i + 1];
    if (key !== undefined && key.toLowerCase() === name) {
      lines.push(value ?? '');
    }
  }
  return lines;
}

function bodyTokenValues(body: unknown, field: string): string[] {
  if (body === null || typeof body !== 'object') {
    return [];
  }
  if (!Object.prototype.hasOwnProperty.call(body, field)) {
    return [];
  }
  return stringValues((body as Record<string, unknown>)[field]);
}

/** The denial status of one disposition: retry answers its own status,
 * a definitive denial the configured one. */
export function failureStatusForDisposition(
  disposition: Disposition,
  failureStatus: number,
  retryStatus: number,
): number {
  return disposition === 'retry' ? retryStatus : failureStatus;
}

/**
 * Build the Express request handler. The handler never throws: a
 * storage outage answers the retry disposition as 503 with the typed
 * storage_unavailable code, fail closed.
 */
export function kiwiVerifyExpress(options: ExpressVerifyOptions): RequestHandler {
  const field = options.tokenField ?? DEFAULT_TOKEN_FIELD;
  const status = options.failureStatus ?? 422;
  const retryStatus = options.retryStatus ?? 503;
  return (req: Request, res: Response, next: NextFunction): void => {
    void (async () => {
      const resolution = resolveTokenValues({
        header: headerTokenValues(
          req.rawHeaders,
          (req.headers as Record<string, unknown>)['x-kiwi-token'],
        ),
        form: bodyTokenValues(req.body, field),
        query: stringValues((req.query as Record<string, unknown>)[field]),
      });
      if (resolution.code !== null) {
        const detail = resolution.code === 'token_source_conflict'
          ? 'the request carries conflicting token sources'
          : `the ${field} field is missing`;
        fail(res, options.failureRedirect, status, resolution.code, detail);
        return;
      }
      try {
        const verifyOptions = await options.verify(req);
        if (options.trustedProxies !== undefined && (verifyOptions.clientIp === undefined || verifyOptions.clientIp === null)) {
          // With trustedProxies configured (an empty list included),
          // the middleware owns the client-IP boundary: it binds the
          // socket peer, or a forwarded entry when a trusted hop
          // justifies one. A factory-pinned clientIp always wins.
          verifyOptions.clientIp = clientIpFromRequest(req, options.trustedProxies);
        }
        const result = await verify(resolution.token, verifyOptions);
        if (!result.ok) {
          const denialStatus = failureStatusForDisposition(
            result.disposition,
            status,
            retryStatus,
          );
          fail(
            res,
            result.disposition === 'retry' ? undefined : options.failureRedirect,
            denialStatus,
            result.code === '' ? 'invalid' : result.code,
            result.detail ?? 'verification failed',
          );
          return;
        }
        (req as Request & { kiwi?: unknown }).kiwi = result;
        next();
      } catch (error) {
        next(error);
      }
    })();
  };
}

function fail(
  res: Response,
  failureRedirect: string | undefined,
  status: number,
  code: string,
  detail: string,
): void {
  if (failureRedirect !== undefined) {
    res.redirect(failureRedirect);
    return;
  }
  res.status(status).json({ error: { code, detail } });
}
