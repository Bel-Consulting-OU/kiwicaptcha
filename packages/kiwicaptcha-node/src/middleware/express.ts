import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { verify, type VerifyOptions } from '../verify.js';

/**
 * The Express middleware: reads the configured token field, verifies
 * the token locally, and answers 422 with a JSON error body on
 * failure. A verified request exposes kiwi.verify on the request for
 * downstream handlers (the decision handle, the price rung, the
 * binding).
 */

export const DEFAULT_TOKEN_FIELD = 'kiwi__token';

export interface ExpressVerifyOptions {
  /** Per-request VerifyOptions factory; receives the request. */
  verify: (req: Request) => VerifyOptions | Promise<VerifyOptions>;
  /** The body field carrying the token (default kiwi__token). */
  tokenField?: string;
  /** Failure status (default 422). */
  failureStatus?: number;
  /** Render the failure as a redirect instead of the JSON error. */
  failureRedirect?: string;
}

function readToken(req: Request, field: string): string | null {
  const body = req.body as unknown;
  if (body !== null && typeof body === 'object' && field in (body as Record<string, unknown>)) {
    const value = (body as Record<string, unknown>)[field];
    if (typeof value === 'string' && value !== '') {
      return value;
    }
  }
  const headers = req.headers as Record<string, unknown>;
  const headerValue = headers[`x-kiwi-token`];
  if (typeof headerValue === 'string' && headerValue !== '') {
    return headerValue;
  }
  const query = req.query as Record<string, unknown>;
  const queryValue = query[field];
  if (typeof queryValue === 'string' && queryValue !== '') {
    return queryValue;
  }
  return null;
}

/**
 * Build the Express request handler. The handler never throws: a
 * storage outage is a 422 with the typed storage_unavailable code,
 * fail closed.
 */
export function kiwiVerifyExpress(options: ExpressVerifyOptions): RequestHandler {
  const field = options.tokenField ?? DEFAULT_TOKEN_FIELD;
  const status = options.failureStatus ?? 422;
  return (req: Request, res: Response, next: NextFunction): void => {
    void (async () => {
      const rawToken = readToken(req, field);
      if (rawToken === null) {
        fail(res, options.failureRedirect, status, 'malformed_token', `the ${field} field is missing`);
        return;
      }
      try {
        const verifyOptions = await options.verify(req);
        const result = await verify(rawToken, verifyOptions);
        if (!result.ok) {
          fail(
            res,
            options.failureRedirect,
            status,
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
