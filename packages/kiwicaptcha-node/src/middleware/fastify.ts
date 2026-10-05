import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { verify, type VerifyOptions } from '../verify.js';

/**
 * The Fastify plugin: a preValidation hook that reads the configured
 * token field, verifies the token locally, and answers 422 with a JSON
 * error body on failure. A verified request exposes request.kiwi for
 * downstream handlers.
 */

export const DEFAULT_TOKEN_FIELD_FASTIFY = 'kiwi__token';

export interface FastifyVerifyOptions {
  /** Per-request VerifyOptions factory; receives the request. */
  verify: (req: FastifyRequest) => VerifyOptions | Promise<VerifyOptions>;
  /** The body field carrying the token (default kiwi__token). */
  tokenField?: string;
  /** Failure status (default 422). */
  failureStatus?: number;
}

function readTokenFastify(req: FastifyRequest, field: string): string | null {
  const body = req.body as unknown;
  if (body !== null && typeof body === 'object' && field in (body as Record<string, unknown>)) {
    const value = (body as Record<string, unknown>)[field];
    if (typeof value === 'string' && value !== '') {
      return value;
    }
  }
  const header = req.headers['x-kiwi-token'];
  if (typeof header === 'string' && header !== '') {
    return header;
  }
  const query = req.query as Record<string, unknown>;
  const queryValue = query[field];
  if (typeof queryValue === 'string' && queryValue !== '') {
    return queryValue;
  }
  return null;
}

/**
 * Register the Fastify verification plugin. The hook never throws: a
 * storage outage is a 422 with the typed storage_unavailable code,
 * fail closed. The plugin carries fastify's skip-override marker, so
 * the hook applies to the routes of the enclosing instance instead of
 * a private child scope.
 */
export async function kiwiVerifyFastify(
  instance: FastifyInstance,
  options: FastifyVerifyOptions,
): Promise<void> {
  const field = options.tokenField ?? DEFAULT_TOKEN_FIELD_FASTIFY;
  const status = options.failureStatus ?? 422;
  instance.addHook('preValidation', async (req: FastifyRequest, reply: FastifyReply) => {
    const rawToken = readTokenFastify(req, field);
    if (rawToken === null) {
      await reply.code(status).send({
        error: { code: 'malformed_token', detail: `the ${field} field is missing` },
      });
      return reply;
    }
    const verifyOptions = await options.verify(req);
    const result = await verify(rawToken, verifyOptions);
    if (!result.ok) {
      await reply.code(status).send({
        error: { code: result.code === '' ? 'invalid' : result.code, detail: result.detail ?? 'verification failed' },
      });
      return reply;
    }
    (req as FastifyRequest & { kiwi?: unknown }).kiwi = result;
    return undefined;
  });
}

// The fastify-plugin marker: register this plugin in place, without a
// child encapsulation context, so the preValidation hook covers the
// routes the integrator registers on their own instance.
(kiwiVerifyFastify as unknown as Record<symbol, boolean>)[Symbol.for('skip-override')] = true;

declare module 'fastify' {
  interface FastifyRequest {
    /** The verification result once the kiwi hook passed. */
    kiwi?: {
      ok: boolean;
      disposition: 'allow' | 'deny';
      decisionHandle: string | null;
      price: string | null;
    };
  }
}
