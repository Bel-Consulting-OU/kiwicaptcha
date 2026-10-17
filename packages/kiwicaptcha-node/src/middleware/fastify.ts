import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { resolveClientIp } from '../clientip.js';
import { verify, type Disposition, type VerifyOptions } from '../verify.js';
import { headerTokenValues, resolveTokenValues, stringValues } from './token-source.js';

/**
 * The Fastify plugin: a preValidation hook that collects the token
 * from the header, the form or body field and the query parameter
 * under the shared authority rule, verifies the one agreed token
 * locally, and answers a definitive denial with the configured denial
 * response. A retry decision answers 503 Service Unavailable so a
 * backend outage stays retryable. A verified request exposes
 * request.kiwi for downstream handlers. When trustedProxies is
 * configured, the plugin resolves the canonical client IP itself (the
 * same trusted-proxy walk every SDK ships) and fills clientIp on the
 * factory's options when the factory left it unset, so fastify's own
 * trustProxy setting is never consulted and the behavior matches
 * every other framework.
 */

export const DEFAULT_TOKEN_FIELD_FASTIFY = 'kiwi__token';

export interface FastifyVerifyOptions {
  /** Per-request VerifyOptions factory; receives the request. */
  verify: (req: FastifyRequest) => VerifyOptions | Promise<VerifyOptions>;
  /** The body field carrying the token (default kiwi__token). */
  tokenField?: string;
  /** Failure status of a definitive denial (default 422). */
  failureStatus?: number;
  /** Status of a retry decision (default 503). */
  retryStatus?: number;
  /**
   * The trusted-proxy CIDR list. The default (option absent) leaves
   * the client-IP choice to the factory; when configured (an empty
   * list included), the socket peer is the client IP unless a trusted
   * hop justifies a forwarded entry.
   */
  trustedProxies?: string[];
}

/** Every header line for one name, preserving duplicates. */
function rawHeaderLines(req: FastifyRequest, name: string): string[] {
  const raw = (req.raw as { rawHeaders?: string[] }).rawHeaders ?? [];
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

/** The canonical client IP of one request per the shared contract. */
export function clientIpFromRequestFastify(req: FastifyRequest, trustedProxies: string[] = []): string {
  const socket = req.socket as { remoteAddress?: string } | undefined;
  const peer = socket?.remoteAddress ?? '';
  const lines = rawHeaderLines(req, 'x-forwarded-for');
  const realIpLines = rawHeaderLines(req, 'x-real-ip');
  // A repeated forwarding header is parser ambiguity (one intermediary
  // reads the first line, another the last): no header-derived identity
  // is trustworthy, so the peer wins. Never pick a line of a repeated
  // X-Real-IP, matching the shared resolver contract.
  if (lines.length > 1 || realIpLines.length > 1) {
    return peer;
  }
  return resolveClientIp({
    peer,
    xffLines: lines,
    realIp: realIpLines[0] ?? null,
    trustedProxies,
  });
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

/**
 * Register the Fastify verification plugin. The hook never throws: a
 * storage outage answers the retry disposition as 503 with the typed
 * storage_unavailable code, fail closed. The plugin carries fastify's
 * skip-override marker, so the hook applies to the routes of the
 * enclosing instance instead of a private child scope.
 */
export async function kiwiVerifyFastify(
  instance: FastifyInstance,
  options: FastifyVerifyOptions,
): Promise<void> {
  const field = options.tokenField ?? DEFAULT_TOKEN_FIELD_FASTIFY;
  const status = options.failureStatus ?? 422;
  const retryStatus = options.retryStatus ?? 503;
  instance.addHook('preValidation', async (req: FastifyRequest, reply: FastifyReply) => {
    const resolution = resolveTokenValues({
      header: headerTokenValues(
        (req.raw as { rawHeaders?: string[] }).rawHeaders,
        (req.headers as Record<string, unknown>)['x-kiwi-token'],
      ),
      form: bodyTokenValues(req.body, field),
      query: stringValues((req.query as Record<string, unknown>)[field]),
    });
    if (resolution.code !== null) {
      const detail = resolution.code === 'token_source_conflict'
        ? 'the request carries conflicting token sources'
        : `the ${field} field is missing`;
      await reply.code(status).send({
        error: { code: resolution.code, detail },
      });
      return reply;
    }
    const verifyOptions = await options.verify(req);
    if (options.trustedProxies !== undefined && (verifyOptions.clientIp === undefined || verifyOptions.clientIp === null)) {
      // With trustedProxies configured (an empty list included), the
      // plugin owns the client-IP boundary: it binds the socket peer,
      // or a forwarded entry when a trusted hop justifies one. A
      // factory-pinned clientIp always wins.
      verifyOptions.clientIp = clientIpFromRequestFastify(req, options.trustedProxies);
    }
    const result = await verify(resolution.token, verifyOptions);
    if (!result.ok) {
      await reply.code(result.disposition === 'retry' ? retryStatus : status).send({
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
      disposition: Disposition;
      decisionHandle: string | null;
      price: string | null;
    };
  }
}
