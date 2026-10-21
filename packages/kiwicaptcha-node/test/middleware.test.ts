import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { after, before, describe, test } from 'node:test';
import express, { type Express } from 'express';
import Fastify from 'fastify';
import { goldenVectors, frozenClock } from './corpus.js';
import { challengeRecordFromJson } from '../src/record.js';
import { MemoryStore } from '../src/stores/memory.js';
import { StoreUnavailableError, type StoreAdapter } from '../src/store.js';
import { verify } from '../src/verify.js';
import { kiwiVerifyExpress, clientIpFromRequest } from '../src/middleware/express.js';
import { kiwiVerifyFastify, clientIpFromRequestFastify } from '../src/middleware/fastify.js';

/**
 * The framework middleware: reads the configured token field, verifies
 * locally, and on failure returns the framework-idiomatic error (422
 * JSON, or the configured redirect). Express is driven through a real
 * loopback HTTP server, Fastify through its inject harness.
 */

const SECRET = goldenVectors().hkdf.secret;

interface World {
  storage: StoreAdapter;
  token: string;
  nonce: string;
  scope: string;
  clock: { now: () => number; nowNs: number };
}

function world(name: string): World {
  const row = goldenVectors().records.find((entry) => entry.name === name);
  assert.ok(row !== undefined);
  const record = challengeRecordFromJson(row.record);
  // The golden record travels back to its issuance era on every clock.
  const storage = new MemoryStore({ now: () => record.issuedAt + 10 });
  void storage.store(record);
  return { storage, token: row.token_b64, nonce: record.nonce, scope: record.scope, clock: frozenClock(record) };
}

describe('express middleware', () => {
  let server: Server;
  let baseUrl: string;
  let state: World;

  function build(app: Express): void {
    app.use(express.urlencoded({ extended: false }));
    app.use(express.json());
    app.post(
      '/login',
      kiwiVerifyExpress({
        verify: () => ({
          storage: state.storage,
          secretKey: SECRET,
          expectedScope: state.scope,
          clientIp: '203.0.113.7',
          ...(state.clock as object),
        }),
      }),
      (req, res) => {
        const kiwi = (req as { kiwi?: { decisionHandle: string | null; price: string | null } }).kiwi;
        res.json({ ok: true, handle: kiwi?.decisionHandle, price: kiwi?.price });
      },
    );
    app.post(
      '/redirect',
      kiwiVerifyExpress({
        verify: () => ({ storage: state.storage, secretKey: SECRET, expectedScope: 'login', ...(state.clock as object) }),
        failureRedirect: '/captcha',
        tokenField: 'captcha',
      }),
      (req, res) => {
        res.json({ ok: true });
      },
    );
  }

  before(async () => {
    state = world('sha_plain');
    const app = express();
    build(app);
    await new Promise<void>((resolve) => {
      server = createServer(app);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    // destroy() kills keepalive sockets (fetch/undici pools) that would
    // otherwise keep the event loop alive after close() returns.
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  test('a valid form token passes and exposes the decision handle', async () => {
    const response = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ kiwi__token: state.token }).toString(),
    });
    assert.equal(response.status, 200);
    const body = (await response.json()) as { ok: boolean; handle: string | null };
    assert.equal(body.ok, true);
    assert.equal(body.handle, state.nonce);
  });

  test('a token in a JSON body or the x-kiwi-token header passes', async () => {
    // One-shot: every acceptance path redeems a fresh record copy.
    const bodies = [
      { 'content-type': 'application/json', body: JSON.stringify({ kiwi__token: state.token }) },
      { 'content-type': 'application/x-www-form-urlencoded', body: new URLSearchParams({ kiwi__token: state.token }).toString() },
      { 'content-type': 'text/plain', body: state.token },
    ];
    for (const [index, init] of bodies.entries()) {
      state = world('sha_plain');
      if (index === 2) {
        // The header path carries the token outside the body.
        init.body = '';
      }
      const response = await fetch(`${baseUrl}/login`, {
        method: 'POST',
        headers: index === 2 ? { 'x-kiwi-token': state.token } : init['content-type'] ? { 'content-type': init['content-type'] } : {},
        body: init.body,
      });
      assert.equal(response.status, 200, `path ${index}`);
    }
  });

  test('a missing token is 422 malformed_token JSON', async () => {
    const response = await fetch(`${baseUrl}/login`, { method: 'POST' });
    assert.equal(response.status, 422);
    const body = (await response.json()) as { error: { code: string } };
    assert.equal(body.error.code, 'malformed_token');
  });

  test('a failing token is 422 with the typed error code', async () => {
    const response = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'kiwi__token=not-a-token',
    });
    assert.equal(response.status, 422);
    const body = (await response.json()) as { error: { code: string } };
    assert.equal(body.error.code, 'malformed_token');
    // A replayed (consumed) token fails with its own verdict.
    const replay = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ kiwi__token: state.token }).toString(),
    });
    assert.equal(replay.status, 422);
    const replayBody = (await replay.json()) as { error: { code: string } };
    assert.equal(replayBody.error.code, 'already_consumed');
  });

  test('conflicting token sources are refused before any candidate verifies', async () => {
    const rows: { name: string; request: (token: string) => { url: string; init: RequestInit } }[] = [
      {
        name: 'header A / body B',
        request: (token) => ({
          url: `${baseUrl}/login`,
          init: {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-kiwi-token': token },
            body: new URLSearchParams({ kiwi__token: 'different-token' }).toString(),
          },
        }),
      },
      {
        name: 'header A / query B',
        request: (token) => ({
          url: `${baseUrl}/login?${new URLSearchParams({ kiwi__token: 'different-token' }).toString()}`,
          init: { method: 'POST', headers: { 'x-kiwi-token': token } },
        }),
      },
      {
        name: 'body A / query B',
        request: (token) => ({
          url: `${baseUrl}/login?${new URLSearchParams({ kiwi__token: 'different-token' }).toString()}`,
          init: {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ kiwi__token: token }).toString(),
          },
        }),
      },
      {
        name: 'two different header values',
        request: (token) => ({
          url: `${baseUrl}/login`,
          init: {
            method: 'POST',
            headers: [
              ['x-kiwi-token', token],
              ['x-kiwi-token', 'different-token'],
            ],
          },
        }),
      },
      {
        name: 'repeated form values',
        request: (token) => ({
          url: `${baseUrl}/login`,
          init: {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: `kiwi__token=${encodeURIComponent(token)}&kiwi__token=different-token`,
          },
        }),
      },
      {
        name: 'repeated query values',
        request: (token) => ({
          url: `${baseUrl}/login?kiwi__token=${encodeURIComponent(token)}&kiwi__token=different-token`,
          init: { method: 'POST' },
        }),
      },
    ];
    for (const row of rows) {
      state = world('sha_plain');
      const { url, init } = row.request(state.token);
      const response = await fetch(url, init);
      assert.equal(response.status, 422, row.name);
      const body = (await response.json()) as { error: { code: string } };
      assert.equal(body.error.code, 'token_source_conflict', row.name);
    }
  });

  test('the same token in every source still verifies', async () => {
    state = world('sha_plain');
    const query = new URLSearchParams({ kiwi__token: state.token }).toString();
    const response = await fetch(`${baseUrl}/login?${query}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'x-kiwi-token': state.token,
      },
      body: new URLSearchParams({ kiwi__token: state.token }).toString(),
    });
    assert.equal(response.status, 200);
    const body = (await response.json()) as { ok: boolean };
    assert.equal(body.ok, true);
  });

  test('a retry decision answers 503, never the denial status', async () => {
    state = world('sha_plain');
    const healthy = state.storage;
    state.storage = failingStore();
    try {
      const response = await fetch(`${baseUrl}/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ kiwi__token: state.token }).toString(),
      });
      assert.equal(response.status, 503);
      const body = (await response.json()) as { error: { code: string } };
      assert.equal(body.error.code, 'storage_unavailable');
    } finally {
      state.storage = healthy;
    }
  });

  test('the redirect mode and the custom field name apply', async () => {
    // One-shot: this path redeems its own fresh record copy.
    state = world('sha_plain');
    const ok = await fetch(`${baseUrl}/redirect`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ captcha: state.token }).toString(),
      redirect: 'manual',
    });
    assert.equal(ok.status, 200);
    const missing = await fetch(`${baseUrl}/redirect`, { method: 'POST', redirect: 'manual' });
    assert.equal(missing.status, 302);
    assert.equal(missing.headers.get('location'), '/captcha');
  });
});

describe('fastify middleware', () => {
  test('a valid token passes and failures are 422 JSON', async () => {
    const state = world('sha_bound');
    const app = Fastify();
    await app.register(kiwiVerifyFastify, {
      verify: (req) => ({
        storage: state.storage,
        secretKey: SECRET,
        expectedScope: state.scope,
        expectedRequestBinding: 'tx-1234',
        clientIp: (req.body as { ip?: string } | null)?.ip ?? null,
        ...state.clock,
      }),
    });
    app.post('/signup', async (req) => {
      const kiwi = (req as unknown as { kiwi?: { decisionHandle: string | null } }).kiwi;
      return { ok: true, handle: kiwi?.decisionHandle };
    });
    try {
      const ok = await app.inject({
        method: 'POST',
        url: '/signup',
        payload: { kiwi__token: state.token, ip: '203.0.113.7' },
      });
      assert.equal(ok.statusCode, 200);
      assert.equal((ok.json() as { handle: string }).handle, state.nonce);
      const missing = await app.inject({ method: 'POST', url: '/signup', payload: {} });
      assert.equal(missing.statusCode, 422);
      assert.equal((missing.json() as { error: { code: string } }).error.code, 'malformed_token');
      const bad = await app.inject({
        method: 'POST',
        url: '/signup',
        payload: { kiwi__token: 'garbage-token' },
      });
      assert.equal(bad.statusCode, 422);
      assert.equal((bad.json() as { error: { code: string } }).error.code, 'malformed_token');
      // The consumed token replays as already_consumed.
      const replay = await app.inject({
        method: 'POST',
        url: '/signup',
        payload: { kiwi__token: state.token, ip: '203.0.113.7' },
      });
      assert.equal(replay.statusCode, 422);
      assert.equal((replay.json() as { error: { code: string } }).error.code, 'already_consumed');
    } finally {
      await app.close();
    }
  });

  test('conflicting sources and the retry status follow the shared rows', async () => {
    const state = world('sha_plain');
    const app = Fastify();
    await app.register(kiwiVerifyFastify, {
      verify: () => ({
        storage: state.storage,
        secretKey: SECRET,
        expectedScope: state.scope,
        clientIp: '203.0.113.7',
        ...state.clock,
      }),
    });
    app.post('/login', async () => ({ ok: true }));
    try {
      const headerBody = await app.inject({
        method: 'POST',
        url: '/login',
        headers: { 'x-kiwi-token': state.token },
        payload: { kiwi__token: 'different-token' },
      });
      assert.equal(headerBody.statusCode, 422);
      assert.equal(
        (headerBody.json() as { error: { code: string } }).error.code,
        'token_source_conflict',
      );
      const headerQuery = await app.inject({
        method: 'POST',
        url: '/login?kiwi__token=different-token',
        headers: { 'x-kiwi-token': state.token },
      });
      assert.equal(headerQuery.statusCode, 422);
      assert.equal(
        (headerQuery.json() as { error: { code: string } }).error.code,
        'token_source_conflict',
      );
      const repeatedBody = await app.inject({
        method: 'POST',
        url: '/login',
        payload: { kiwi__token: [state.token, 'different-token'] },
      });
      assert.equal(repeatedBody.statusCode, 422);
      assert.equal(
        (repeatedBody.json() as { error: { code: string } }).error.code,
        'token_source_conflict',
      );

      // A retry decision is 503 even though the denial status is 422.
      const failing = Fastify();
      await failing.register(kiwiVerifyFastify, {
        verify: () => ({
          storage: failingStore(),
          secretKey: SECRET,
          expectedScope: state.scope,
          clientIp: '203.0.113.7',
          ...state.clock,
        }),
      });
      failing.post('/login', async () => ({ ok: true }));
      try {
        const retry = await failing.inject({
          method: 'POST',
          url: '/login',
          payload: { kiwi__token: state.token },
        });
        assert.equal(retry.statusCode, 503);
        assert.equal(
          (retry.json() as { error: { code: string } }).error.code,
          'storage_unavailable',
        );
      } finally {
        await failing.close();
      }
    } finally {
      await app.close();
    }
  });

  test('the plain verify call keeps the contract shape', async () => {
    const state = world('sha_plain');
    await state.storage.store(challengeRecordFromJson(
      goldenVectors().records.find((entry) => entry.name === 'sha_plain')?.record ?? {},
    ));
    const result = await verify(state.token, { storage: state.storage, secretKey: SECRET, expectedScope: 'login', ...state.clock });
    assert.deepEqual(
      { ok: result.ok, disposition: result.disposition },
      { ok: true, disposition: 'allow' },
    );
    assert.ok(result.price !== null);
    assert.ok(result.decisionHandle !== null);
  });
});

/** A store whose backend is down: every transition answers the
 * retryable storage_unavailable outcome. */
function failingStore(): StoreAdapter {
  const down = (): never => {
    throw new StoreUnavailableError('backend down');
  };
  return {
    authenticatedResultCommit: true,
    store: async () => down(),
    find: async () => down(),
    runtimeState: async () => down(),
    consume: async () => down(),
    commitResult: async () => down(),
    deleteIfPending: async () => down(),
  };
}

describe('adapter client-ip resolution', () => {
  const TRUSTED = ['10.0.0.0/24'];

  function expressReq(rawHeaders: string[]): Parameters<typeof clientIpFromRequest>[0] {
    return {
      rawHeaders,
      socket: { remoteAddress: '10.0.0.9' },
    } as unknown as Parameters<typeof clientIpFromRequest>[0];
  }

  function fastifyReq(rawHeaders: string[]): Parameters<typeof clientIpFromRequestFastify>[0] {
    return {
      raw: { rawHeaders },
      socket: { remoteAddress: '10.0.0.9' },
    } as unknown as Parameters<typeof clientIpFromRequestFastify>[0];
  }

  test('a single trusted-hop X-Real-IP is honored', () => {
    const headers = ['X-Real-IP', '198.51.100.5'];
    assert.equal(clientIpFromRequest(expressReq(headers), TRUSTED), '198.51.100.5');
    assert.equal(clientIpFromRequestFastify(fastifyReq(headers), TRUSTED), '198.51.100.5');
  });

  test('a repeated X-Real-IP is parser ambiguity and never selects a line', () => {
    // One intermediary reads the first line, another the last: a
    // header-derived identity is untrustworthy and the peer wins. This
    // must never pick the attacker-supplied first line.
    const headers = ['X-Real-IP', '1.2.3.4', 'X-Real-IP', '10.0.0.9'];
    assert.equal(clientIpFromRequest(expressReq(headers), TRUSTED), '10.0.0.9');
    assert.equal(clientIpFromRequestFastify(fastifyReq(headers), TRUSTED), '10.0.0.9');
  });

  test('a repeated X-Real-IP also overrides a valid X-Forwarded-For chain', () => {
    const headers = [
      'X-Forwarded-For', '198.51.100.5',
      'X-Real-IP', '1.2.3.4',
      'X-Real-IP', '5.6.7.8',
    ];
    assert.equal(clientIpFromRequest(expressReq(headers), TRUSTED), '10.0.0.9');
    assert.equal(clientIpFromRequestFastify(fastifyReq(headers), TRUSTED), '10.0.0.9');
  });
});
