import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { after, before, describe, test } from 'node:test';
import express, { type Express } from 'express';
import Fastify from 'fastify';
import { goldenVectors, frozenClock } from './corpus.js';
import { challengeRecordFromJson } from '../src/record.js';
import { MemoryStore } from '../src/stores/memory.js';
import { verify } from '../src/verify.js';
import { kiwiVerifyExpress } from '../src/middleware/express.js';
import { kiwiVerifyFastify } from '../src/middleware/fastify.js';

/**
 * The framework middleware: reads the configured token field, verifies
 * locally, and on failure returns the framework-idiomatic error (422
 * JSON, or the configured redirect). Express is driven through a real
 * loopback HTTP server, Fastify through its inject harness.
 */

const SECRET = goldenVectors().hkdf.secret;

interface World {
  storage: MemoryStore;
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

  after(() => {
    server.close();
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
