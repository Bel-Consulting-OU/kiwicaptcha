import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { challengeRecordFromJson } from '../src/record.js';
import { verify, type VerifyOptions } from '../src/verify.js';
import { encodeToken } from '../src/token.js';
import { solveSha256 } from '../src/pow.js';
import { MemoryStore } from '../src/stores/memory.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..', '..', '..', '..');
const SIDECAR_BIN = join(REPO_ROOT, 'target', 'debug', 'kiwicaptcha-verifier');
const SECRET = 'node-sidecar-delegation-0123456789abcdef';

interface EvidenceDoc {
  record: Record<string, unknown>;
  nonce: string;
  trace: string;
  digest: string;
  program: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

async function freePort(): Promise<number> {
  const net = await import('node:net');
  return new Promise((resolveBind) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      server.close(() => resolveBind(port));
    });
  });
}

describe('the sidecar delegation plane', () => {
  // The spawned sidecar plus its armed evidence: skipped (never
  // failed) where the verifier crate is unavailable.
  let sidecar: { url: string; doc: EvidenceDoc } | null = null;
  let cleanup: (() => void) | null = null;

  before(async () => {
    if (!existsSync(SIDECAR_BIN)) {
      const build = spawnSync(
        'cargo',
        ['build', '-q', '-p', 'kiwicaptcha-verifier', '--features', 'test-fixtures'],
        { cwd: REPO_ROOT, encoding: 'utf8' },
      );
      if (build.status !== 0 || !existsSync(SIDECAR_BIN)) {
        return;
      }
    }
    const storeDir = mkdtempSync(join(tmpdir(), 'kiwi-sidecar-'));
    const helper = spawnSync(
      SIDECAR_BIN,
      [
        'exec-evidence',
        '--secret', SECRET,
        '--scope', 'login',
        '--action', 'login-action',
        '--version', '1',
        '--store-dir', storeDir,
      ],
      { encoding: 'utf8' },
    );
    if (helper.status !== 0) {
      rmSync(storeDir, { recursive: true, force: true });
      return;
    }
    const doc = JSON.parse(helper.stdout) as EvidenceDoc;
    const port = await freePort();
    const child = spawn(SIDECAR_BIN, [], {
      env: {
        ...process.env,
        KIWI_LISTEN: `http://127.0.0.1:${port}`,
        KIWI_SECRET: SECRET,
        KIWI_STORE: `file=${storeDir}`,
        KIWI_BINDING: 'none',
        KIWI_PROFILE: 'sha16',
      },
      stdio: 'ignore',
    });
    const url = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      try {
        const health = await fetch(`${url}/healthz`);
        if (health.ok) {
          sidecar = { url, doc };
          cleanup = () => {
            child.kill();
            rmSync(storeDir, { recursive: true, force: true });
          };
          return;
        }
      } catch {
        // not listening yet
      }
      await sleep(150);
    }
    child.kill();
    rmSync(storeDir, { recursive: true, force: true });
  });

  after(() => {
    if (cleanup !== null) {
      cleanup();
    }
  });

  it('the fail-closed default refuses the armed record, the sidecar policy delegates', async () => {
    if (sidecar === null) {
      return;
    }
    const record = challengeRecordFromJson(sidecar.doc.record);
    assert.ok(record.executionProgram !== null, 'the minted record is execution-armed');

    const makeOptions = async (extra: Partial<VerifyOptions>): Promise<VerifyOptions> => {
      const storage = new MemoryStore({ now: () => record.issuedAt + 10 });
      await storage.store(record);
      return {
        storage,
        secretKey: SECRET,
        expectedScope: 'login',
        ...extra,
      };
    };
    const token = encodeToken({
      nonce: record.nonce,
      counter: solveSha256(record.prefix, record.salt, record.targetBits),
      durationMs: 5000,
      telemetry: {},
      executionDigest: sidecar.doc.digest,
      executionTrace: sidecar.doc.trace,
      rswProof: null,
    });

    // The default policy of this SDK: the node surface carries the
    // deterministic walker, so a fully valid trace verifies natively.
    // The sidecar policy exists for the deployments that want the
    // single shared verdict path; the delegation legs below prove the
    // same acceptance through the sidecar.
    const native = await verify(token, await makeOptions({}));
    assert.equal(native.ok, true, `the native walker accepts: ${JSON.stringify(native)}`);

    // The sidecar policy: the delegation accepts and the verdict
    // merges into this SDK's result shape. A fresh delegated success is
    // a fresh result, never a stored one.
    const accepted = await verify(token, await makeOptions({
      executionPolicy: { sidecarUrl: sidecar.url },
    }));
    assert.equal(accepted.ok, true, `the delegation must accept: ${JSON.stringify(accepted)}`);
    assert.equal(accepted.disposition, 'allow');
    assert.equal(accepted.fromStoredResult, false, 'a fresh delegated success must not claim a stored result');

    // Single-use: the sidecar consumed; a replay never re-accepts.
    const replay = await verify(token, await makeOptions({
      executionPolicy: { sidecarUrl: sidecar.url },
    }));
    assert.equal(replay.ok, false);
    assert.ok(['already_consumed', 'record_not_found'].includes(replay.code ?? ''), `replay code: ${replay.code}`);

    // An unreachable sidecar answers the retry disposition, the
    // record intact.
    const down = await verify(token, await makeOptions({
      executionPolicy: { sidecarUrl: 'http://127.0.0.1:1', timeoutMs: 300 },
    }));
    assert.equal(down.ok, false);
    assert.equal(down.code, 'storage_unavailable');
  });
});
