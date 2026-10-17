import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ALL_VERIFY_ERROR_CODES, VerifyErrorCode } from '../src/errors.js';
import { readProtocol } from './corpus.js';
import {
  RETRY_ERROR_CODES,
  dispositionForCode,
  invalidResult,
} from '../src/verify.js';
import { resolveTokenValues } from '../src/middleware/token-source.js';

/**
 * The shared decision and authority register: protocol/decision-v1/
 * corpus.json. This suite is the Node side of the cross-SDK rows the
 * D3.17 campaign replays; a drift from the register fails here first.
 */

interface AuthorityRow {
  case: string;
  header: string[];
  form: string[];
  query: string[];
  verdict: 'verify' | 'conflict' | 'missing';
  token?: string;
}

interface DecisionCorpus {
  dispositions: string[];
  retry_codes: string[];
  codes: Record<string, string>;
  http: {
    allow_status: number;
    retry_status: number;
    deny_status: Record<string, number>;
  };
  authority: {
    conflict_code: string;
    missing_code: string;
    matrix: AuthorityRow[];
  };
}

function corpus(): DecisionCorpus {
  return readProtocol('decision-v1/corpus.json') as DecisionCorpus;
}

test('decision corpus: every wire code maps to its registered disposition', () => {
  const register = corpus();
  assert.deepEqual([...ALL_VERIFY_ERROR_CODES].sort(), Object.keys(register.codes).sort());
  for (const [code, disposition] of Object.entries(register.codes)) {
    assert.equal(
      dispositionForCode(code as VerifyErrorCode),
      disposition,
      `disposition for ${code}`,
    );
    const result = invalidResult(code as VerifyErrorCode);
    assert.equal(result.ok, false, `${code} must not verify`);
    assert.equal(result.disposition, disposition, `result disposition for ${code}`);
    assert.equal(result.code, code);
  }
});

test('decision corpus: the retry table is exactly the four transient codes', () => {
  const register = corpus();
  assert.deepEqual([...RETRY_ERROR_CODES].sort(), [...register.retry_codes].sort());
  for (const code of register.retry_codes) {
    assert.equal(dispositionForCode(code as VerifyErrorCode), 'retry');
  }
});

test('decision corpus: the middleware status rows agree with the register', () => {
  const register = corpus();
  assert.equal(register.http.allow_status, 200);
  assert.equal(register.http.retry_status, 503);
  assert.equal(register.http.deny_status['node'], 422);
});

test('authority corpus: every row resolves under reject-on-conflict', () => {
  const register = corpus();
  assert.equal(register.authority.conflict_code, 'token_source_conflict');
  assert.equal(register.authority.missing_code, 'malformed_token');
  for (const row of register.authority.matrix) {
    const resolution = resolveTokenValues({
      header: row.header,
      form: row.form,
      query: row.query,
    });
    if (row.verdict === 'verify') {
      assert.equal(resolution.code, null, `${row.case}: must verify, not refuse`);
      assert.equal(resolution.token, row.token, `${row.case}: the agreed token`);
    } else if (row.verdict === 'conflict') {
      assert.equal(resolution.code, 'token_source_conflict', `${row.case}: conflict`);
      assert.equal(resolution.token, null, `${row.case}: no candidate is selected`);
    } else {
      assert.equal(resolution.code, 'malformed_token', `${row.case}: missing`);
    }
  }
});
