import assert from 'node:assert/strict';
import { test } from 'node:test';
import { executionCorpus } from './corpus.js';
import {
  decodeProgram,
  isValidProgram,
  verifyExecutedTrace,
  digestOverTrace,
  expectedDigest,
  canonicalTrace,
} from '../src/execution.js';

/**
 * The execution differential corpus: the adversarial program and trace
 * shapes the audit produced, ported from the PHP
 * ExecutionDifferentialCorpusTest and its Rust twin. Every case must
 * land on the same classification in this interpreter.
 */

test('the corpus cases classify identically to the PHP and Rust cores', () => {
  const corpus = executionCorpus();
  assert.equal(corpus.cases.length, 19);
  for (const row of corpus.cases) {
    const programOk = isValidProgram(row.program);
    if (row.expected === 'malformed') {
      assert.equal(programOk, false, `${row.name}: the program must be malformed`);
      assert.equal(decodeProgram(row.program), null);
      continue;
    }
    assert.equal(programOk, true, `${row.name}: the program must parse`);
    if (row.expected === 'execution_mismatch') {
      assert.equal(
        verifyExecutedTrace(row.program, corpus.nonce, row.trace),
        null,
        `${row.name}: the trace must fail the walk`,
      );
      continue;
    }
    const verified = verifyExecutedTrace(row.program, corpus.nonce, row.trace);
    assert.equal(verified, row.trace, `${row.name}: the trace must verify verbatim`);
    const digest = digestOverTrace(row.program, corpus.nonce, verified);
    assert.match(digest ?? '', /^[0-9a-f]{64}$/);
    // When the submitted trace has no browser-observed entries it
    // equals the canonical trace, so both digests coincide.
    const program = decodeProgram(row.program);
    assert.ok(program !== null);
    if (canonicalTrace(program) === row.trace) {
      assert.equal(digest, expectedDigest(row.program, corpus.nonce), `${row.name}: deterministic digests agree`);
    }
  }
});

test('the valid traces digest under their program and reject foreign nonces', () => {
  const corpus = executionCorpus();
  const valid = corpus.cases.filter((row) => row.expected === 'valid');
  assert.ok(valid.length >= 5);
  for (const row of valid) {
    const program = decodeProgram(row.program);
    assert.ok(program !== null);
    const foreign = digestOverTrace(row.program, 'cG9pc29uLW5vbmNlLXZlY3RvcgAAAAA=', row.trace);
    assert.notEqual(foreign, digestOverTrace(row.program, corpus.nonce, row.trace));
    // The canonical trace of the program is a pure function of it.
    assert.equal(typeof canonicalTrace(program), 'string');
  }
});

test('mutated traces of a valid program always fail the walk', () => {
  const corpus = executionCorpus();
  const valid = corpus.cases.find((row) => row.name === 'v1-valid');
  assert.ok(valid !== undefined);
  const mutations = [
    valid.trace.replace(';dappend(1);', ';dappend(0);'),
    valid.trace + ';add(1)',
    valid.trace.replace(/^dcreate\(/, 'dclone('),
    // Zero-height geometry is the layout rule class.
    valid.trace.replace(/geom\(\d+,\d+\)/, 'geom(7,0)'),
    valid.trace.slice(1),
    valid.trace.replace(';', ''),
    valid.trace.replace('evreal(kiwi-ev:div)', 'evreal(kiwi-ev:span)'),
    valid.trace.replace('u8rot(0)', 'u8rot(1)'),
    // Deterministic entries are exact: one bit flips, the walk fails.
    valid.trace.replace('or(3621764315)', 'or(3621764316)'),
    valid.trace.replace('shr(15901358)', 'shr(15901359)'),
    valid.trace.replace('dappend(1);', 'dappend(1);dappend(1);'),
  ];
  for (const mutated of mutations) {
    assert.equal(
      verifyExecutedTrace(valid.program, corpus.nonce, mutated),
      null,
      `mutation must fail: ${mutated.slice(0, 40)}`,
    );
  }
});
