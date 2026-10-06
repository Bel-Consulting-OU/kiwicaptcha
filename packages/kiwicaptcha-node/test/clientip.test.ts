import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, test } from 'node:test';
import { canonicalIp, ipInTrusted, resolveClientIp } from '../src/clientip.js';

/**
 * The shared client-IP test vectors, asserted against the Node
 * resolver. Every SDK runs the same scenarios from
 * tools/client-ip/test-vectors.json, so one request resolves to one
 * canonical IP everywhere.
 */

const VECTORS = join(
  dirname(dirname(fileURLToPath(import.meta.url))),
  '..',
  '..',
  '..',
  'tools',
  'client-ip',
  'test-vectors.json',
);

interface VectorFile {
  cidr_cases: { cidr: string; ip: string; matches: boolean }[];
  scenarios: {
    id: string;
    peer: string;
    xff_lines: string[] | null;
    real_ip: string | null;
    trusted: string[];
    expected: string;
    expected_merged?: string;
    duplicate_detection?: boolean;
  }[];
}

function loadVectors(): VectorFile {
  return JSON.parse(readFileSync(VECTORS, 'utf8')) as VectorFile;
}

describe('shared client-ip vectors', () => {
  const vectors = loadVectors();

  test('cidr matcher edges', () => {
    for (const testCase of vectors.cidr_cases) {
      assert.equal(
        ipInTrusted(testCase.ip, [testCase.cidr]),
        testCase.matches,
        `cidr ${testCase.cidr} vs ${testCase.ip}`,
      );
    }
  });

  test('scenarios', () => {
    for (const scenario of vectors.scenarios) {
      // The Node surface sees every header line, so the duplicate
      // scenario asserts the fail-closed expectation.
      const resolved = resolveClientIp({
        peer: scenario.peer,
        xffLines: scenario.xff_lines,
        realIp: scenario.real_ip,
        trustedProxies: scenario.trusted,
      });
      assert.equal(resolved, scenario.expected, `scenario ${scenario.id}`);
    }
  });

  test('canonical ip edges', () => {
    assert.equal(canonicalIp(''), null);
    assert.equal(canonicalIp('unknown'), null);
    assert.equal(canonicalIp('_obfuscated'), null);
    assert.equal(canonicalIp('[2001:db8::1]:notaport'), null);
    assert.equal(canonicalIp('[2001:db8::1]garbage'), null);
    assert.equal(canonicalIp('1.2.3.4:0'), null);
    assert.equal(canonicalIp(' 192.0.2.10:4711 '), '192.0.2.10');
    assert.equal(canonicalIp('[2001:DB8::1]'), '2001:db8::1');
    assert.equal(canonicalIp('::ffff:198.51.100.5'), '198.51.100.5');
    assert.equal(canonicalIp('2001:0db8:0:0:0:0:0:1'), '2001:db8::1');
    assert.equal(canonicalIp('1.2.3.4.5'), null);
    assert.equal(canonicalIp('0:1.2.3.4'), null);
    assert.equal(canonicalIp('3232235521'), null);
  });
});
