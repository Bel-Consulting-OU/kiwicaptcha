// The node test of the zitadel action script's pure core and the
// guard flow over a stubbed fetch. Run: node tests/kiwi-signup-guard.test.mjs
import { createRequire } from "node:module";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const guard = require("../scripts/kiwi-signup-guard.js");

let checks = 0;
function check(name, fn) {
  checks++;
  try {
    fn();
  } catch (e) {
    console.error(`FAIL: ${name}: ${e.message}`);
    process.exitCode = 1;
  }
}

// The wire request.
check("request shape", () => {
  const request = guard.buildRequest("http://127.0.0.1:7371/verify", "t", "signup", "192.0.2.6", "b");
  assert.equal(request.url, "http://127.0.0.1:7371/verify");
  assert.equal(request.headers.Authorization, "Bearer b");
  const body = JSON.parse(request.body);
  assert.equal(body.token, "t");
  assert.equal(body.scope, "signup");
  assert.equal(body.remoteip, "192.0.2.6");
});

// The decision table.
check("success verifies", () => {
  assert.deepEqual(guard.decide(200, '{"success":true}'), { ok: true, code: "verified" });
});
check("failure denies", () => {
  assert.deepEqual(guard.decide(200, '{"success":false}'), { ok: false, code: "challenge_failed" });
});
check("5xx is a fault", () => {
  assert.deepEqual(guard.decide(502, ""), { ok: false, code: "verify_unavailable" });
});
check("garbage body is unreadable", () => {
  assert.deepEqual(guard.decide(200, "<html>"), { ok: false, code: "verify_unreadable" });
});
check("302 with success body fails closed", () => {
  assert.deepEqual(guard.decide(302, '{"success":true}'), { ok: false, code: "challenge_failed" });
});
check("403 with success body fails closed", () => {
  assert.deepEqual(guard.decide(403, '{"success":true}'), { ok: false, code: "challenge_failed" });
});
check("429 with success body fails closed", () => {
  assert.deepEqual(guard.decide(429, '{"success":true}'), { ok: false, code: "challenge_failed" });
});
check("199 with success body fails closed", () => {
  assert.deepEqual(guard.decide(199, '{"success":true}'), { ok: false, code: "challenge_failed" });
});
check("204 with success body passes", () => {
  assert.deepEqual(guard.decide(204, '{"success":true}'), { ok: true, code: "verified" });
});

// verify() against a stubbed fetch.
function stubFetch(status, body, capture) {
  guard.verify && null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (capture) capture.push({ url, init });
    return {
      status,
      text: async () => body,
    };
  };
  return () => {
    globalThis.fetch = original;
  };
}

check("verify success", async () => {
  const restore = stubFetch(200, '{"success":true}');
  try {
    const result = await guard.verify(guard.KIWI_VERIFY_URL, "", "good-token", "signup", "192.0.2.6");
    assert.deepEqual(result, { ok: true, code: "verified" });
  } finally {
    restore();
  }
});

check("verify failure", async () => {
  const restore = stubFetch(200, '{"success":false}');
  try {
    const result = await guard.verify(guard.KIWI_VERIFY_URL, "", "stale", "signup", "192.0.2.6");
    assert.deepEqual(result, { ok: false, code: "challenge_failed" });
  } finally {
    restore();
  }
});

check("verify transport failure", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("down");
  };
  try {
    const result = await guard.verify(guard.KIWI_VERIFY_URL, "", "good", "signup", "192.0.2.6");
    assert.deepEqual(result, { ok: false, code: "verify_unavailable" });
  } finally {
    globalThis.fetch = original;
  }
});

check("missing token short circuits", async () => {
  const result = await guard.verify(guard.KIWI_VERIFY_URL, "", "  ", "signup", "192.0.2.6");
  assert.deepEqual(result, { ok: false, code: "missing_token" });
});

check("missing client ip refuses with missing_client_ip", async () => {
  const result = await guard.verify(guard.KIWI_VERIFY_URL, "", "good", "signup", "");
  assert.deepEqual(result, { ok: false, code: "missing_client_ip" });
});

check("blank client ip refuses with missing_client_ip (never 127.0.0.1)", async () => {
  const result = await guard.verify(guard.KIWI_VERIFY_URL, "", "good", "signup", "   ");
  assert.deepEqual(result, { ok: false, code: "missing_client_ip" });
});

check("guard aborts with missing_client_ip when the request has no ip", async () => {
  const restore = stubFetch(200, '{"success":true}');
  const aborts = [];
  try {
    await guard.guardPreCreation(
      { request: { kiwiToken: "good" } },
      { abort: (message) => aborts.push(message) },
    );
    assert.equal(aborts.length, 1);
  } finally {
    restore();
  }
});

// The guard flow over the stub: abort on failure, continue on success.
check("guard aborts on failure", async () => {
  const restore = stubFetch(200, '{"success":false}');
  const aborts = [];
  try {
    await guard.guardPreCreation(
      { request: { kiwiToken: "stale", ipAddress: "192.0.2.6" } },
      { abort: (message) => aborts.push(message) },
    );
    assert.equal(aborts.length, 1);
  } finally {
    restore();
  }
});

check("guard continues on success", async () => {
  const restore = stubFetch(200, '{"success":true}');
  const aborts = [];
  try {
    await guard.guardPreCreation(
      { request: { kiwiToken: "good", ipAddress: "192.0.2.6" } },
      { abort: (message) => aborts.push(message) },
    );
    assert.equal(aborts.length, 0);
  } finally {
    restore();
  }
});

check("guard aborts on a missing token", async () => {
  const aborts = [];
  await guard.guardPreCreation({ request: {} }, { abort: (message) => aborts.push(message) });
  assert.equal(aborts.length, 1);
});

check("guard fails closed by throwing when the runtime offers no abort", async () => {
  let threw = false;
  try {
    await guard.guardPreCreation({ request: {} }, {});
  } catch (e) {
    threw = true;
    assert.match(String(e && e.message), /kiwi-captcha guard/);
  }
  assert.ok(threw, "without api.abort the action must throw so user creation never continues");
});

console.log(`${checks} checks${process.exitCode ? ", failures above" : ", all green"}`);
