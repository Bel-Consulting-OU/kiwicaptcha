#!/usr/bin/env node
/**
 * Raw-HTTP attacks against the live gateway endpoint (kiwi-verify.php
 * under php -S), the shapes a curl call cannot express: literal CRLF
 * in form tokens, misstated Content-Length framing with a smuggled
 * second request, over-cap bodies, UTF-16 BOM bodies, content-type
 * confusion across media-type spellings, healthz path confusion and a
 * CRLF-bearing deny redirect target. One assert per attack; any
 * failure exits non-zero.
 *
 * Usage: node tests/attack-gate.mjs (cwd irrelevant).
 */

import net from "node:net";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const STUB_PORT = 18794;
const GATE_PORT = 18795;
const SPLIT_PORT = 18796;

let failures = 0;
let checks = 0;
function check(name, condition, detail = "") {
  checks += 1;
  if (!condition) {
    failures += 1;
    console.error(`FAIL: ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

const children = [];
function boot(args, env) {
  const child = spawn("php", args, {
    env: { ...process.env, ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  children.push(child);
  return child;
}

function cleanup() {
  for (const child of children) {
    child.kill("SIGKILL");
  }
}

/** Send one raw request and read until the server closes. */
function raw(port, payload, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port }, () => {
      socket.write(payload);
      // Half-close so a Content-Length reader sees the end of body.
      socket.end();
    });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error("socket timeout"));
    });
    const chunks = [];
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("error", (err) => {
      // A reset after the server answered still yields partial bytes.
      if (chunks.length > 0) {
        resolve(Buffer.concat(chunks));
      } else {
        reject(err);
      }
    });
    socket.on("close", () => resolve(Buffer.concat(chunks)));
  });
}

function statusOf(response) {
  const text = response.toString("latin1");
  const match = text.match(/^HTTP\/\S+\s+(\d{3})/);
  return match ? Number(match[1]) : 0;
}

function headOf(response) {
  const text = response.toString("latin1");
  const split = text.indexOf("\r\n\r\n");
  return split === -1 ? text : text.slice(0, split);
}

function bodyOf(response) {
  const text = response.toString("latin1");
  const split = text.indexOf("\r\n\r\n");
  return split === -1 ? "" : text.slice(split + 4);
}

function post(port, path, headers, body) {
  const head = [
    `POST ${path} HTTP/1.1`,
    "host: attack.test",
    ...headers.map(([name, value]) => `${name}: ${value}`),
    `content-length: ${Buffer.byteLength(body, "latin1")}`,
    "connection: close",
    "",
    "",
  ].join("\r\n");
  return raw(port, head + body);
}

function get(port, path) {
  return raw(port, `GET ${path} HTTP/1.1\r\nhost: attack.test\r\nconnection: close\r\n\r\n`);
}

async function main() {
  boot(["-S", `127.0.0.1:${STUB_PORT}`, join(HERE, "stub-kiwi-router.php")], {});
  boot(
    ["-S", `127.0.0.1:${GATE_PORT}`, join(HERE, "endpoint-router.php")],
    {
      KIWI_VERIFY_URL: `http://127.0.0.1:${STUB_PORT}/verify`,
    },
  );
  boot(
    ["-S", `127.0.0.1:${SPLIT_PORT}`, join(HERE, "endpoint-router.php")],
    {
      KIWI_VERIFY_URL: `http://127.0.0.1:${STUB_PORT}/verify`,
      KIWI_DENY: "302",
      KIWI_REDIRECT: "/need-captcha\r\nSet-Cookie: evil=1",
    },
  );

  // Wait for the gate to answer.
  for (let i = 0; i < 60; i += 1) {
    try {
      const response = await get(GATE_PORT, "/healthz");
      if (statusOf(response) > 0) break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  // --- header / response splitting through a form token with CRLF.
  const crlfBody = "kiwi__token=good%0d%0aX-Injected%3A%201";
  let response = await post(
    GATE_PORT,
    "/kiwi-verify.php",
    [["content-type", "application/x-www-form-urlencoded"]],
    crlfBody,
  );
  check(
    "CRLF form token never splits the response",
    statusOf(response) === 403 && !headOf(response).toLowerCase().includes("x-injected"),
    `status ${statusOf(response)} head ${headOf(response)}`,
  );

  // --- healthz is an exact path, not a suffix.
  response = await get(GATE_PORT, "/healthz");
  check(
    "exact /healthz answers the health document",
    statusOf(response) === 200 && bodyOf(response).includes('"status":"ok"'),
    bodyOf(response),
  );
  response = await get(GATE_PORT, "/admin/healthz");
  check(
    "/admin/healthz is not the health document",
    statusOf(response) === 403 && !bodyOf(response).includes('"status"'),
    `status ${statusOf(response)} body ${bodyOf(response)}`,
  );

  // --- content-type confusion across spellings.
  for (const media of [
    "application/jsonp",
    "application/json-seq",
    "text/application/json",
    "application/jsonx",
  ]) {
    response = await post(
      GATE_PORT,
      "/kiwi-verify.php",
      [["content-type", media]],
      '{"kiwi_token":"good"}',
    );
    check(
      `media type ${media} does not open the JSON token source`,
      statusOf(response) === 403,
      `status ${statusOf(response)}`,
    );
  }
  response = await post(
    GATE_PORT,
    "/kiwi-verify.php",
    [["content-type", "Application/JSON; charset=UTF-8"]],
    '{"kiwi_token":"good"}',
  );
  check(
    "exact json media type (any case/params) opens the source",
    statusOf(response) === 204,
    `status ${statusOf(response)}`,
  );

  // --- body bombs: an over-cap JSON body contributes no token source.
  const pad = "a".repeat(70 * 1024);
  response = await post(
    GATE_PORT,
    "/kiwi-verify.php",
    [["content-type", "application/json"]],
    `{"kiwi_token":"good","pad":"${pad}"}`,
  );
  check(
    "over-cap JSON body never contributes a token",
    statusOf(response) === 403,
    `status ${statusOf(response)}`,
  );
  const smallPad = "a".repeat(1024);
  response = await post(
    GATE_PORT,
    "/kiwi-verify.php",
    [["content-type", "application/json"]],
    `{"kiwi_token":"good","pad":"${smallPad}"}`,
  );
  check(
    "under-cap JSON body with a valid token still passes",
    statusOf(response) === 204,
    `status ${statusOf(response)}`,
  );

  // --- UTF-16 BOM body is opaque: never a decoded token.
  const utf16 = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from('{"kiwi_token":"good"}', "utf16le"),
  ]);
  response = await raw(
    GATE_PORT,
    Buffer.concat([
      Buffer.from(
        "POST /kiwi-verify.php HTTP/1.1\r\nhost: attack.test\r\ncontent-type: application/json\r\n" +
          `content-length: ${utf16.length}\r\nconnection: close\r\n\r\n`,
      ),
      utf16,
    ]),
  );
  check(
    "UTF-16 BOM body contributes no token",
    statusOf(response) === 403,
    `status ${statusOf(response)}`,
  );

  // --- token sources are closed: query strings are never sources.
  response = await post(
    GATE_PORT,
    "/kiwi-verify.php?kiwi_token=good",
    [["content-type", "application/json"]],
    "{}",
  );
  check(
    "query-string token is never consumed",
    statusOf(response) === 403,
    `status ${statusOf(response)}`,
  );

  // --- extraction order is fixed: the header candidate wins over a
  // good cookie, so a decoy header can only hurt the caller itself.
  response = await raw(
    GATE_PORT,
    "GET /kiwi-verify.php HTTP/1.1\r\nhost: attack.test\r\nx-kiwi-token: bogus\r\ncookie: kiwi_token=good\r\nconnection: close\r\n\r\n",
  );
  check(
    "header candidate outranks the cookie (order is fixed)",
    statusOf(response) === 403,
    `status ${statusOf(response)}`,
  );

  // --- framing: a Content-Length that understates the body must not
  // let the trailing bytes be answered as a second request (php -S
  // refuses the malformed pipeline outright — zero responses is also
  // a pass; a single response for the first request is a pass too).
  response = await raw(
    GATE_PORT,
    "POST /kiwi-verify.php HTTP/1.1\r\nhost: attack.test\r\ncontent-type: application/json\r\ncontent-length: 5\r\nconnection: close\r\n\r\n" +
      'xxxxxGET /healthz HTTP/1.1\r\nhost: attack.test\r\n\r\n',
  );
  const responseCount = (response.toString("latin1").match(/HTTP\/1\.1 /g) || []).length;
  check(
    "an understated Content-Length never smuggles a second response",
    responseCount <= 1 && !bodyOf(response).includes('"status":"ok"'),
    `responses ${responseCount} body ${bodyOf(response).slice(0, 120)}`,
  );

  // --- a CRLF-bearing deny redirect target fails the config audit:
  // every request through that gate answers 503 (fail closed) and a
  // split Location / Set-Cookie header can never be emitted.
  response = await raw(
    SPLIT_PORT,
    "GET /kiwi-verify.php HTTP/1.1\r\nhost: attack.test\r\nconnection: close\r\n\r\n",
  );
  const splitHead = headOf(response).toLowerCase();
  check(
    "CRLF redirect target fails closed with no split headers",
    statusOf(response) === 503 &&
      !splitHead.includes("set-cookie") &&
      !splitHead.includes("location:"),
    `status ${statusOf(response)} head ${headOf(response)}`,
  );

  console.log(`${checks} checks, ${failures} failures`);
  cleanup();
  process.exit(failures === 0 ? 0 : 1);
}

process.on("exit", cleanup);
main().catch((err) => {
  console.error(`FAIL: harness error: ${err.stack || err}`);
  cleanup();
  process.exit(1);
});
