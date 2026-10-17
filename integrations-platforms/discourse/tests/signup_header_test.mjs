// The plain-node test of the signup header asset. The real browser
// script is loaded into a vm context with fake window/document
// objects; the fetch wrapper must attach X-Kiwi-Token to the sign-up
// paths the server gates, including /users and /users.json (the
// config default), and to nothing else.
//
// Run: node tests/signup_header_test.mjs

import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(
  new URL("../assets/javascripts/kiwi-signup-header.js", import.meta.url),
  "utf8",
);

let failures = 0;
let checks = 0;

function check(name, condition) {
  checks += 1;
  if (condition) return;
  failures += 1;
  console.error(`FAIL: ${name}`);
}

function load() {
  const calls = [];
  const window = {
    fetch(input, init) {
      calls.push({ input, init });
      return Promise.resolve("ok");
    },
    Discourse: { __container__: {} },
  };
  const document = {
    querySelector: () => ({ value: " token-value " }),
    cookie: "",
  };
  const context = vm.createContext({ window, document, Headers, decodeURIComponent });
  vm.runInContext(source, context, { filename: "kiwi-signup-header.js" });
  return { window, calls };
}

async function headerFor(path, init = { method: "POST" }) {
  const { window, calls } = load();
  await window.fetch(path, init);
  const headers = calls[0].init && calls[0].init.headers;
  return headers instanceof Headers ? headers.get("X-Kiwi-Token") : null;
}

for (const path of ["/u", "/u.json", "/users", "/users.json"]) {
  check(`${path} carries the token`, (await headerFor(path)) === "token-value");
}

for (const path of [
  "https://forum.example/u",
  "https://forum.example/users.json",
]) {
  check(`${path} carries the token`, (await headerFor(path)) === "token-value");
}

check("/user is not a sign-up path", (await headerFor("/user")) === null);
check("/login is not a sign-up path", (await headerFor("/login")) === null);
check("GET requests are untouched", (await headerFor("/users", { method: "GET" })) === null);
check(
  "an existing header survives",
  (await headerFor("/users", { method: "POST", headers: { "X-Other": "1" } })) ===
    "token-value",
);

console.log(`${checks} checks, ${failures} failures`);
process.exit(failures === 0 ? 0 : 1);
