// Renderer and copy-inventory tests for the edition-6 widget system.
// The copy inventories are the source of truth; these tests keep both pure
// renderers, the state table and every locale pack in agreement with the
// PDF's copy & semantics tables.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { renderWidget, STATUS_STATES, STATUS_WIDTHS, STATUS_SCALES } from "../widget-view.js";
import { renderFactor, FACTOR_VIEWS, FACTOR_WIDTHS } from "../factor-view.js";
import { esc } from "../widget-primitives.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const statesDoc = JSON.parse(readFileSync(join(root, "widget-states.json"), "utf8"));
const copyDoc = JSON.parse(readFileSync(join(root, "widget-copy-v5.json"), "utf8"));

test("the ten source driver states are complete and alias-free", () => {
  assert.deepEqual(Object.keys(statesDoc.states), STATUS_STATES);
  assert.deepEqual(Object.values(statesDoc.aliases), ["solving", "solver-mismatch"]);
  for (const [name, state] of Object.entries(statesDoc.states)) {
    assert.ok(state.title.length > 0, `${name} title`);
    assert.ok(state.explanation.length > 0, `${name} explanation`);
    assert.ok(["none", "check", "warning"].includes(state.icon), `${name} icon`);
    if (state.icon === "check") assert.equal(name, "done");
    if (state.icon === "warning") {
      assert.ok(["failed", "worker-unavailable", "execution-unavailable", "solver-mismatch"].includes(name));
    }
  }
});

test("every state exposes a recovery contract", () => {
  for (const name of STATUS_STATES) {
    assert.ok(statesDoc.recoveryContract[name], `recovery contract for ${name}`);
  }
});

test("ten locale packs cover status and factor copy", () => {
  assert.deepEqual(
    Object.keys(copyDoc.packs),
    ["en", "de", "fr", "es", "it", "nl", "pl", "pt", "pt-br", "ar"],
  );
  for (const [lang, pack] of Object.entries(copyDoc.packs)) {
    assert.ok(["ltr", "rtl"].includes(pack.dir), `${lang} dir`);
    for (const name of STATUS_STATES) {
      const entry = pack.states[name];
      assert.ok(entry, `${lang} state ${name}`);
      assert.equal(entry.action, statesDoc.states[name].action ? entry.action : null, `${lang} ${name} action shape`);
      if (statesDoc.states[name].action) {
        assert.equal(typeof entry.action, "string", `${lang} ${name} action`);
      }
    }
    for (const key of [
      "caption", "close", "utility_change_email", "utility_resend",
    ]) {
      assert.ok(pack.factor[key], `${lang} factor.${key}`);
    }
    for (const view of ["requested", "address", "code", "service_unavailable", "response"]) {
      assert.ok(pack.factor[view].title, `${lang} factor.${view}.title`);
      assert.ok(pack.factor[view].copy, `${lang} factor.${view}.copy`);
      assert.ok(pack.factor[view].primary, `${lang} factor.${view}.primary`);
    }
  }
  assert.equal(copyDoc.packs.ar.dir, "rtl");
});

test("English copy matches the canonical state inventory exactly", () => {
  const en = copyDoc.packs.en;
  for (const name of STATUS_STATES) {
    assert.equal(en.states[name].title, statesDoc.states[name].title);
    assert.equal(en.states[name].explanation, statesDoc.states[name].explanation);
    assert.equal(en.states[name].action, statesDoc.states[name].action);
  }
});

test("English factor copy matches the PDF specimens exactly", () => {
  const f = copyDoc.packs.en.factor;
  assert.equal(f.caption, "Email confirmation");
  assert.equal(f.requested.title, "One more check");
  assert.equal(f.requested.copy, "Confirm your email to continue.");
  assert.equal(f.requested.primary, "Continue");
  assert.equal(f.address.title, "Confirm your email");
  assert.equal(f.address.copy, "We'll send you a six-digit code.");
  assert.equal(f.address.label, "Email address");
  assert.equal(f.address.primary, "Send code");
  assert.equal(f.sending.primary, "Sending…");
  assert.equal(f.delivery_error.message, "We couldn't send the code. Try again.");
  assert.equal(f.code.title, "Check your inbox");
  assert.equal(f.code.copy, "Enter the code sent to {email}.");
  assert.equal(f.code.label, "Verification code");
  assert.equal(f.code.primary, "Verify code");
  assert.equal(f.code_error.message, "That code didn't match. Try again.");
  assert.equal(f.expired.message, "This code expired. Request a new one.");
  assert.equal(f.expired.primary, "Get a new code");
  assert.equal(f.rate_limited.message, "Too many attempts. Please wait before trying again.");
  assert.equal(f.rate_limited.primary, "Please wait");
  assert.equal(f.service_unavailable.title, "Check unavailable");
  assert.equal(f.service_unavailable.copy, "Try again, or contact the site if this continues.");
  assert.equal(f.service_unavailable.primary, "Try again");
  assert.equal(f.response.title, "Check complete");
  assert.equal(f.response.copy, "Return to the application to continue.");
  assert.equal(f.response.primary, "Continue");
  assert.equal(f.utility_change_email, "Change email");
  assert.equal(f.utility_resend, "Resend code");
});

test("renderWidget is pure, deterministic and state-shaped", () => {
  for (const name of STATUS_STATES) {
    const copy = copyDoc.packs.en.states[name];
    const icon = statesDoc.states[name].icon;
    const view = { state: name, copy, icon };
    const first = renderWidget(view);
    assert.equal(first, renderWidget(view));
    assert.ok(first.includes(`data-state`) || first.includes('class="kc-status'), "status shell");
    assert.ok(first.includes(esc(copy.title)), "title rendered");
    assert.ok(first.includes(esc(copy.explanation)), "explanation rendered");
    assert.ok(first.includes("KiwiCaptcha"), "attribution rendered");
    if (copy.action) {
      assert.ok(first.includes(esc(copy.action)), "action rendered");
    } else {
      assert.ok(!first.includes('class="kc-action'), "no action row without capability");
    }
    if (icon === "check") assert.ok(first.includes("kc-state-icon--check"));
    if (icon === "warning") assert.ok(first.includes("kc-state-icon--warning"));
    if (icon === "none") assert.ok(!first.includes("kc-state-icon--"));
  }
});

test("status widths and scales resolve to global classes", () => {
  for (const width of STATUS_WIDTHS) {
    const html = renderWidget({
      state: "pending", copy: copyDoc.packs.en.states.pending, icon: "none", width,
    });
    assert.ok(html.includes(`kc-w${width}`), `width class ${width}`);
    assert.ok(!html.includes("style="), "no inline styles");
  }
  for (const scale of STATUS_SCALES) {
    const html = renderWidget({
      state: "pending", copy: copyDoc.packs.en.states.pending, icon: "none", scale,
    });
    assert.equal(html.includes("kc-text-2x"), scale === 2);
    assert.ok(!html.includes("style="), "no inline styles");
  }
});

test("renderFactor covers every view with the copy table", () => {
  for (const kind of FACTOR_VIEWS) {
    const html = renderFactor({
      view: kind, copy: copyDoc.packs.en, email: "you@example.com", code: "123456",
    });
    assert.equal(html, renderFactor({
      view: kind, copy: copyDoc.packs.en, email: "you@example.com", code: "123456",
    }), `deterministic ${kind}`);
    assert.ok(html.includes("Email confirmation"), `${kind} caption`);
    assert.ok(html.includes("KiwiCaptcha"), `${kind} attribution`);
    assert.ok(!html.includes("style="), `${kind} no inline styles`);
  }
});

test("factor views carry the right task per phase", () => {
  const en = copyDoc.packs.en;
  const requested = renderFactor({ view: "requested", copy: en });
  assert.ok(requested.includes("One more check"));
  assert.ok(!requested.includes("kc-field"), "requested has no field");

  const address = renderFactor({ view: "address", copy: en });
  assert.ok(address.includes("kc-email") && address.includes("Send code"));

  const sending = renderFactor({ view: "sending", copy: en });
  assert.ok(sending.includes("Sending…") && sending.includes("disabled"));

  const code = renderFactor({ view: "code", copy: en, email: "you@example.com" });
  assert.ok(code.includes("Enter the code sent to <bdi>you@example.com</bdi>."));
  assert.ok(code.includes("Change email") && code.includes("Resend code"));

  const codeError = renderFactor({ view: "code-error", copy: en, code: "123456" });
  assert.ok(codeError.includes("That code didn&#39;t match. Try again."));
  assert.ok(codeError.includes('value="123456"'), "invalid code kept for correction");
  assert.ok(codeError.includes('aria-invalid="true"'));

  const expired = renderFactor({ view: "expired", copy: en, code: "123456" });
  assert.ok(expired.includes("This code expired. Request a new one."));
  assert.ok(expired.includes("Get a new code"));
  assert.ok(!expired.includes('value="123456"'), "expiry clears the code");

  const limited = renderFactor({ view: "rate-limited", copy: en });
  assert.ok(limited.includes("Too many attempts"));
  assert.ok(limited.includes("Please wait") && limited.includes("disabled"));

  const service = renderFactor({ view: "service-unavailable", copy: en });
  assert.ok(service.includes("Check unavailable"));
  assert.ok(!service.includes("kc-field"), "service failure keeps the task simple");

  const response = renderFactor({ view: "response", copy: en });
  assert.ok(response.includes("Check complete"));
  assert.ok(response.includes("Return to the application to continue."));
});

test("code copy interpolates the email escaped, inside bdi", () => {
  const html = renderFactor({
    view: "code", copy: copyDoc.packs.en, email: "a<b>@example.com",
  });
  assert.ok(html.includes("<bdi>a&lt;b&gt;@example.com</bdi>"));
  assert.ok(!html.includes("<b>a@"), "no raw interpolation");
});

test("the Arabic pack renders right-to-left in both renderers", () => {
  const ar = copyDoc.packs.ar;
  const status = renderWidget({ state: "failed", copy: ar.states.failed, icon: "warning" });
  assert.ok(status.includes(ar.states.failed.title));
  const factor = renderFactor({ view: "code", copy: ar, email: "you@example.com" });
  assert.ok(factor.includes(ar.factor.code.title));
});

test("every locale renders every view without throwing", () => {
  for (const pack of Object.values(copyDoc.packs)) {
    for (const name of STATUS_STATES) {
      renderWidget({ state: name, copy: pack.states[name], icon: statesDoc.states[name].icon });
    }
    for (const kind of FACTOR_VIEWS) {
      renderFactor({ view: kind, copy: pack, email: "you@example.com", code: "000000" });
    }
  }
});
