#!/usr/bin/env node
// feature-inventory-check.mjs — the "every declared surface is used" gate.
//
// The repo ships twenty-five packages, a platform-integration tree, a
// tool tree and a canonical protocol. This checker holds the inventory
// (tools/ci/feature-inventory.json) to the tree:
//
//   * every package on disk has an inventory entry, a test marker, and
//     a CI job that names it;
//   * every tool under tools/ci is invoked by a workflow, a runner or
//     another tool — an unreferenced script is a feature nobody uses;
//   * every platform-integration directory is reached by the platform
//     runner;
//   * every canonical Lua script exists byte-identically in both runtime
//     mirrors, and the corpus files exist;
//   * every CI job is either in the promotion gate or explicitly
//     non-gating (nightly, dispatch-only, advisory);
//   * every manual lane names an existing command and its evidence.
//
// The failure output names the exact missing wiring. It reads files
// only; it never mutates the tree.

import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const failures = [];
const notes = [];

function read(file) {
  try {
    return fs.readFileSync(path.join(root, file), "utf8");
  } catch {
    failures.push(`missing file: ${file}`);
    return "";
  }
}

function exists(file) {
  return fs.existsSync(path.join(root, file));
}

function markerExists(base, marker) {
  if (!marker.includes("*")) return exists(path.join(base, marker));
  const dir = path.dirname(path.join(base, marker));
  const pattern = new RegExp(
    "^" + path.basename(marker).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$",
  );
  if (!exists(dir)) return false;
  return fs.readdirSync(path.join(root, dir)).some((name) => pattern.test(name));
}

const manifest = JSON.parse(read("tools/ci/feature-inventory.json"));
const ci = read(".github/workflows/ci.yml");

const kiwiFiles = fs
  .readdirSync(path.join(root, ".kiwi"))
  .filter((name) => name.endsWith(".yaml"))
  .sort();
const kiwiSources = new Map(kiwiFiles.map((name) => [name, read(path.join(".kiwi", name))]));
const kiwiText = [...kiwiSources.values()].join("\n");

const runners = [
  read("integrations-platforms/tests/run-all.sh"),
  read("integrations-platforms/tests/run.sh"),
  read("tools/redteam/exit-criteria.sh"),
  read("tools/dogfood/dogfood.sh"),
].join("\n");

const allWorkflows = ci + "\n" + kiwiText;
const jobsBlock = ci.slice(ci.indexOf("\njobs:"));
const jobNames = new Set(
  jobsBlock
    .split("\n")
    .map((line) => /^  ([a-z0-9-]+):\s*$/.exec(line))
    .filter(Boolean)
    .map((match) => match[1]),
);

// Kiwi-CI job keys are indented two spaces under each file's jobs map.
const kiwiJobs = new Set();
for (const [name, source] of kiwiSources) {
  const block = source.slice(source.indexOf("\njobs:"));
  for (const line of block.split("\n")) {
    const match = /^  ([A-Za-z0-9_.:-]+):\s*$/.exec(line);
    if (match) kiwiJobs.add(match[1]);
  }
}

// ---------- packages ----------
const packageDirs = fs
  .readdirSync(path.join(root, "packages"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => `packages/${entry.name}`);

const inventory = new Map(manifest.packages.map((entry) => [entry.path, entry]));
for (const dir of packageDirs) {
  if (!inventory.has(dir)) {
    failures.push(`package ${dir} has no entry in tools/ci/feature-inventory.json`);
  }
}

for (const entry of manifest.packages) {
  if (!exists(entry.path)) {
    failures.push(`inventory names a missing package: ${entry.path}`);
    continue;
  }
  if (!entry.markers.some((marker) => markerExists(entry.path, marker))) {
    failures.push(`${entry.path}: none of its test markers exist (${entry.markers.join(", ")})`);
  }
  if (!jobNames.has(entry.ci_job)) {
    failures.push(`${entry.path}: CI job "${entry.ci_job}" does not exist in ci.yml`);
  }
  if (!entry.kiwi_job) {
    failures.push(`${entry.path}: no kiwi_job mapping in the inventory`);
  } else if (!kiwiJobs.has(entry.kiwi_job)) {
    failures.push(`${entry.path}: Kiwi job "${entry.kiwi_job}" does not exist in .kiwi/`);
  }
  const basename = path.basename(entry.path);
  if (!ci.includes(entry.path) && !new RegExp(`(^|[^a-z-])${basename}([^a-z-]|$)`, "m").test(ci)) {
    failures.push(`${entry.path}: no CI job references this package`);
  }
}

// ---------- tools/ci: every script must have a caller ----------
const toolFiles = fs
  .readdirSync(path.join(root, "tools/ci"))
  .filter((name) => /\.(sh|mjs|py|awk)$/.test(name))
  .filter((name) => name !== "feature-inventory-check.mjs");

const toolSources = new Map(
  toolFiles.map((name) => [name, fs.readFileSync(path.join(root, "tools/ci", name), "utf8")]),
);
for (const name of toolFiles) {
  const others = [allWorkflows, runners, read("README.md")]
    .concat([...toolSources.entries()].filter(([other]) => other !== name).map(([, source]) => source))
    .join("\n");
  if (!others.includes(name)) {
    failures.push(`tools/ci/${name} is never invoked by a workflow, runner or another tool`);
  }
}
notes.push(`tools/ci: ${toolFiles.length} scripts, all invoked or imported`);

// ---------- surfaces ----------
for (const surface of manifest.surfaces) {
  if (!exists(surface.path)) {
    failures.push(`inventory names a missing surface: ${surface.path}`);
    continue;
  }
  if (!exists(surface.runner.split(" ")[0])) {
    failures.push(`${surface.path}: runner ${surface.runner} does not exist`);
  }
  if (surface.lane === "ci") {
    if (!jobNames.has(surface.ci_job)) {
      failures.push(`${surface.path}: CI job "${surface.ci_job}" does not exist in ci.yml`);
    }
    if (surface.kiwi_job && !kiwiJobs.has(surface.kiwi_job)) {
      failures.push(`${surface.path}: Kiwi job "${surface.kiwi_job}" does not exist in .kiwi/`);
    }
  }
  if (surface.lane === "manual" || surface.lane === "release") {
    if (!surface.reason) failures.push(`${surface.path}: a manual/release lane needs a stated reason`);
  }
}

// ---------- protocol parity ----------
const luaDir = manifest.protocols.risk_lua_dir;
const luaFiles = fs.readdirSync(path.join(root, luaDir)).filter((name) => name.endsWith(".lua"));
if (luaFiles.length < manifest.protocols.minimum_count) {
  failures.push(
    `${luaDir}: ${luaFiles.length} scripts, expected at least ${manifest.protocols.minimum_count}`,
  );
}
for (const name of luaFiles) {
  const canonical = fs.readFileSync(path.join(root, luaDir, name));
  for (const mirror of manifest.protocols.risk_lua_mirrors) {
    const target = path.join(mirror, name);
    if (!exists(target)) {
      failures.push(`${mirror}/${name} is missing (canonical copy exists)`);
    } else if (!canonical.equals(fs.readFileSync(path.join(root, target)))) {
      failures.push(`${mirror}/${name} differs from ${luaDir}/${name}`);
    }
  }
}
for (const corpus of manifest.protocols.corpora) {
  if (!exists(corpus)) failures.push(`protocol corpus missing: ${corpus}`);
}
notes.push(`protocol: ${luaFiles.length} Lua scripts byte-identical in both runtime mirrors`);

// ---------- platform integrations ----------
const platformDirs = fs
  .readdirSync(path.join(root, "integrations-platforms"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .filter((name) => name !== "tests");
for (const name of platformDirs) {
  if (!runners.includes(name)) {
    failures.push(`integrations-platforms/${name} is not reached by tests/run-all.sh or tests/run.sh`);
  }
}
notes.push(`platform integrations: ${platformDirs.length} platforms reached by the runner`);

// ---------- promotion gate: no orphan job ----------
const nonGating = new Set(["promotion-gate", "php-nightly", "perf-latency-quiet", "redis-compat"]);
const gateStart = ci.indexOf("  promotion-gate:");
const gateBlock = gateStart === -1 ? "" : ci.slice(gateStart);
const needsMatch = /    needs:\n([\s\S]*?)    runs-on:/.exec(gateBlock);
const needs = new Set(
  (needsMatch ? needsMatch[1] : "")
    .split("\n")
    .map((line) => /^\s+- ([a-z0-9-]+)\s*$/.exec(line))
    .filter(Boolean)
    .map((match) => match[1]),
);
for (const job of jobNames) {
  if (!nonGating.has(job) && !needs.has(job)) {
    failures.push(`CI job "${job}" is not in promotion-gate.needs and is not a declared non-gating job`);
  }
}
notes.push(`ci: ${jobNames.size} jobs, ${needs.size} gated, ${nonGating.size} declared non-gating`);

const kiwiGateSource = kiwiSources.get("pipeline.yaml") ?? "";
const kiwiGateStart = kiwiGateSource.indexOf("\n  promotion-gate:");
const kiwiGateBlock = kiwiGateStart === -1 ? "" : kiwiGateSource.slice(kiwiGateStart);
const kiwiNeedsMatch = /^    needs:\n([\s\S]*?)^    [a-z]/m.exec(kiwiGateBlock);
const kiwiNeeds = new Set(
  (kiwiNeedsMatch ? kiwiNeedsMatch[1] : "")
    .split("\n")
    .map((line) => /^    - ([A-Za-z0-9_.:-]+)\s*$/.exec(line))
    .filter(Boolean)
    .map((match) => match[1]),
);
for (const job of kiwiJobs) {
  if (kiwiSources.get("pipeline.yaml")?.includes(`\n  ${job}:`) && job !== "promotion-gate" && !kiwiNeeds.has(job)) {
    failures.push(`Kiwi job "${job}" is not in promotion-gate.needs`);
  }
}
notes.push(`kiwi: ${kiwiJobs.size} jobs in ${kiwiFiles.length} pipelines, ${kiwiNeeds.size} gated`);

// ---------- Symfony config-tree inventory ----------
if (!exists("packages/kiwicaptcha/integrations/symfony/tests/FeatureUseTest.php")) {
  failures.push("the Symfony feature-use test (every config leaf read or declared informational) is missing");
}

// ---------- manual lanes ----------
for (const lane of manifest.manual_lanes) {
  const command = lane.command.split(" ")[0];
  if (!exists(command)) failures.push(`manual lane "${lane.name}" names a missing command: ${lane.command}`);
  if (!exists(lane.evidence)) failures.push(`manual lane "${lane.name}" names missing evidence: ${lane.evidence}`);
}

if (failures.length > 0) {
  console.error("feature-inventory: FAIL");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

for (const note of notes) console.log(`feature-inventory: ${note}`);
console.log("feature-inventory: PASS — every declared surface has a lane");
