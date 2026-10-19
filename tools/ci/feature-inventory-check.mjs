#!/usr/bin/env node
// feature-inventory-check.mjs — the "every declared surface is used" gate.
//
// The repo ships twenty-five packages, a platform-integration tree, a
// tool tree and a canonical protocol. This checker holds the inventory
// (tools/ci/feature-inventory.json) to the tree:
//
//   * every package on disk has an inventory entry, a test marker, and
//     a CI job that names it;
//   * every declared capability is real: an exported ABI symbol is in
//     the source, the native module the bridge dispatches to exists,
//     and a removed degradation marker stays gone — wiring alone never
//     satisfies the gate, and every failure names the missing artifact;
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

// ---------- capability gates: wiring is not implementation ----------
// A package may declare a `capabilities` list: concrete facts about its
// implementation artifacts. Kinds:
//   files      — every pattern in `files` must match an existing file
//                (`**`/`*` globs, package-relative; a leading "/" anchors
//                at the repository root for protocol-level markers)
//   exports    — `file` must contain every string in `symbols`
//   dispatches — `file` must reference every bridge target in `targets`
//   free_of    — `file` must not contain any string in `markers`
// Every failure names the exact missing artifact; an unknown kind, a
// missing `file` or an empty token list is itself a loud failure, so a
// half-edited capability can never silently check nothing.
const KNOWN_CAPABILITY_KINDS = new Set(["files", "exports", "dispatches", "free_of"]);
const capabilitySkipDirs = new Set([
  "node_modules",
  "build",
  "target",
  "dist",
  "vendor",
  ".gradle",
  "Pods",
]);
const packageFilesCache = new Map();
function packageFiles(packagePath) {
  if (packageFilesCache.has(packagePath)) return packageFilesCache.get(packagePath);
  const files = [];
  const absPackage = path.join(root, packagePath);
  const walk = (abs, rel) => {
    for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (capabilitySkipDirs.has(entry.name)) continue;
        walk(path.join(abs, entry.name), `${rel}/${entry.name}`);
      } else if (entry.isFile()) {
        files.push(`${rel}/${entry.name}`);
      }
    }
  };
  if (fs.existsSync(absPackage)) walk(absPackage, packagePath);
  packageFilesCache.set(packagePath, files);
  return files;
}

function globToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    "^" +
      escaped
        .replace(/\*\*/g, "\u0000")
        .replace(/\*/g, "[^/]*")
        .replace(/\u0000/g, ".*") +
      "$",
  );
}

// Capability paths are package-relative; a leading "/" anchors at the
// repository root (a protocol-level marker may live outside the package).
function capabilityFilePath(entryPath, fileSpec) {
  return fileSpec.startsWith("/") ? fileSpec.slice(1) : `${entryPath}/${fileSpec}`;
}

let capabilityChecks = 0;
for (const entry of manifest.packages) {
  for (const capability of entry.capabilities ?? []) {
    const label = capability.comment ?? capability.kind;
    if (!KNOWN_CAPABILITY_KINDS.has(capability.kind)) {
      failures.push(`${entry.path}: capability "${label}" names an unknown kind "${capability.kind}"`);
      continue;
    }
    capabilityChecks += 1;
    if (capability.kind === "files") {
      for (const patternSpec of capability.files ?? []) {
        const anchored = patternSpec.startsWith("/");
        const pattern = capabilityFilePath(entry.path, patternSpec);
        if (anchored && patternSpec.includes("*")) {
          failures.push(`${entry.path}: capability "${label}": an anchored pattern must be a literal path: ${patternSpec}`);
          continue;
        }
        if (!pattern.includes("*")) {
          if (!exists(pattern)) {
            failures.push(`${entry.path}: capability "${label}" is missing its artifact: ${pattern}`);
          }
          continue;
        }
        if (!packageFiles(entry.path).some((file) => globToRegExp(pattern).test(file))) {
          failures.push(`${entry.path}: capability "${label}" is missing its artifact (no file matches): ${pattern}`);
        }
      }
      continue;
    }
    if (!capability.file) {
      failures.push(`${entry.path}: capability "${label}" (kind ${capability.kind}) names no file to check`);
      continue;
    }
    const file = capabilityFilePath(entry.path, capability.file);
    if (!exists(file)) {
      failures.push(`${entry.path}: capability "${label}" needs ${file}, which does not exist`);
      continue;
    }
    const source = fs.readFileSync(path.join(root, file), "utf8");
    if (capability.kind === "exports" || capability.kind === "dispatches") {
      const tokens = capability.kind === "exports" ? capability.symbols ?? [] : capability.targets ?? [];
      if (tokens.length === 0) {
        failures.push(`${entry.path}: capability "${label}" (kind ${capability.kind}) lists no ${capability.kind === "exports" ? "symbols" : "targets"} for ${file}`);
      }
      for (const token of tokens) {
        if (!source.includes(token)) {
          failures.push(
            capability.kind === "exports"
              ? `${entry.path}: ${file} does not export ${token} (capability: ${label})`
              : `${entry.path}: ${file} does not dispatch to ${token} (capability: ${label})`,
          );
        }
      }
    } else {
      const markers = capability.markers ?? [];
      if (markers.length === 0) {
        failures.push(`${entry.path}: capability "${label}" (kind free_of) lists no forbidden markers for ${file}`);
      }
      for (const marker of markers) {
        if (source.includes(marker)) {
          failures.push(`${entry.path}: ${file} still contains forbidden marker "${marker}" (capability: ${label})`);
        }
      }
    }
  }
}
notes.push(
  `capability gates: ${capabilityChecks} checks across ${manifest.packages.filter((entry) => (entry.capabilities ?? []).length > 0).length} packages`,
);

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
