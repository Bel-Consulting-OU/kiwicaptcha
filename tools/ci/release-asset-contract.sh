#!/usr/bin/env bash
# tools/ci/release-asset-contract.sh - the release asset contract
#
# Usage:
#   bash tools/ci/release-asset-contract.sh [--workflow FILE]
#       [--manifest FILE] [--assets-dir DIR] [--sri-script FILE]
#
# Every name in the canonical release-assets.txt manifest must appear
# in ALL of the locations that carry the release asset set:
#
#   1. the SLSA subject-path block of .github/workflows/release.yml,
#   2. the gh release create asset arguments of the same workflow,
#   3. the SHA256SUMS producer line of the same workflow,
#   4. the SRI default asset list of packages/kiwicaptcha-wasm/tools/
#      sri-hashes.mjs,
#   5. the SHA256SUMS and SRI.txt files in the assets directory, when
#      present (they exist at release time; CI checks the producer
#      sources in 3 and 4).
#
# The script then asserts set equality for the four canonical carrier
# sets against the manifest set (strict rebuild set, SRI set,
# attestation set, publish set), so deleting an asset name from ANY one
# location, or adding an undeclared asset to a carrier list, fails the
# contract. Non-asset outputs of the release blocks (SHA256SUMS,
# SRI.txt, RELEASE_NOTES.md) are not release assets and are excluded
# from the carrier sets.
#
# Prints one PASS line per canonical asset plus one PASS line per
# set-equality check, and exits 0; any failure prints FAIL lines and
# exits 1.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

workflow="$repo_root/.github/workflows/release.yml"
manifest_file="$repo_root/packages/kiwicaptcha-wasm/release-assets.txt"
assets_dir="$repo_root/packages/kiwicaptcha-wasm/assets"
sri_script="$repo_root/packages/kiwicaptcha-wasm/tools/sri-hashes.mjs"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --workflow)
      workflow="$2"
      shift 2
      ;;
    --manifest)
      manifest_file="$2"
      shift 2
      ;;
    --assets-dir)
      assets_dir="$2"
      shift 2
      ;;
    --sri-script)
      sri_script="$2"
      shift 2
      ;;
    *)
      echo "release-asset-contract: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

for required in "$workflow" "$manifest_file" "$sri_script"; do
  if [ ! -f "$required" ]; then
    echo "release-asset-contract: required file is missing: $required" >&2
    exit 1
  fi
done

# Non-asset files that legitimately ride inside the carrier blocks.
non_assets="^(SHA256SUMS|SRI.txt|RELEASE_NOTES.md)$"

# names_in_blocks: stdin text -> sorted unique asset names found as
# workspace-rooted or assets/-prefixed paths.
names_in_blocks() {
  grep -oE '\$\{\{ github\.workspace \}\}/[A-Za-z0-9._-]+|\$GITHUB_WORKSPACE/[A-Za-z0-9._-]+|assets/[A-Za-z0-9._-]+' \
    | sed -E 's#.*/##' \
    | grep -vE "$non_assets" \
    | sort -u
}

# set_from_line_list: stdin raw name tokens -> sorted unique names.
set_from_line_list() {
  tr -s '[:space:]' '\n' | grep -vE '^$' | sort -u
}

subject_block="$(sed -n '/subject-path:/,/^      - name:/p' "$workflow")"
# The publish block is carved between the actual invocation line (not
# the prose that mentions gh release create) and the --verify-tag flag
# at the start of a line (not the comment line that names it).
publish_block="$(sed -n '/gh release create "\$GITHUB_REF_NAME"/,/^[[:space:]]*--verify-tag/p' "$workflow")"
rebuild_block="$(sed -n '/git diff --exit-code/,/strict rebuild ==/p' "$workflow")"

attestation_set="$(printf '%s\n' "$subject_block" | names_in_blocks || true)"
publish_set="$(printf '%s\n' "$publish_block" | names_in_blocks || true)"
rebuild_set="$(printf '%s\n' "$rebuild_block" | names_in_blocks || true)"

sha256_producer_line="$(sed -n '/shasum -a 256/p' "$workflow")"
sha256_set="$(printf '%s\n' "$sha256_producer_line" \
  | sed -E 's/.*shasum -a 256[[:space:]]+//; s/[[:space:]]*>.*//' \
  | set_from_line_list || true)"

# The SRI default list is the literal DEFAULT_ASSETS array in
# sri-hashes.mjs; the awk range captures the array across lines (a
# single-line array terminates on its own line).
sri_default_block="$(awk '/DEFAULT_ASSETS = \[/ { print; if ($0 ~ /\]/) exit; f=1; next } f { print; if ($0 ~ /\]/) exit }' "$sri_script")"
sri_set="$(printf '%s\n' "$sri_default_block" \
  | grep -oE '"[A-Za-z0-9._-]+"' \
  | tr -d '"' \
  | grep -vE "$non_assets" \
  | sort -u || true)"

manifest="$(cat "$manifest_file" | set_from_line_list || true)"

if [ -z "$manifest" ]; then
  echo "release-asset-contract: the manifest is empty: $manifest_file" >&2
  exit 1
fi

# Optional generated files (present at release time).
file_sets=""
if [ -f "$assets_dir/SHA256SUMS" ]; then
  sha256_file_set="$(awk '{print $2}' "$assets_dir/SHA256SUMS" | grep -vE '^$' | grep -vE "$non_assets" | sort -u || true)"
  file_sets="$file_sets $sha256_file_set"
fi
if [ -f "$assets_dir/SRI.txt" ]; then
  sri_file_set="$(awk '{print $1}' "$assets_dir/SRI.txt" | grep -vE '^$' | grep -vE "$non_assets" | sort -u || true)"
  file_sets="$file_sets $sri_file_set"
fi

# Presence: every manifest name in every carrier location.
failed=0
check_presence() {
  local name="$1"
  local location_label="$2"
  shift 2
  local members="$1"
  if ! grep -Fxq "$name" <<<"$members"; then
    echo "FAIL: $name is missing from the $location_label" >&2
    failed=1
  fi
}

for name in $manifest; do
  check_presence "$name" "SLSA subject-path block of release.yml" "$attestation_set"
  check_presence "$name" "gh release create arguments of release.yml" "$publish_set"
  check_presence "$name" "SHA256SUMS producer line of release.yml" "$sha256_set"
  check_presence "$name" "SRI default asset list of sri-hashes.mjs" "$sri_set"
  check_presence "$name" "strict rebuild (committed-bytes) block of release.yml" "$rebuild_set"
  if [ -f "$assets_dir/SHA256SUMS" ]; then
    check_presence "$name" "generated SHA256SUMS file" "$sha256_file_set"
  fi
  if [ -f "$assets_dir/SRI.txt" ]; then
    check_presence "$name" "generated SRI.txt file" "$sri_file_set"
  fi
done

# Set equality: carrier sets must equal the manifest set exactly.
check_equality() {
  local label="$1"
  local a="$2"
  local b="$3"
  local a_file b_file
  a_file="$(mktemp)"
  b_file="$(mktemp)"
  printf '%s\n' "$a" > "$a_file"
  printf '%s\n' "$b" > "$b_file"
  if diff -u "$a_file" "$b_file" >/dev/null 2>&1; then
    echo "PASS $label == manifest set"
  else
    echo "FAIL $label != manifest set:" >&2
    diff -u "$a_file" "$b_file" >&2 || true
    failed=1
  fi
  rm -f "$a_file" "$b_file"
}

# Emit PASS only once every presence check passed, then the equalities.
if [ "$failed" -eq 0 ]; then
  for name in $manifest; do
    echo "PASS $name"
  done
  check_equality "strict rebuild set" "$rebuild_set" "$manifest"
  check_equality "SRI set" "$sri_set" "$manifest"
  check_equality "attestation set" "$attestation_set" "$manifest"
  check_equality "publish set" "$publish_set" "$manifest"
fi

if [ "$failed" -ne 0 ]; then
  echo "release asset contract VIOLATED" >&2
  exit 1
fi

echo "release asset contract OK: every manifest asset is published, attested, rebuilt and hashed as one set"
