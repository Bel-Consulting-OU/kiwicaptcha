#!/bin/sh
# Build the KiwiCaptcha product website: assemble static assets, run
# Zola, then verify the output is JavaScript-free with intact local
# anchors and assets. Artifacts under website/zola/static/canonical are
# generated copies of repository files and are not committed.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
site_dir="$repo_root/website/zola"
static_dir="$site_dir/static"
resources="$repo_root/packages/kiwicaptcha/resources"
design_fonts="$repo_root/packages/kiwicaptcha/design/fonts"

echo "== assemble canonical assets"
mkdir -p "$static_dir/fonts" "$static_dir/brand" "$static_dir/pdf" "$static_dir/css"
cp "$design_fonts"/*.woff2 "$static_dir/fonts/"
cp "$design_fonts"/OFL-*.txt "$static_dir/fonts/"
cp "$resources"/kiwi-mark.svg "$resources"/kiwi-lockup.svg "$resources"/kiwi-stacked.svg \
   "$resources"/kiwi-wordmark.svg "$resources"/kiwi-app-icon.svg "$resources"/kiwi-shield.svg \
   "$static_dir/brand/"
cp "$resources"/widget.css "$static_dir/css/widget.css"
cp "$repo_root/lettering.json" "$static_dir/brand/lettering.json" 2>/dev/null ||
  cp "$repo_root/packages/kiwicaptcha/design/lettering.json" "$static_dir/brand/lettering.json"
cp "$repo_root/KiwiCaptcha_Website.pdf" "$static_dir/pdf/"
cp "$repo_root/KiwiCaptcha_Visual_Identity.pdf" "$static_dir/pdf/"

echo "== zola build"
cd "$site_dir"
zola build

echo "== site checks (no javascript, anchors, assets)"
python3 "$repo_root/tools/ci/website-site-check.py" "$site_dir/public"

echo "website built: $site_dir/public"
