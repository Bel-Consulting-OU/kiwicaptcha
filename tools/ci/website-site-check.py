#!/usr/bin/env python3
"""Site checks for the built KiwiCaptcha website.

The contract the build must honor (KiwiCaptcha_Website.pdf, QA scope):
JavaScript-free output, self-hosted assets only, and every local anchor
and asset reference resolving to a built file. Fails closed: any script
tag, inline event handler, javascript: URI, external resource host or
dangling local reference is a nonzero exit.
"""

from __future__ import annotations

import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse, unquote

VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}
RESOURCE_ATTRIBUTES = {
    "img": ("src", "srcset"),
    "link": ("href",),
    "script": ("src",),
    "source": ("src", "srcset"),
    "video": ("src",),
    "audio": ("src",),
}
INLINE_EVENT_PREFIX = "on"


class PageAuditor(HTMLParser):
    """Collects violations for one built page."""

    def __init__(self, rel: str) -> None:
        super().__init__(convert_charrefs=True)
        self.rel = rel
        self.failures: list[str] = []

    def _fail(self, message: str) -> None:
        self.failures.append(f"{self.rel}: {message}")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name: (value or "") for name, value in attrs}
        if tag == "script":
            self._fail("script element found; the site ships no JavaScript")
        if tag == "iframe":
            self._fail("iframe element found")
        for name in attr_map:
            if name.lower().startswith(INLINE_EVENT_PREFIX) and name.lower() != "on":
                self._fail(f"inline event attribute {name}")
        for name, value in attr_map.items():
            if value.strip().lower().startswith("javascript:"):
                self._fail(f"javascript: URI in {name}")
        resource_names = RESOURCE_ATTRIBUTES.get(tag, ())
        for name in resource_names:
            value = attr_map.get(name, "")
            for candidate in value.split(","):
                candidate = candidate.strip().split(" ")[0]
                if not candidate:
                    continue
                parsed = urlparse(candidate)
                if parsed.scheme in ("http", "https"):
                    self._fail(f"external resource host in <{tag} {name}>: {candidate}")


def collect_pages(root: Path) -> list[Path]:
    return sorted(root.rglob("*.html"))


def check_page(root: Path, page: Path) -> list[str]:
    rel = page.relative_to(root).as_posix()
    text = page.read_text(encoding="utf-8")
    auditor = PageAuditor(rel)
    auditor.feed(text)
    failures = list(auditor.failures)
    # Local reference integrity: every href/src that targets this site
    # must resolve to a built file (or a file/anchor inside one).
    for needle_start, needle_end in (('href="', '"'), ('src="', '"')):
        position = 0
        while True:
            start = text.find(needle_start, position)
            if start < 0:
                break
            end = text.find(needle_end, start + len(needle_start))
            if end < 0:
                break
            position = end + 1
            target = text[start + len(needle_start):end]
            failures.extend(
                check_reference(root, page, rel, target)
            )
    return failures


def check_reference(root: Path, page: Path, rel: str, target: str) -> list[str]:
    target = target.strip()
    if not target or target.startswith(("#", "mailto:", "tel:", "data:")):
        return []
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        return []  # outbound links to the source repository are expected
    if parsed.scheme:
        return [f"{rel}: unsupported URI scheme in reference {target}"]
    path_part = unquote(parsed.path)
    if not path_part:
        return []
    base_dir = page.parent if not path_part.startswith("/") else root
    resolved = (base_dir / path_part.lstrip("/")).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return [f"{rel}: reference {target} escapes the site root"]
    if not resolved.exists():
        return [f"{rel}: dangling reference {target}"]
    if resolved.is_file() and parsed.fragment:
        fragment = parsed.fragment
        if fragment and not fragment_has_anchor(resolved, fragment):
            return [f"{rel}: missing anchor #{fragment} in {target}"]
    return []


def fragment_has_anchor(path: Path, fragment: str) -> bool:
    text = path.read_text(encoding="utf-8")
    return (
        f'id="{fragment}"' in text
        or f"id='{fragment}'" in text
    )


def check_labels(root: Path) -> list[str]:
    failures: list[str] = []
    index = root / "index.html"
    if not index.exists():
        return [f"missing built index.html at {root}"]
    text = index.read_text(encoding="utf-8")
    for label in (
        "How it works", "Integration", "Security", "Docs", "Widget", "Identity",
        "Skip to content", "Bel Consulting", "Also in the family",
        "Download the complete website PDF", "All questions and answers",
    ):
        if label not in text:
            failures.append(f"index.html: missing required label {label!r}")
    return failures


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <built-site-root>", file=sys.stderr)
        return 2
    root = Path(argv[1]).resolve()
    if not root.is_dir():
        print(f"built site root not found: {root}", file=sys.stderr)
        return 2
    failures: list[str] = []
    pages = collect_pages(root)
    if not pages:
        failures.append("no built pages found")
    for page in pages:
        failures.extend(check_page(root, page))
    failures.extend(check_labels(root))
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    pages_n = len(pages)
    if failures:
        print(f"site checks: {len(failures)} failure(s) across {pages_n} pages", file=sys.stderr)
        return 1
    print(f"site checks: PASS ({pages_n} pages, no JavaScript, all local references resolve)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
