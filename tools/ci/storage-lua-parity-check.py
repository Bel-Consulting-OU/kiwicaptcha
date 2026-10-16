#!/usr/bin/env python3
"""Cross-runtime parity gate for the storage-transition Lua copies.

Every runtime embeds the same Lua storage-transition scripts as string
literals: the shared envelope-inspection prelude plus consume,
delete-if-pending, cancel, claim-resume, release-resume and commit.
A copy that silently diverges changes which stored records a runtime
transitions: a consume copy that dropped the claim-lease legs of the
pending-envelope guard consumed a record the other mirrors refuse, and
nothing in CI compared the copies. The risk-plane Lua has its own
byte-identity lane; the storage copies had none. This is that gate.

What is compared. For each family, every runtime that declares the copy
is extracted from its own source, decoded by that host's literal rules,
joined with the prelude exactly as the host joins the two literals,
normalized for layout, and compared line for line against the family's
reference copy. A declared copy that cannot be found, a Lua-shaped
literal the gate does not know about, a marker hit outside the declared
carriers, and a change to a declared-divergent copy are all failures: a
skip would let a mirror escape notice. The marker sweep covers the whole
packages/ and tests/ trees and skips install-artifact directories
(vendor, node_modules, target and build output), which are regenerated
from published packages rather than being source mirrors.

Layout-only normalization. Blank lines are dropped, per-line leading and
trailing whitespace is stripped, comment-only lines are dropped, and a
trailing comment is stripped outside Lua short strings. Inner whitespace
is never collapsed: the scripts carry significant spacing inside string
literals (key names, byte-class patterns), so a collapse would mask a
real divergence. The gate still fails on a missing guard leg, a changed
key name, a different constant or a reordered statement.

Named extraction allowances (one per host encoding, never a blanket
tolerance):

  php-nowdoc           A PHP nowdoc value is the lines between the
                       markers, with the closing marker's indentation
                       removed and no trailing newline; no escapes.
  php-boundary-fusion  A nowdoc carries no newline before its closing
                       identifier, so `PRELUDE . <<<'LUA'` fuses the
                       prelude's last code line with the script's first
                       line (a comment). The fused runtime string is
                       reproduced here and the trailing-comment rule
                       normalizes it; every other host keeps the newline
                       before the script's first line.
  go-raw-string        A Go backtick literal is verbatim; it cannot
                       carry a backtick, so the Lua backticks in the
                       comments are spliced as `+ "`" +`. Only that
                       splice is accepted.
  java-text-block      Java strips the incidental indentation shared by
                       the content lines and the closing delimiter, then
                       translates escapes (a doubled backslash to one
                       backslash, and so on).
  csharp-verbatim      A C# verbatim string doubles embedded quotes;
                       the doubled pair decodes to one quote.
  node-template        A TypeScript template literal translates escapes
                       (a doubled backslash, an escaped backtick); an
                       interpolation would change the value and is
                       refused.
  ruby-heredoc         A squiggly heredoc removes the least-indented
                       line's indentation, translates escapes and keeps
                       the trailing newline; an interpolation is
                       refused.
  elixir-heredoc       An Elixir heredoc removes the closing delimiter's
                       indentation, translates escapes and keeps the
                       trailing newline; an interpolation is refused.
  rust-raw-string      A Rust `r#"..."#` literal is verbatim, and the
                       prelude join at the call site is asserted.

Declared divergences. A copy whose text is a documented different
lineage is not line-comparable; it is declared with a reason and pinned
by the SHA-256 of its normalized text, so any change to it (including a
dropped guard leg) still fails the gate. The summary printed on every
run names each compared pair, each pinned copy and the reason.

Usage:
  python3 tools/ci/storage-lua-parity-check.py            # self-test
  python3 tools/ci/storage-lua-parity-check.py --assert   # live tree
  python3 tools/ci/storage-lua-parity-check.py --print-pins
      Recompute the pinned digests, for a review after a deliberate
      change to a declared-divergent copy; re-syncing the copy with its
      family is the better fix.

Exit status: 0 when clean, 1 on the first violation. Pure offline
tooling: it reads only the checkout and needs no host language runtime.
"""
import hashlib
import os
import re
import sys

RUNTIMES = ("php", "go", "python", "jvm", "rust", "dotnet", "node", "ruby", "elixir")

# ---------------------------------------------------------------------
# The declared coverage: which runtime carries which family, under which
# literal name.
# ---------------------------------------------------------------------
FAMILIES = {
    "php": {
        "prelude": "ENVELOPE_LUA_PRELUDE",
        "consume": "CONSUME_SCRIPT",
        "delete-if-pending": "DELETE_IF_PENDING_SCRIPT",
        "cancel": "CANCEL_SCRIPT",
        "claim-resume": "CLAIM_RESUME_SCRIPT",
        "release-resume": "RELEASE_RESUME_SCRIPT",
        "commit": "COMMIT_SCRIPT",
    },
    "go": {
        "prelude": "luaEnvelopePrelude",
        "consume": "ConsumeScript",
        "delete-if-pending": "DeleteIfPendingScript",
        "cancel": "CancelScript",
        "commit": "CommitScript",
    },
    "python": {
        "prelude": "ENVELOPE_LUA_PRELUDE",
        "consume": "CONSUME_SCRIPT",
        "delete-if-pending": "DELETE_IF_PENDING_SCRIPT",
        "cancel": "CANCEL_SCRIPT",
        "commit": "COMMIT_SCRIPT",
    },
    "jvm": {
        "prelude": "ENVELOPE_PRELUDE",
        "consume": "CONSUME_SCRIPT",
        "delete-if-pending": "DELETE_IF_PENDING_SCRIPT",
        "cancel": "CANCEL_SCRIPT",
        "commit": "COMMIT_SCRIPT",
    },
    "rust": {
        "prelude": "ENVELOPE_LUA_PRELUDE",
        "consume": "CONSUME_TRANSITION_LUA",
        "delete-if-pending": "DELETE_IF_PENDING_LUA",
        "cancel": "CANCEL_TRANSITION_LUA",
        "claim-resume": "CLAIM_RESUME_LUA",
        "release-resume": "RELEASE_RESUME_LUA",
        "commit": "COMMIT_RESULT_LUA",
        "commit-clearing-claim": "COMMIT_RESULT_CLEARING_CLAIM_LUA",
    },
    "dotnet": {
        "prelude": "EnvelopePrelude",
        "consume": "ConsumeScript",
        "delete-if-pending": "DeleteIfPendingScript",
        "cancel": "CancelScript",
        "commit": "CommitScript",
    },
    "node": {
        "prelude": "ENVELOPE_LUA_PRELUDE",
        "consume": "CONSUME_SCRIPT",
        "delete-if-pending": "DELETE_IF_PENDING_SCRIPT",
    },
    "ruby": {
        "prelude": "ENVELOPE_LUA_PRELUDE",
        "consume": "CONSUME_SCRIPT",
        "delete-if-pending": "DELETE_IF_PENDING_SCRIPT",
    },
    "elixir": {
        "prelude": "prelude",
        "consume": "consume_script",
        "delete-if-pending": "delete_if_pending_script",
    },
}

CARRIERS = {
    "php": "packages/kiwicaptcha-php/src/Storage/RedisStorage.php",
    "go": "packages/kiwicaptcha-go/lua.go",
    "python": "packages/kiwicaptcha-python-sdk/kiwicaptcha/stores/_lua_scripts.py",
    "jvm": "packages/kiwicaptcha-jvm/core/src/main/java/com/kiwicaptcha/LuaScripts.java",
    "rust": "packages/kiwicaptcha/src/redis_verify.rs",
    "dotnet": "packages/kiwicaptcha-dotnet/src/KiwiCaptcha/Redis.cs",
    "node": "packages/kiwicaptcha-node/src/stores/redis.ts",
    "ruby": "packages/kiwicaptcha-ruby/lib/kiwicaptcha/stores/redis.rb",
    "elixir": "packages/kiwicaptcha-elixir/lib/kiwicaptcha/stores/redis.ex",
}

# The name of the prelude literal each runtime joins its family literals
# with, or None when the host joins them at the call site (Rust, whose
# extractor asserts the join instead). The boundary newline differs: PHP
# fuses (php-boundary-fusion), the rest keep the prelude's newline.
PRELUDE_PREFIX = {
    "php": "ENVELOPE_LUA_PRELUDE",
    "go": "luaEnvelopePrelude",
    "python": "ENVELOPE_LUA_PRELUDE",
    "jvm": "ENVELOPE_PRELUDE",
    "rust": None,
    "dotnet": "EnvelopePrelude",
    "node": "ENVELOPE_LUA_PRELUDE",
    "ruby": "ENVELOPE_LUA_PRELUDE",
    "elixir": "prelude",
}

# Every family any runtime declares: the comparison must cover a family
# even when only one runtime carries it (the pinned check still runs).
ALL_FAMILIES = tuple(sorted({family for runtime in RUNTIMES for family in FAMILIES[runtime]}))

# Family -> (reference runtime, ordered party runtimes). Parties are
# compared against the reference line for line. A declared copy that is
# neither a reference, a party, nor pinned is a failure.
COVERAGE = {
    "prelude": ("php", ("go", "python", "jvm", "dotnet", "node", "ruby", "elixir", "rust")),
    "consume": ("php", ("go", "python", "jvm", "dotnet", "node", "ruby", "elixir")),
    "delete-if-pending": ("php", ("go", "python", "jvm", "dotnet", "node", "ruby",
                                  "elixir", "rust")),
    "cancel": ("php", ("go", "python", "jvm", "dotnet", "rust")),
    "claim-resume": (None, ()),
    "release-resume": ("php", ("rust",)),
    "commit": ("php", ("go", "python", "jvm", "dotnet")),
    "commit-clearing-claim": (None, ()),
}

# The copies whose text is a documented different lineage: not
# line-comparable, pinned by the digest of the normalized text instead.
# The pin is not a blessing: any change to the copy fails the gate, so a
# dropped guard leg in a pinned copy is caught too.
PINNED = {
    ("rust", "consume"):
        "the Rust core's consume predates the PHP port and is only behaviour "
        "compatible: single quotes in redis.call, a bare `return false` where the "
        "port returns nil, and a three-element reply",
    ("rust", "commit"):
        "the Rust core's commit predates the claim-fencing arguments the PHP port "
        "added; its resume path uses the separate commit-clearing-claim script",
    ("php", "claim-resume"):
        "the claim copies are a known coverage gap of the line comparison: the php "
        "and rust claim scripts differ in the local microsecond variable name and "
        "in how the lease value is formatted for the splice, so neither pair is "
        "line-comparable and each copy is pinned instead",
    ("rust", "claim-resume"):
        "the claim copies are a known coverage gap of the line comparison: the php "
        "and rust claim scripts differ in the local microsecond variable name and "
        "in how the lease value is formatted for the splice, so neither pair is "
        "line-comparable and each copy is pinned instead",
    ("rust", "commit-clearing-claim"):
        "the sole carrier: the PHP port folds the same claim fence into its commit "
        "script, so there is nothing to compare it against",
}

# SHA-256 of the normalized text of each pinned copy. Regenerate with
# --print-pins after a reviewed change; prefer re-syncing the copy with
# the family it diverged from. The literal digests are below the table.
PINNED_DIGESTS = {
    ("php", "claim-resume"):
        "591ea4fc97051e8e793bc73fd6f5e3d7caed5cf6aefc8c4fe2daca17778d9e9c",
    ("rust", "claim-resume"):
        "f33d520b72b30369e81ed61c8d4bde9fcd0d6ba994dc754c382f73a497afb2f2",
    ("rust", "commit"):
        "ea8c8c76b4e0132f5745616edc2cadb8f58a9399c2932af77e34b38c5de09bc7",
    ("rust", "commit-clearing-claim"):
        "f69320529ab09ed821fc030d32a6f9f639580c74efebe51ead1d1db4d2aa747b",
    ("rust", "consume"):
        "bdc200254fa6a246444e0699404a8fbc8690ffb8f8b0b8e086f38649939ce022",
}

# The marker every storage-transition copy carries: the shared envelope
# scanner's entry point. A hit outside the declared carriers is a copy
# the gate does not know about.
MARKER = "kiwiTopLevelFields"

SWEEP_EXTENSIONS = (".go", ".py", ".java", ".rs", ".cs", ".ts", ".rb", ".ex",
                    ".exs", ".php", ".lua", ".json", ".md")
# Install-artifact and build-output directories are excluded from the
# sweep: they are regenerated from published packages on an install and
# are not source mirrors (a stale vendored copy of another lineage must
# not fail the gate). Every tracked source file is still swept.
SWEEP_SKIP_DIRS = (".git", "target", "node_modules", "vendor", "__pycache__",
                   ".venv", ".mypy_cache", ".gradle", "bin", "obj")


class ExtractionError(Exception):
    """A declared copy could not be extracted, or a literal could not be
    decoded by the host's own rules."""


def _fail(where, message):
    raise ExtractionError("%s: %s" % (where, message))


def _leading_ws(line):
    return len(line) - len(line.lstrip(" \t"))


def _skip_hspace(text, i):
    while i < len(text) and text[i] in " \t":
        i += 1
    return i


# ---------------------------------------------------------------------
# Per-language extractors. Each returns {literal name: (value, prefix)},
# where `value` is the exact string the runtime holds and `prefix` names
# the prelude literal the value is concatenated with (None for a
# standalone literal). Every shape the extractor does not recognize is
# an ExtractionError, never a skip.
# ---------------------------------------------------------------------

def extract_php(text, where):
    """PHP nowdoc heredocs delimited by LUA (php-nowdoc)."""
    out = {}
    pattern = re.compile(
        r"^\s*(?:[\w\\]+\s+)*const\s+([A-Z_][A-Z0-9_]*)\s*=\s*"
        r"(?:self::([A-Z_][A-Z0-9_]*)\s*\.\s*)?<<<'LUA'\n", re.M)
    closing = re.compile(r"^([ \t]*)LUA;", re.M)
    for m in pattern.finditer(text):
        name, prefix = m.group(1), m.group(2)
        end = closing.search(text, m.end())
        if end is None:
            _fail(where, "unterminated <<<'LUA' nowdoc for %s" % name)
        if name in out:
            _fail(where, "duplicate literal %s" % name)
        body = text[m.end():end.start()]
        indent = end.group(1)
        if indent:
            lines = []
            for line in body.split("\n"):
                if line.startswith(indent):
                    lines.append(line[len(indent):])
                elif line.strip() == "":
                    lines.append("")
                else:
                    _fail(where, "a line of %s is indented less than the closing "
                                 "marker: %r" % (name, line))
            body = "\n".join(lines)
        if body.endswith("\n"):
            body = body[:-1]
        out[name] = (body, prefix)
    return out


def extract_go(text, where):
    """Go raw (backtick) const literals plus the backtick splice
    (go-raw-string). A quoted part must decode to one backtick."""
    raw = {}
    for m in re.finditer(r"^const ([A-Za-z_][A-Za-z0-9_]*) = ", text, re.M):
        name = m.group(1)
        if name in raw:
            _fail(where, "duplicate const %s" % name)
        parts = []
        i = m.end()
        while True:
            i = _skip_hspace(text, i)
            if i >= len(text):
                _fail(where, "truncated const %s" % name)
            c = text[i]
            if c == "`":
                j = text.find("`", i + 1)
                if j < 0:
                    _fail(where, "unterminated raw string for %s" % name)
                parts.append(("text", text[i + 1:j]))
                i = j + 1
            elif c == '"':
                j = i + 1
                decoded = []
                while j < len(text) and text[j] != '"':
                    if text[j] == "\\":
                        j += 1
                        if j >= len(text):
                            _fail(where, "truncated escape in %s" % name)
                        if text[j] == "`":
                            decoded.append("`")
                        else:
                            decoded.append("\\" + text[j])
                    else:
                        decoded.append(text[j])
                    j += 1
                if j >= len(text):
                    _fail(where, "unterminated quoted string for %s" % name)
                if "".join(decoded) != "`":
                    _fail(where, "%s concatenates a quoted string that is not the "
                                 "backtick splice: %r" % (name, "".join(decoded)))
                parts.append(("text", "`"))
                i = j + 1
            else:
                ident = re.match(r"[A-Za-z_][A-Za-z0-9_]*", text[i:])
                if ident is None:
                    _fail(where, "unexpected %r in the %s expression" % (text[i:i + 30], name))
                parts.append(("ref", ident.group(0)))
                i += len(ident.group(0))
            i = _skip_hspace(text, i)
            if i < len(text) and text[i] == "+":
                i += 1
                continue
            if i >= len(text) or text[i] == "\n":
                break
            _fail(where, "unexpected %r after a part of %s" % (text[i:i + 30], name))
        if not any(kind == "text" for kind, _ in parts):
            _fail(where, "%s concatenates no raw string" % name)
        prefix = None
        if parts and parts[0][0] == "ref":
            prefix = parts[0][1]
            parts = parts[1:]
        if any(kind == "ref" for kind, _ in parts):
            _fail(where, "%s carries a prelude reference in a non-leading position" % name)
        raw[name] = ("".join(val for _kind, val in parts), prefix)

    return raw


def extract_python(text, where):
    """Python raw triple-quoted literals (`r'''`) joined with `+`."""
    out = {}
    pattern = re.compile(
        r"^([A-Z_][A-Z0-9_]*) = (?:([A-Z_][A-Z0-9_]*) \+ )?r'''(.*?)^'''$", re.M | re.S)
    for m in pattern.finditer(text):
        name = m.group(1)
        if name in out:
            _fail(where, "duplicate literal %s" % name)
        out[name] = (m.group(3), m.group(2))
    return out


JAVA_SIMPLE_ESCAPES = {"b": "\b", "s": " ", "t": "\t", "n": "\n", "f": "\f",
                       "r": "\r", '"': '"', "'": "'", "\\": "\\"}


def unescape_java(s, where, name):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        if i + 1 >= len(s):
            _fail(where, "%s ends with a dangling backslash" % name)
        nxt = s[i + 1]
        if nxt == "\n":
            _fail(where, "%s carries a line continuation" % name)
        if nxt in JAVA_SIMPLE_ESCAPES:
            out.append(JAVA_SIMPLE_ESCAPES[nxt])
            i += 2
        elif nxt == "u":
            if not re.match(r"[0-9a-fA-F]{4}", s[i + 2:i + 6]):
                _fail(where, "%s carries a malformed unicode escape" % name)
            out.append(chr(int(s[i + 2:i + 6], 16)))
            i += 6
        elif nxt in "01234567":
            j = i + 1
            while j < len(s) and j < i + 4 and s[j] in "01234567":
                j += 1
            out.append(chr(int(s[i + 1:j], 8)))
            i = j
        else:
            _fail(where, "unhandled Java escape \\%s in %s" % (nxt, name))
    return "".join(out)


def extract_java(text, where):
    """Java text blocks with incidental-indentation stripping and escape
    translation (java-text-block)."""
    out = {}
    pattern = re.compile(
        r"^\s*(?:public |private |protected )?(?:static )?(?:final )?"
        r"String ([A-Z_][A-Z0-9_]*) = (?:([A-Z_][A-Z0-9_]*) \+ )?\"\"\"\n"
        r"(.*?)^([ \t]*)\"\"\";", re.M | re.S)
    for m in pattern.finditer(text):
        name, prefix, body, closing_indent = m.group(1), m.group(2), m.group(3), m.group(4)
        if name in out:
            _fail(where, "duplicate literal %s" % name)
        lines = body.split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        else:
            _fail(where, "the %s text block does not end with a newline" % name)
        widths = [_leading_ws(line) for line in lines if line.strip()]
        widths.append(len(closing_indent))
        indent = min(widths) if widths else 0
        decoded = []
        for line in lines:
            if line.strip() == "":
                decoded.append("")
            elif _leading_ws(line) >= indent:
                decoded.append(unescape_java(line[indent:], where, name))
            else:
                _fail(where, "a line of %s is indented less than the incidental "
                             "indentation" % name)
        out[name] = ("\n".join(decoded) + "\n", prefix)
    return out


def extract_rust(text, where):
    """Rust `r#"..."#` const literals (rust-raw-string). The prelude join
    lives at the call site and is asserted here."""
    out = {}
    pattern = re.compile(r"^const ([A-Z_][A-Z0-9_]*): &str = r#\"(.*?)\"#;$", re.M | re.S)
    for m in pattern.finditer(text):
        name = m.group(1)
        if name in out:
            _fail(where, "duplicate const %s" % name)
        out[name] = (m.group(2), None)
    for name in sorted(out):
        if name == "ENVELOPE_LUA_PRELUDE":
            continue
        call = '"{ENVELOPE_LUA_PRELUDE}{%s}"' % name
        if call not in text:
            _fail(where, "%s is not joined with the prelude at the call site "
                         "(expected %s)" % (name, call))
    return out


def scan_csharp_verbatim(text, start, where, name):
    """The value of the C# verbatim string whose opening quote sits at
    start, plus the index after the closing quote (csharp-verbatim)."""
    i = start + 1
    out = []
    while i < len(text):
        c = text[i]
        if c == '"':
            if text[i + 1:i + 2] == '"':
                out.append('"')
                i += 2
                continue
            return "".join(out), i + 1
        out.append(c)
        i += 1
    _fail(where, "unterminated verbatim string for %s" % name)


def extract_csharp(text, where):
    """C# verbatim strings (`@"..."`), including `Prelude + @"..."`."""
    out = {}
    pattern = re.compile(
        r"^\s*(?:(?:internal|public|private|protected)\s+)?"
        r"(?:(?:const|static|readonly)\s+)*"
        r"string\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?:([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*)?@\"", re.M)
    for m in pattern.finditer(text):
        name = m.group(1)
        if name in out:
            _fail(where, "duplicate literal %s" % name)
        value, _end = scan_csharp_verbatim(text, m.end() - 1, where, name)
        out[name] = (value, m.group(2))
    return out


JS_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
                     "v": "\v", "0": "\0", "\\": "\\", "`": "`", "$": "$",
                     "'": "'", '"': '"'}


def unescape_js(s, where, name):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "$" and s[i + 1:i + 2] == "{":
            _fail(where, "%s carries a template interpolation" % name)
        if c != "\\":
            out.append(c)
            i += 1
            continue
        if i + 1 >= len(s):
            _fail(where, "%s ends with a dangling backslash" % name)
        nxt = s[i + 1]
        if nxt == "\n":
            _fail(where, "%s carries a line continuation" % name)
        if nxt in JS_SIMPLE_ESCAPES:
            out.append(JS_SIMPLE_ESCAPES[nxt])
            i += 2
        elif nxt == "u":
            if s[i + 2:i + 3] == "{":
                j = s.find("}", i + 3)
                if j < 0:
                    _fail(where, "%s carries a malformed unicode escape" % name)
                out.append(chr(int(s[i + 3:j], 16)))
                i = j + 1
            else:
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
        elif nxt == "x":
            out.append(chr(int(s[i + 2:i + 4], 16)))
            i += 4
        else:
            _fail(where, "unhandled template escape \\%s in %s" % (nxt, name))
    return "".join(out)


def extract_node(text, where):
    """TypeScript template literals (node-template)."""
    out = {}
    pattern = re.compile(
        r"^const ([A-Z_][A-Z0-9_]*) = (?:([A-Z_][A-Z0-9_]*) \+ )?`", re.M)
    for m in pattern.finditer(text):
        name = m.group(1)
        if name in out:
            _fail(where, "duplicate literal %s" % name)
        i = m.end()
        chunks = []
        while i < len(text) and text[i] != "`":
            if text[i] == "\\":
                chunks.append(text[i:i + 2])
                i += 2
                continue
            chunks.append(text[i])
            i += 1
        if i >= len(text):
            _fail(where, "unterminated template literal for %s" % name)
        out[name] = (unescape_js("".join(chunks), where, name), m.group(2))
    return out


SCRIPT_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "s": " ",
                         "e": "\x1b", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
                         "\\": "\\", '"': '"', "'": "'", "#": "#"}


def unescape_script_string(s, where, name, host, interp):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == interp[0] and s[i + 1:i + 2] == interp[1]:
            _fail(where, "%s carries an interpolation" % name)
        if c != "\\":
            out.append(c)
            i += 1
            continue
        if i + 1 >= len(s):
            _fail(where, "%s ends with a dangling backslash" % name)
        nxt = s[i + 1]
        if nxt == "\n":
            i += 2
            continue
        if nxt in SCRIPT_SIMPLE_ESCAPES:
            out.append(SCRIPT_SIMPLE_ESCAPES[nxt])
            i += 2
        elif nxt == "u":
            if host == "elixir" and s[i + 2:i + 3] == "{":
                j = s.find("}", i + 3)
                if j < 0:
                    _fail(where, "%s carries a malformed unicode escape" % name)
                out.append(chr(int(s[i + 3:j], 16)))
                i = j + 1
            else:
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
        elif nxt == "x" and host == "ruby":
            out.append(chr(int(s[i + 2:i + 4], 16)))
            i += 4
        else:
            _fail(where, "unhandled %s escape \\%s in %s" % (host, nxt, name))
    return "".join(out)


def extract_ruby(text, where):
    """Ruby squiggly heredocs (ruby-heredoc)."""
    out = {}
    pattern = re.compile(
        r"^([ \t]*)([A-Z_][A-Z0-9_]*) = (?:([A-Z_][A-Z0-9_]*) \+ )?<<~LUA\n", re.M)
    for m in pattern.finditer(text):
        indent, name, prefix = m.group(1), m.group(2), m.group(3)
        if name in out:
            _fail(where, "duplicate literal %s" % name)
        end = re.compile(r"^%sLUA$" % re.escape(indent), re.M).search(text, m.end())
        if end is None:
            _fail(where, "unterminated <<~LUA heredoc for %s" % name)
        lines = text[m.end():end.start()].split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        widths = [_leading_ws(line) for line in lines if line.strip()]
        dedent = min(widths) if widths else 0
        stripped = []
        for line in lines:
            if line.strip() == "":
                stripped.append("")
            elif _leading_ws(line) >= dedent:
                stripped.append(line[dedent:])
            else:
                _fail(where, "a line of %s is indented less than the heredoc's "
                             "least-indented line" % name)
        value = unescape_script_string("\n".join(stripped) + "\n", where, name, "ruby", "#{")
        out[name] = (value, prefix)
    return out


def _elixir_heredoc(body, indent, where, name):
    lines = body.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    stripped = []
    for line in lines:
        if line.strip() == "":
            stripped.append("")
        elif _leading_ws(line) >= len(indent):
            stripped.append(line[len(indent):])
        else:
            _fail(where, "a line of %s is indented less than its closing "
                         "delimiter" % name)
    return unescape_script_string("\n".join(stripped) + "\n", where, name, "elixir", "#{")


def extract_elixir(text, where):
    """Elixir heredocs in the script functions (elixir-heredoc). The body
    functions join the prelude with `<>`, which the pattern asserts."""
    out = {}
    body_pattern = re.compile(
        r"^  defp ([a-z_][a-z0-9_]*) do\n[ \t]*prelude\(\) <>\n([ \t]+)\"\"\"\n(.*?)^\2\"\"\"\n",
        re.M | re.S)
    prelude_pattern = re.compile(
        r"^  defp (prelude) do\n([ \t]+)\"\"\"\n(.*?)^\2\"\"\"\n", re.M | re.S)
    for m in body_pattern.finditer(text):
        name, indent, body = m.group(1), m.group(2), m.group(3)
        if name in out:
            _fail(where, "duplicate literal %s" % name)
        out[name] = (_elixir_heredoc(body, indent, where, name), "prelude")
    for m in prelude_pattern.finditer(text):
        name, indent, body = m.group(1), m.group(2), m.group(3)
        if name in out:
            _fail(where, "duplicate literal %s" % name)
        out[name] = (_elixir_heredoc(body, indent, where, name), None)
    return out


EXTRACTORS = {
    "php": extract_php,
    "go": extract_go,
    "python": extract_python,
    "jvm": extract_java,
    "rust": extract_rust,
    "dotnet": extract_csharp,
    "node": extract_node,
    "ruby": extract_ruby,
    "elixir": extract_elixir,
}


# ---------------------------------------------------------------------
# Normalization: layout only, never content.
# ---------------------------------------------------------------------

def strip_trailing_comment(line):
    """The line's code without a trailing Lua comment, or None when the
    line is blank or comment-only. The scan tracks short-string quoting,
    so a `--` inside a string literal stays content. The same rule
    absorbs the php-boundary-fusion line, where the prelude's last code
    line is glued to the next script's leading comment."""
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote is not None:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"":
            quote = c
            i += 1
            continue
        if c == "-" and line[i + 1:i + 2] == "-":
            return line[:i].rstrip() or None
        i += 1
    return line.strip() or None


def normalize(text):
    """Layout-only normalization: blank lines dropped, per-line leading
    and trailing whitespace stripped, comment-only lines dropped, a
    trailing comment stripped. Inner whitespace is untouched."""
    out = []
    for line in text.split("\n"):
        code = strip_trailing_comment(line)
        if code is not None:
            out.append(code)
    return out


def digest(lines):
    return hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def first_difference(reference, other):
    """(index, reference line or None, other line or None) at the first
    differing normalized line, or None when the two are equal."""
    for i in range(max(len(reference), len(other))):
        a = reference[i] if i < len(reference) else None
        b = other[i] if i < len(other) else None
        if a != b:
            return i, a, b
    return None


def missing_declared(literals, declared):
    """The declared (family, literal name) pairs a source did not carry.
    A declared copy that cannot be found is a failure, never a skip."""
    return [(family, name) for family, name in sorted(declared.items())
            if name not in literals]


# ---------------------------------------------------------------------
# The comparison core: a state ({runtime: {family: value}}) plus the
# coverage table plus the pins. The self-test drives it with synthetic
# states; --assert drives it with the extracted tree.
# ---------------------------------------------------------------------

def prelude_join(state, runtime, family):
    """The full runtime string for the family: the prelude literal plus
    the body literal, exactly as the host joins them. The prelude family
    is the prelude itself, never the prelude twice."""
    if family == "prelude":
        return state[runtime]["prelude"]
    return state[runtime]["prelude"] + state[runtime][family]


def check_state(state, coverage, pinned, pinned_digests, families):
    """Every violation, in a stable order. `state` maps runtime -> family
    -> the literal's own value."""
    violations = []
    for family in sorted(families):
        if family not in coverage:
            violations.append("the coverage table has no entry for family %s" % family)
            continue
        reference, parties = coverage[family]
        if reference is not None:
            for runtime in parties:
                if (runtime, family) in pinned:
                    violations.append("%s: %s is both compared and pinned" % (family, runtime))
        expected = set(parties) | {rt for (rt, fam) in pinned if fam == family}
        if reference is not None:
            expected.add(reference)
        present = {rt for rt in state if family in state[rt]}
        for runtime in sorted(present - expected):
            violations.append("%s: the copy is carried by %s but is neither compared nor "
                              "declared as a pinned divergence" % (family, runtime))
        for runtime in sorted(expected - present):
            violations.append("%s: the declared copy of %s is missing from %s; a runtime "
                              "whose copy cannot be found is a failure, never a skip"
                              % (family, family, runtime))
        if reference is None:
            continue
        ref_text = state.get(reference, {}).get(family)
        if ref_text is None:
            continue
        ref_lines = normalize(prelude_join(state, reference, family))
        for runtime in parties:
            if runtime not in state or family not in state[runtime]:
                continue
            lines = normalize(prelude_join(state, runtime, family))
            diff = first_difference(ref_lines, lines)
            if diff is None:
                continue
            index, a, b = diff
            violations.append(
                "%s: runtime pair (%s, %s) differ at normalized line %d "
                "(the reference copy has %d lines, the %s copy %d)\n"
                "      %s: %s\n      %s: %s"
                % (family, reference, runtime, index + 1,
                   len(ref_lines), runtime, len(lines),
                   reference, "<line missing>" if a is None else a,
                   runtime, "<line missing>" if b is None else b))
    for (runtime, family) in sorted(pinned):
        if runtime not in state or family not in state[runtime]:
            continue
        if family not in coverage:
            violations.append("%s: the %s copy is pinned but the coverage table has no such "
                              "family" % (family, runtime))
            continue
        lines = normalize(prelude_join(state, runtime, family))
        got = digest(lines)
        want = pinned_digests.get((runtime, family))
        if want is None:
            violations.append("%s: the %s copy is declared divergent but has no pinned "
                              "digest" % (family, runtime))
        elif got != want:
            violations.append(
                "%s: the pinned %s copy changed\n"
                "      declared divergent because %s\n"
                "      expected sha256 %s\n      actual   sha256 %s\n"
                "      if the copy was re-synced with its family, move it into the "
                "compared set; otherwise update the pin with --print-pins"
                % (family, runtime, pinned[(runtime, family)], want, got))
    return violations


# ---------------------------------------------------------------------
# Live-tree extraction.
# ---------------------------------------------------------------------

def go_const_names(text):
    """Go const names declared outside any raw string (the extractor
    reads top-level `const` declarations; this also catches a const
    block, so a new Lua copy cannot slip in there)."""
    names = []
    in_raw = False
    for lineno, line in enumerate(text.split("\n"), 1):
        if in_raw:
            if "`" in line:
                in_raw = False
            continue
        if line.count("`") % 2 == 1:
            in_raw = True
        for m in re.finditer(r"^(?:const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=|const\s*\(|"
                             r"\t([A-Za-z_][A-Za-z0-9_]*)\s*=)", line):
            name = m.group(1) or m.group(2)
            if name is not None:
                names.append((name, lineno))
    return names


def lua_shaped(value):
    """A literal whose first non-blank line is a Lua comment or a `local`
    declaration: the shape every storage-transition copy starts with."""
    first = next((line.strip() for line in value.split("\n") if line.strip()), "")
    return first.startswith("--") or first.startswith("local ")


def extract_tree(root):
    """(state, violations). Violations are extraction failures: they are
    failures of the gate, never skips."""
    state = {}
    violations = []
    for runtime in RUNTIMES:
        rel = CARRIERS[runtime]
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            violations.append("carrier file missing: %s" % rel)
            continue
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        try:
            literals = EXTRACTORS[runtime](text, rel)
        except ExtractionError as exc:
            violations.append(str(exc))
            continue
        declared = FAMILIES[runtime]
        by_name = {name: fam for fam, name in declared.items()}
        state[runtime] = {}
        for name in sorted(literals):
            value, prefix = literals[name]
            if name not in by_name:
                if lua_shaped(value):
                    violations.append(
                        "%s: undeclared Lua literal %s; declare it in FAMILIES (compared) "
                        "or PINNED (with a reason)" % (rel, name))
                continue
            family = by_name[name]
            expected_prefix = None if family == "prelude" else PRELUDE_PREFIX[runtime]
            if prefix != expected_prefix:
                violations.append("%s: %s joins the wrong way (prefix %r, expected %r)"
                                  % (rel, name, prefix, expected_prefix))
                continue
            state[runtime][family] = value
        for family, name in missing_declared(literals, declared):
            violations.append(
                "%s: the declared %s copy (%s) is not present; a runtime whose copy "
                "cannot be found is a failure, never a skip. Literals found: %s"
                % (rel, family, name, ", ".join(sorted(literals)) or "none"))
        for family in sorted(state[runtime]):
            if "[[" in state[runtime][family]:
                violations.append(
                    "%s: the %s copy carries a Lua long-bracket string; the layout-only "
                    "normalizer tracks short-string quoting only, so a long string must be "
                    "handled explicitly before this copy can be compared"
                    % (rel, family))
        if runtime == "go":
            for name, lineno in go_const_names(text):
                if name not in by_name:
                    violations.append("%s:%d: undeclared Go const %s in a Lua carrier; "
                                      "declare it or move it" % (rel, lineno, name))
    return state, violations


def sweep_for_unknown_copies(root):
    """Any source file outside the declared carriers that carries the
    shared scanner's marker is a copy the gate does not know about. The
    sweep covers the whole packages/ and tests/ trees, so a mirror that
    lands in a package the gate has never heard of is still caught."""
    violations = []
    known = {os.path.realpath(os.path.join(root, p)) for p in CARRIERS.values()}
    roots = [os.path.join(root, "packages"), os.path.join(root, "tests")]
    for package_root in roots:
        if not os.path.isdir(package_root):
            continue
        for dirpath, dirnames, filenames in os.walk(package_root):
            dirnames[:] = [d for d in dirnames if d not in SWEEP_SKIP_DIRS]
            for filename in filenames:
                if not filename.endswith(SWEEP_EXTENSIONS):
                    continue
                path = os.path.join(dirpath, filename)
                if os.path.realpath(path) in known:
                    continue
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        for lineno, line in enumerate(fh, 1):
                            if MARKER in line:
                                violations.append(
                                    "undeclared storage Lua copy: %s:%d carries %s; add "
                                    "it as a carrier in FAMILIES/CARRIERS"
                                    % (os.path.relpath(path, root), lineno, MARKER))
                                break
                except OSError as exc:
                    violations.append("cannot read %s: %s" % (path, exc))
    return violations


def assert_live(root):
    state, violations = extract_tree(root)
    if not violations:
        violations = check_state(state, COVERAGE, PINNED, PINNED_DIGESTS, ALL_FAMILIES)
    if not violations:
        violations = sweep_for_unknown_copies(root)
    if violations:
        for message in violations:
            print("storage-lua-parity-check: FAIL: %s" % message, file=sys.stderr)
        return 1
    report_coverage()
    print("storage-lua-parity-check: PASS (%d runtimes, %d families, %d pinned copies)"
          % (len(state), len(ALL_FAMILIES), len(PINNED)))
    return 0


def report_coverage():
    for family in ALL_FAMILIES:
        reference, parties = COVERAGE.get(family, (None, ()))
        pinned_here = sorted(rt for (rt, fam) in PINNED if fam == family)
        if reference is None:
            print("  %s: not line-comparable; pinned: %s"
                  % (family, " ".join(pinned_here)))
            continue
        print("  %s: %s (reference) vs %s; pinned: %s"
              % (family, reference, " ".join(parties), " ".join(pinned_here) or "none"))


def print_pins(root):
    state, violations = extract_tree(root)
    if violations:
        for message in violations:
            print("storage-lua-parity-check: FAIL: %s" % message, file=sys.stderr)
        return 1
    for (runtime, family) in sorted(PINNED):
        lines = normalize(prelude_join(state, runtime, family))
        print('    ("%s", "%s"):\n        "%s",' % (runtime, family, digest(lines)))
    return 0


# ---------------------------------------------------------------------
# Self-test: one extraction fixture per host encoding, the layout-only
# verdict cases, and the pinned-copy cases.
# ---------------------------------------------------------------------

LUA_PRELUDE = "-- shared prelude\nlocal KIWI_ENVELOPE_MAX_BYTES = 131072"
LUA_BODY = ("-- a transition\n"
            "local pattern = '[\\t]'\n"
            "local backtick = '`'\n"
            "local KIWI_MIN_TTL_MS = 1000\n"
            "if not kiwiNullish(decoded['consumed_result'])\n"
            "  or not kiwiNullish(decoded['operation_identity'])\n"
            "  or not kiwiNullish(decoded['resume_owner'])\n"
            "  or not kiwiNullish(decoded['resume_until']) then\n"
            "  return nil\n"
            "end")
LUA_GUARD_LEGS = ("  or not kiwiNullish(decoded['resume_owner'])\n"
                  "  or not kiwiNullish(decoded['resume_until']) then\n")
EXPECTED_LINES = ["local KIWI_ENVELOPE_MAX_BYTES = 131072",
                  "local pattern = '[\\t]'",
                  "local backtick = '`'",
                  "local KIWI_MIN_TTL_MS = 1000",
                  "if not kiwiNullish(decoded['consumed_result'])",
                  "or not kiwiNullish(decoded['operation_identity'])",
                  "or not kiwiNullish(decoded['resume_owner'])",
                  "or not kiwiNullish(decoded['resume_until']) then",
                  "return nil",
                  "end"]


def _lines_with_indent(text, pad, escape_backslash=False):
    lines = text.split("\n")
    if escape_backslash:
        lines = [line.replace("\\", "\\\\") for line in lines]
    return "\n".join(pad + line for line in lines)


def _fixtures():
    """The same Lua written in each host's own encoding, with the
    literal values the host would hold: (fixture, {name: (value, prefix)})."""
    out = []

    php = ("final class F {\n"
           "    private const PRELUDE = <<<'LUA'\n" + LUA_PRELUDE + "\nLUA;\n"
           "    private const BODY = self::PRELUDE . <<<'LUA'\n" + LUA_BODY + "\nLUA;\n"
           "}\n")
    out.append(("php", php, {"PRELUDE": (LUA_PRELUDE, None),
                             "BODY": (LUA_BODY, "PRELUDE")}, "PRELUDE", "BODY"))

    go = ("package f\n\n"
          "const luaEnvelopePrelude = `" + LUA_PRELUDE + "\n`\n\n"
          "const body = luaEnvelopePrelude + `" +
          LUA_BODY.replace("`", "` + \"`\" + `") + "\n`\n")
    out.append(("go", go, {"luaEnvelopePrelude": (LUA_PRELUDE + "\n", None),
                           "body": (LUA_BODY + "\n", "luaEnvelopePrelude")},
                "luaEnvelopePrelude", "body"))

    python = ("ENVELOPE_LUA_PRELUDE = r'''" + LUA_PRELUDE + "\n'''\n\n"
              "BODY = ENVELOPE_LUA_PRELUDE + r'''" + LUA_BODY + "\n'''\n")
    out.append(("python", python, {"ENVELOPE_LUA_PRELUDE": (LUA_PRELUDE + "\n", None),
                                   "BODY": (LUA_BODY + "\n", "ENVELOPE_LUA_PRELUDE")},
                "ENVELOPE_LUA_PRELUDE", "BODY"))

    java_pad = " " * 12
    java = ("public final class F {\n"
            "    static final String PRELUDE = \"\"\"\n" +
            _lines_with_indent(LUA_PRELUDE, java_pad, True) + "\n" + java_pad + "\"\"\";\n"
            "    public static final String BODY = PRELUDE + \"\"\"\n" +
            _lines_with_indent(LUA_BODY, java_pad, True) + "\n" + java_pad + "\"\"\";\n"
            "}\n")
    out.append(("jvm", java, {"PRELUDE": (LUA_PRELUDE + "\n", None),
                              "BODY": (LUA_BODY + "\n", "PRELUDE")}, "PRELUDE", "BODY"))

    rust = ("const ENVELOPE_LUA_PRELUDE: &str = r#\"\n" + LUA_PRELUDE + "\n\"#;\n"
            "const BODY: &str = r#\"\n" + LUA_BODY + "\n\"#;\n"
            "fn build() {\n"
            "    redis::Script::new(&format!(\"{ENVELOPE_LUA_PRELUDE}{BODY}\"));\n"
            "}\n")
    out.append(("rust", rust, {"ENVELOPE_LUA_PRELUDE": ("\n" + LUA_PRELUDE + "\n", None),
                               "BODY": ("\n" + LUA_BODY + "\n", None)},
                "ENVELOPE_LUA_PRELUDE", "BODY"))

    csharp = ("public static class F\n{\n"
              "    internal const string Prelude = @\"\n" +
              LUA_PRELUDE.replace('"', '""') + "\n\";\n"
              "    public static readonly string Body = Prelude + @\"\n" +
              LUA_BODY.replace('"', '""') + "\n\";\n"
              "}\n")
    out.append(("dotnet", csharp, {"Prelude": ("\n" + LUA_PRELUDE + "\n", None),
                                   "Body": ("\n" + LUA_BODY + "\n", "Prelude")},
                "Prelude", "Body"))

    node_esc = LUA_BODY.replace("\\", "\\\\").replace("`", "\\`")
    node = ("const ENVELOPE_LUA_PRELUDE = `\n" + LUA_PRELUDE + "\n`;\n"
            "const BODY = ENVELOPE_LUA_PRELUDE + `\n" + node_esc + "\n`;\n"
            "export const other = `${1}`;\n")
    out.append(("node", node, {"ENVELOPE_LUA_PRELUDE": ("\n" + LUA_PRELUDE + "\n", None),
                               "BODY": ("\n" + LUA_BODY + "\n", "ENVELOPE_LUA_PRELUDE")},
                "ENVELOPE_LUA_PRELUDE", "BODY"))

    ruby_pad = "  "
    ruby = ("ENVELOPE_LUA_PRELUDE = <<~LUA\n" +
            _lines_with_indent(LUA_PRELUDE, ruby_pad, True) + "\nLUA\n"
            "BODY = ENVELOPE_LUA_PRELUDE + <<~LUA\n" +
            _lines_with_indent(LUA_BODY, ruby_pad, True) + "\nLUA\n")
    out.append(("ruby", ruby, {"ENVELOPE_LUA_PRELUDE": (LUA_PRELUDE + "\n", None),
                               "BODY": (LUA_BODY + "\n", "ENVELOPE_LUA_PRELUDE")},
                "ENVELOPE_LUA_PRELUDE", "BODY"))

    elixir = ("  defp body do\n"
              "    prelude() <>\n"
              "      \"\"\"\n" +
              _lines_with_indent(LUA_BODY, "      ", True) + "\n"
              "      \"\"\"\n"
              "  end\n\n"
              "  defp prelude do\n"
              "    \"\"\"\n" +
              _lines_with_indent(LUA_PRELUDE, "    ", True) + "\n"
              "    \"\"\"\n"
              "  end\n")
    out.append(("elixir", elixir, {"prelude": (LUA_PRELUDE + "\n", None),
                                   "body": (LUA_BODY + "\n", "prelude")},
                "prelude", "body"))
    return out


def _state(bodies, prelude=None):
    """A synthetic state: every listed runtime carries the same prelude
    (an empty one unless given) and its own consume body."""
    state = {}
    for runtime, body in bodies.items():
        state[runtime] = {"prelude": LUA_PRELUDE if prelude is None else prelude,
                          "consume": body}
    return state


def self_test():
    failures = 0
    families = {"consume": "CONSUME_SCRIPT"}
    coverage = {"consume": ("php", ("go", "ruby"))}

    def check(name, ok, detail=""):
        nonlocal failures
        print("%s %s%s" % ("PASS" if ok else "FAIL", name, "" if ok else ": " + detail))
        if not ok:
            failures += 1

    print("self-test: %s" % os.path.basename(__file__))

    # 1. Every host encoding decodes to the same Lua, and the
    #    normalized prelude join matches the known line list (the PHP
    #    fusion included).
    for host, fixture, expected, _prelude_name, _body_name in _fixtures():
        try:
            got = EXTRACTORS[host](fixture, "synthetic-%s" % host)
        except ExtractionError as exc:
            check("extractor %s" % host, False, str(exc))
            continue
        ok, detail = True, ""
        for name in sorted(expected):
            want, want_prefix = expected[name]
            if name not in got:
                ok, detail = False, "%s missing (found %s)" % (name, sorted(got))
                break
            value, prefix = got[name]
            if value != want:
                ok, detail = False, "the %s value differs: %r != %r" % (name, value, want)
                break
            if prefix != want_prefix:
                ok, detail = False, "the %s prefix is %r, expected %r" % (name, prefix, want_prefix)
                break
        check("extractor %s decodes its host encoding" % host, ok, detail)

    for host, fixture, expected, prelude_name, body_name in _fixtures():
        try:
            literals = EXTRACTORS[host](fixture, "synthetic-%s" % host)
        except ExtractionError:
            continue
        full = literals[prelude_name][0] + literals[body_name][0]
        check("the %s prelude join normalizes to the shared lines" % host,
              normalize(full) == EXPECTED_LINES, repr(normalize(full)[:3]))

    # 2. The layout-only rules: comments, blank lines, indentation and
    #    trailing comments do not count as differences.
    reference_lines = normalize(LUA_PRELUDE + LUA_BODY)
    check("layout-only normalization keeps inner spacing",
          "local pattern = '[\\t]'" in reference_lines)
    check("a trailing comment is dropped",
          normalize("local a = 1 -- note") == ["local a = 1"])
    check("a comment inside a string is content",
          normalize("local a = 'x--y'") == ["local a = 'x--y'"])
    check("a comment-only line is dropped", normalize("  -- note\nlocal a = 1") == ["local a = 1"])
    check("the php boundary fusion is absorbed",
          normalize("end-- kiwicaptcha consume transition") == ["end"])

    # 3. The verdict cases. The "dropped guard leg" case is the
    #    historical drift: the claim-lease legs removed from a consume
    #    copy, which let that mirror consume a record the others refuse.
    dropped_both = LUA_BODY.replace(
        LUA_GUARD_LEGS,
        "  or not kiwiNullish(decoded['operation_identity']) then\n")

    def verdict(state, pinned=None, pinned_digests=None):
        return check_state(state, coverage, pinned or {}, pinned_digests or {}, families)

    cases = [
        ("identical copies pass", _state({"php": LUA_BODY, "go": LUA_BODY, "ruby": LUA_BODY}),
         False, None),
        ("a dropped claim-lease guard leg fails",
         _state({"php": LUA_BODY, "go": dropped_both, "ruby": LUA_BODY}),
         True, "resume_owner"),
        ("a renamed envelope key fails",
         _state({"php": LUA_BODY, "go": LUA_BODY.replace("resume_owner", "resume_owner_x"),
                 "ruby": LUA_BODY}),
         True, "resume_owner_x"),
        ("a changed constant fails",
         _state({"php": LUA_BODY, "go": LUA_BODY.replace("KIWI_MIN_TTL_MS = 1000",
                                                        "KIWI_MIN_TTL_MS = 2000"),
                 "ruby": LUA_BODY}),
         True, "2000"),
        ("reordered statements fail",
         _state({"php": LUA_BODY,
                 "go": LUA_BODY.replace(
                     "  or not kiwiNullish(decoded['resume_owner'])\n"
                     "  or not kiwiNullish(decoded['resume_until']) then\n",
                     "  or not kiwiNullish(decoded['resume_until'])\n"
                     "  or not kiwiNullish(decoded['resume_owner']) then\n"),
                 "ruby": LUA_BODY}),
         True, "resume_until"),
    ]
    for name, state, expect_fail, needle in cases:
        violations = verdict(state)
        if expect_fail:
            ok = bool(violations) and any(needle in v for v in violations)
            detail = "no violation" if not violations else violations[0][:160]
        else:
            ok = not violations
            detail = violations[0][:160] if violations else ""
        check(name, ok, detail)

    missing = _state({"php": LUA_BODY, "go": LUA_BODY})
    violations = verdict(missing)
    check("a missing declared copy fails",
          any("missing from ruby" in v for v in violations),
          violations[0][:160] if violations else "no violation")

    undeclared = _state({"php": LUA_BODY, "go": LUA_BODY, "ruby": LUA_BODY, "jvm": LUA_BODY})
    violations = verdict(undeclared)
    check("a copy from an undeclared runtime fails",
          any("neither compared nor declared" in v for v in violations),
          violations[0][:160] if violations else "no violation")

    layout_only = ("\n" + LUA_BODY.replace("-- a transition", "-- a transition\n\n-- note\n")
                   .replace("end", "end -- trailing", 1) + "\n\n")
    violations = verdict(_state({"php": LUA_BODY, "go": LUA_BODY, "ruby": layout_only}))
    check("layout-only differences pass", not violations,
          violations[0][:160] if violations else "")

    violations = check_state(_state({"php": LUA_BODY, "go": LUA_BODY, "ruby": LUA_BODY}),
                             coverage, {}, {},
                             {"consume": "CONSUME_SCRIPT", "new-family": "NEW_SCRIPT"})
    check("a declared family with no coverage entry fails",
          any("no entry for family" in v for v in violations),
          violations[0][:160] if violations else "no violation")

    # 4. The pinned copies: unchanged passes, changed fails, and a
    #    pinned copy that is also compared is a table error.
    pinned = {("rust", "consume"): "a declared different lineage"}
    pinned_state = _state({"php": LUA_BODY, "go": LUA_BODY, "ruby": LUA_BODY, "rust": LUA_BODY})
    good_pins = {("rust", "consume"): digest(normalize(LUA_PRELUDE + LUA_BODY))}
    violations = verdict(pinned_state, pinned, good_pins)
    check("an unchanged pinned copy passes", not violations,
          violations[0][:160] if violations else "")
    violations = verdict(pinned_state, pinned, {("rust", "consume"): "0" * 64})
    check("a changed pinned copy fails", any("pinned" in v for v in violations),
          violations[0][:160] if violations else "no violation")
    violations = verdict(pinned_state, {("ruby", "consume"): "also compared"}, good_pins)
    check("a copy that is both compared and pinned fails",
          any("both compared and pinned" in v for v in violations),
          violations[0][:160] if violations else "no violation")

    # 5. Extraction failures are verdicts, not skips: a declared copy
    #    absent from the source is reported, and undecodable shapes are
    #    refused.
    reported = missing_declared(extract_php("<?php\n// nothing\n", "synthetic"),
                                FAMILIES["php"])
    check("a source with no declared copy reports every one of them",
          [name for _family, name in reported] == sorted(FAMILIES["php"].values()),
          repr(reported))
    for name, thunk in [
        ("an unknown template escape is refused",
         lambda: extract_node("const A = `x\\q`;\n", "synthetic")),
        ("a template interpolation is refused",
         lambda: extract_node("const A = `x${y}`;\n", "synthetic")),
        ("an unterminated nowdoc is refused",
         lambda: extract_php("<?php\nconst A = <<<'LUA'\nx\n", "synthetic")),
        ("a Rust literal without the call-site join is refused",
         lambda: extract_rust("const ENVELOPE_LUA_PRELUDE: &str = r#\"\nx\n\"#;\n"
                              "const BODY: &str = r#\"\ny\n\"#;\n", "synthetic")),
    ]:
        try:
            result = thunk()
        except ExtractionError:
            check(name, True)
            continue
        check(name, False, "returned %r" % (result,))
    check("a declared copy absent from the literals is reported",
          missing_declared({"ENVELOPE_LUA_PRELUDE": ("", None)},
                           {"prelude": "ENVELOPE_LUA_PRELUDE", "consume": "CONSUME_SCRIPT"})
          == [("consume", "CONSUME_SCRIPT")])

    print("%s: %d case(s) failed" % ("FAIL" if failures else "OK", failures))
    return 1 if failures else 0


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    if "--print-pins" in sys.argv:
        sys.exit(print_pins(root))
    if "--assert" in sys.argv:
        sys.exit(assert_live(root))
    sys.exit(self_test())
