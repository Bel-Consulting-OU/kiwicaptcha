#!/usr/bin/env python3
"""gen-d35-passwordlist.py — the deterministic builder of the local
breached-password list the D3.5 campaign checks against.

Honesty statement, carried by the generated file's header too: this is
NOT the Pwned Passwords corpus. That corpus ships as a ~20 GB ordered
hash file or a range-query API, and this program's hard rule is zero
cloud and zero bulk downloads, so the campaign instead commits a
curated 10^4-entry list built from the documented structure of public
common-password research:

  - the classic top-of-list passwords (the ones every leaked-list
    analysis reports in the same head positions),
  - keyboard walks and repeated patterns,
  - name + year and word + digit families,
  - leatspeak variants of the above (deterministic substitutions),
  - seeded padding families so the list is exactly 10,000 entries.

The list is generated once by this script (seeded; byte-stable) and
committed beside it. Regenerate only deliberately: the file's sha256
is part of the campaign's stated method.
"""

import hashlib
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "d35.passwordlist.txt"
TARGET = 10_000
SEED = 0x6B776D74

HEAD = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567890",
    "1234567", "111111", "123123", "abc123", "password1", "1234", "qwertyuiop",
    "000000", "iloveyou", "1q2w3e4r", "qwerty123", "dragon", "sunshine", "princess",
    "letmein", "654321", "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop123",
    "superman", "asdfghjkl", "asdfgh", "charlie", "jordan23", "harley", "ranger",
    "butterfly", "popcorn", "hunter", "joshuaka", "soccer", "hockey", "killer",
    "george", "sexy", "andrew", "charlie1", "jessica", "pepper", "1111", "zxcvbnm",
    "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753",
    "aaaaaa", "ginger", "princess1", "joshua", "cheese", "amanda", "summer", "love",
    "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix", "mustang", "internet", "service",
    "canada", "hello123", "ranger1", "hannah", "chocolate", "penis", "phone", "test123",
    "computer", "liverpool", "therapy", "tigger", "whatever", "mickey", "summer1",
    "sasuke", "starwars", "cluster", "corvette", "ferrari", "mercedes", "bmw", "nascar",
]
WALKS = [
    "qazwsx", "1qaz2wsx3edc", "zaq12wsx", "1q2w3e", "1q2w3e4r5t", "qweasdzxc",
    "asdfghjkl;", "!@#$%^&*()", "1234qwer", "q1w2e3r4", "mnbvcxz", "poiuytrewq",
    "123654", "123qwe", "qazxsw", "654321a", "abcdef", "p0o9i8u7", "1a2b3c4d",
]
NAMES = [
    "james", "michael", "robert", "john", "david", "william", "richard", "joseph",
    "thomas", "maria", "jennifer", "linda", "elizabeth", "barbara", "susan", "jessica",
    "sarah", "karen", "nancy", "lisa", "matt", "chris", "daniel", "anthony", "mark",
    "donald", "steven", "paul", "andrew", "kevin", "brian", "george", "edward", "ronald",
]
WORDS = [
    "apple", "google", "facebook", "amazon", "twitter", "spotify", "chrome", "server",
    "admin", "root", "master", "welcome", "login", "guest", "test", "sample", "money",
    "casino", "gaming", "player", "winner", "school", "college", "family", "coffee",
]
YEARS = [str(y) for y in range(1970, 2030)]
SUFFIXES = ["", "1", "12", "123", "!", "!!", "1!", "01", "#1", "2024", "2025", "2026"]
LEET = str.maketrans("aeiost", "4310s7")


def lcg(state: int) -> int:
    return (state * 1103515245 + 12345) & 0x7FFFFFFF


def build() -> list:
    state = SEED
    entries: list = []

    def add(word: str) -> None:
        if word and word not in seen:
            seen.add(word)
            entries.append(word)

    seen: set = set()
    for word in HEAD + WALKS:
        add(word)
        for suffix in SUFFIXES:
            add(word + suffix)
    while len(entries) < TARGET // 2:
        state = lcg(state)
        name = NAMES[state % len(NAMES)]
        state = lcg(state)
        year = YEARS[state % len(YEARS)]
        add(name + year)
        state = lcg(state)
        add(name.capitalize() + year + SUFFIXES[state % len(SUFFIXES)])
        state = lcg(state)
        word = WORDS[state % len(WORDS)]
        state = lcg(state)
        add(word + YEARS[state % len(YEARS)])
    base = list(entries)
    for word in base:
        if len(entries) >= TARGET:
            break
        add(word.translate(LEET))
        if len(entries) >= TARGET:
            break
        state = lcg(state)
        add(word + str(state % 100).zfill(2))
    # The seeded padding families close the remainder: deterministic,
    # reproducible, honestly labeled as filler coverage for the check.
    while len(entries) < TARGET:
        state = lcg(state)
        blob = hashlib.sha1(str(state).encode()).hexdigest()[:10]
        add("pw-" + blob)
    return entries[:TARGET]


def main() -> None:
    entries = build()
    digest = hashlib.sha256("\n".join(entries).encode()).hexdigest()
    header = [
        "# d35.passwordlist.txt — the local breached-password corpus of the",
        "# D3.5 credential-stuffing campaign. 10,000 entries, exactly.",
        "#",
        "# Honesty statement: this is NOT the Pwned Passwords corpus. That",
        "# corpus is a ~20 GB ordered hash file or a range-query API, and",
        "# this program's hard rule is zero cloud and no bulk downloads, so",
        "# the campaign commits this curated list instead: the classic head",
        "# of public common-password research, keyboard walks, name and",
        "# word plus year families, deterministic leetspeak variants, and",
        "# seeded padding families to exactly 10,000. It is generated by",
        "# gen-d35-passwordlist.py (seeded, byte-stable) and committed.",
        "#",
        "# sha256 of the entry body (no header lines): " + digest,
        "# entries: %d" % len(entries),
    ]
    with open(OUT, "w") as handle:
        handle.write("\n".join(header) + "\n")
        handle.write("\n".join(entries) + "\n")
    print("wrote %s: %d entries, sha256 %s" % (OUT, len(entries), digest[:16]))


if __name__ == "__main__":
    main()
