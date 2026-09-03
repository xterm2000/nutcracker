"""Phone numbers:
  * note()     -- regex-flag a phone-shaped plaintext target (advisory)
  * generate() -- for every number in data/phone_numbers.txt (and the target
                  itself, if phone-shaped), emit the common written formats
                  with and without +, spaces, dashes and parentheses.
"""

from __future__ import annotations

import os
import re

_SHAPE = re.compile(r"^\+?[\d\s().\-]{7,20}$")
_TEMPLATES = [
    "+{c} ({a}) {p}-{l}", "+{c} ({a})-{p}-{l}", "+{c}{a}{p}{l}",
    "+{c} {a} {p} {l}", "+{c}-{a}-{p}-{l}", "{c}-{a}-{p}-{l}",
    "{c} ({a}) {p}-{l}", "{c}{a}{p}{l}", "({a}) {p}-{l}", "({a}){p}-{l}",
    "{a}-{p}-{l}", "{a}.{p}.{l}", "{a} {p} {l}", "{a}{p}{l}",
    "{p}-{l}", "{p}{l}",
]


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def looks_like_phone(s: str) -> bool:
    s = s.strip()
    d = _digits(s)
    return (
        10 <= len(d) <= 15
        and bool(_SHAPE.match(s))
        and (s.startswith("+") or any(ch in s for ch in "()-. "))
    )


def _split(d: str):
    if len(d) == 10:
        return "", d[:3], d[3:6], d[6:]
    if len(d) == 11:
        return d[:1], d[1:4], d[4:7], d[7:]
    if len(d) == 12:
        return d[:2], d[2:5], d[5:8], d[8:]
    if len(d) == 13:
        return d[:3], d[3:6], d[6:9], d[9:]
    if len(d) == 7:
        return "", "", d[:3], d[3:]
    return None


def variants(d: str):
    d = _digits(d)
    parts = _split(d)
    seen = set()
    if d and d not in seen:
        seen.add(d)
        yield d
    if not parts:
        return
    c, a, p, l = parts
    for t in _TEMPLATES:
        if not c and "{c}" in t:
            continue
        if not a and "{a}" in t:
            continue
        v = t.format(c=c, a=a, p=p, l=l).replace("+ ", "+").strip()
        if v and v not in seen:
            seen.add(v)
            yield v


class PhoneModule:
    name = "phone"
    order = 6

    def note(self, ctx):
        t = ctx.plaintext_target
        if t and looks_like_phone(t):
            d = _digits(t)
            return f"FLAGGED: looks like a phone number ({len(d)} digits: {d})"
        return None

    def generate(self, ctx):
        numbers: list[str] = []
        path = os.path.join(ctx.data_dir, "phone_numbers.txt")
        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    d = _digits(line)
                    if 7 <= len(d) <= 15:
                        numbers.append(d)
        if ctx.plaintext_target:
            d = _digits(ctx.plaintext_target)
            if 7 <= len(d) <= 15:
                numbers.append(d)

        seen: set[str] = set()
        for num in numbers:
            for v in variants(num):
                if v not in seen:
                    seen.add(v)
                    yield v
