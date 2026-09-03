"""Rule-based mangling of dictionary words (breadth-first, so a budget
cutoff still covers every word at shallow depth)."""

from __future__ import annotations

from core.context import CURRENT_YEAR

LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
SUFFIXES = ["1", "12", "123", "1234", "!", "!!", "12345", "007", "69", "01", "00"]
# recent years first -- they are far more common and we want them cheap
YEARS = [str(y) for y in range(CURRENT_YEAR + 2, 1949, -1)]
PREFIXES = ["1", "123", "!"]


def leet_variants(word: str) -> list[str]:
    out = {word, "".join(LEET_MAP.get(c, c) for c in word)}
    for ch, repl in LEET_MAP.items():
        if ch in word:
            out.add(word.replace(ch, repl))
    return list(out)


def mangle(word: str):
    """Every variant of a single word -- used by dictionary & context modules."""
    seen: set[str] = set()

    def emit(v: str):
        if v and v not in seen:
            seen.add(v)
            return True
        return False

    bases = [word, word.lower(), word.upper(), word.capitalize()]
    for b in bases:
        if emit(b):
            yield b
    for b in bases:
        for suf in SUFFIXES + YEARS:
            if emit(b + suf):
                yield b + suf
        for pre in PREFIXES:
            if emit(pre + b):
                yield pre + b
    for v in leet_variants(word):
        if emit(v):
            yield v
        for suf in ("1", "123", "!", str(CURRENT_YEAR)):
            if emit(v + suf):
                yield v + suf
    for extra in (word[::-1], word + word, word.capitalize() + "1"):
        if emit(extra):
            yield extra


class RulesModule:
    name = "rules"
    order = 20

    def generate(self, ctx):
        words = list(ctx.wordlists)
        for w in words:
            yield w.lower()
        for w in words:
            yield w.capitalize()
            yield w.upper()
        for suf in SUFFIXES:
            for w in words:
                yield w + suf
                yield w.capitalize() + suf
        recent = [str(y) for y in range(CURRENT_YEAR - 2, CURRENT_YEAR + 2)]
        for y in recent:
            for sym in ("", "!", "1", ".", "@", "#"):
                for w in words:
                    yield w + y + sym
                    yield w.capitalize() + y + sym
        for y in YEARS:
            for w in words:
                yield w + y
                yield w.capitalize() + y
        for pre in PREFIXES:
            for w in words:
                yield pre + w
        for w in words:
            for v in leet_variants(w):
                if v != w:
                    yield v
        for suf in ("1", "123", "!", str(CURRENT_YEAR), str(CURRENT_YEAR - 1)):
            for w in words:
                for v in leet_variants(w):
                    if v != w:
                        yield v + suf
        for w in words:
            yield w[::-1]
            yield w + w
