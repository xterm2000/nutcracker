"""Hashcat-compatible rule engine (a practical subset).

A rule file is one rule per line; a rule is a whitespace-separated list of
function tokens applied left-to-right to a word, producing one candidate.
Full-line ``#`` comments and blank lines are ignored (hashcat treats ``#`` as
a literal, so inline comments are *not* supported -- keep them on their own
line).

Supported functions
    :               do nothing
    l u c C t       lower / upper / Capitalize / lower-first-upper-rest / toggle-all
    TN              toggle case of the char at position N
    r d f           reverse / duplicate / reflect (append reversed)
    { }             rotate left / rotate right
    [ ]             delete first / delete last char
    DN              delete the char at position N
    'N              truncate to N chars
    pN              duplicate the whole word N extra times
    zN ZN           duplicate the first / last char N times
    $X ^X           append / prepend the literal char X
    @X              purge every occurrence of X
    sXY             replace every X with Y
    iNX oNX         insert / overwrite char X at position N
    xNM             keep M chars starting at position N
    k K             swap first two / last two chars

Positions use the hashcat alphabet: ``0``-``9`` then ``A``-``Z`` (10-35).
Unknown / unsupported tokens (reject rules, memory rules, ...) are skipped so
a real-world rule file still loads -- the affected rule just does less.
"""

from __future__ import annotations

_ARG2 = set("sxOio")            # two argument chars
_ARG1 = set("TDpzZ'$^@LR")      # one argument char (position or literal)


def _pos(c: str) -> int:
    if not c:
        return 0
    if c.isdigit():
        return int(c)
    return 10 + (ord(c.upper()) - ord("A"))


def tokenize(line: str) -> list[tuple[str, str]]:
    """Split one rule line into (function, args) tokens."""
    toks: list[tuple[str, str]] = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch.isspace():
            i += 1
            continue
        if ch in _ARG2:
            toks.append((ch, line[i + 1:i + 3]))
            i += 3
        elif ch in _ARG1:
            toks.append((ch, line[i + 1:i + 2]))
            i += 2
        else:
            toks.append((ch, ""))
            i += 1
    return toks


def apply(word: str, toks: list[tuple[str, str]]) -> str:
    """Run a tokenized rule against `word`. Never raises -- a broken step is a no-op."""
    w = word
    for ch, arg in toks:
        try:
            if ch == ":":
                pass
            elif ch == "l":
                w = w.lower()
            elif ch == "u":
                w = w.upper()
            elif ch == "c":
                w = w.capitalize()
            elif ch == "C":
                w = w[:1].lower() + w[1:].upper()
            elif ch == "t":
                w = w.swapcase()
            elif ch == "T":
                p = _pos(arg)
                if p < len(w):
                    w = w[:p] + w[p].swapcase() + w[p + 1:]
            elif ch == "r":
                w = w[::-1]
            elif ch == "d":
                w = w + w
            elif ch == "p":
                w = w * (_pos(arg) + 1)
            elif ch == "f":
                w = w + w[::-1]
            elif ch == "{":
                w = w[1:] + w[:1]
            elif ch == "}":
                w = w[-1:] + w[:-1]
            elif ch == "[":
                w = w[1:]
            elif ch == "]":
                w = w[:-1]
            elif ch == "D":
                p = _pos(arg)
                if p < len(w):
                    w = w[:p] + w[p + 1:]
            elif ch == "'":
                w = w[:_pos(arg)]
            elif ch == "z":
                w = w[:1] * _pos(arg) + w
            elif ch == "Z":
                w = w + w[-1:] * _pos(arg)
            elif ch == "$":
                w = w + arg
            elif ch == "^":
                w = arg + w
            elif ch == "@":
                w = w.replace(arg, "")
            elif ch == "s":
                if len(arg) == 2:
                    w = w.replace(arg[0], arg[1])
            elif ch == "i":
                if len(arg) == 2:
                    p = min(_pos(arg[0]), len(w))
                    w = w[:p] + arg[1] + w[p:]
            elif ch == "o":
                if len(arg) == 2:
                    p = _pos(arg[0])
                    if p < len(w):
                        w = w[:p] + arg[1] + w[p + 1:]
            elif ch == "x":
                if len(arg) == 2:
                    a, b = _pos(arg[0]), _pos(arg[1])
                    w = w[a:a + b]
            elif ch == "k":
                if len(w) >= 2:
                    w = w[1] + w[0] + w[2:]
            elif ch == "K":
                if len(w) >= 2:
                    w = w[:-2] + w[-1] + w[-2]
            # anything else: unsupported, skip silently
        except Exception:
            continue
    return w


class RuleSet:
    def __init__(self, rules: list[list[tuple[str, str]]], source: str = "<rules>"):
        self.rules = rules
        self.source = source

    def __len__(self) -> int:
        return len(self.rules)

    def apply_all(self, word: str):
        """Yield each rule's output for `word`, de-duplicated within the word."""
        seen: set[str] = set()
        for toks in self.rules:
            out = apply(word, toks)
            if out and out not in seen:
                seen.add(out)
                yield out


def load(path: str) -> RuleSet:
    rules: list[list[tuple[str, str]]] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.rstrip("\n").rstrip("\r")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            toks = tokenize(line)
            if toks:
                rules.append(toks)
    return RuleSet(rules, source=path)
