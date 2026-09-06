"""Fuzz attack: dictionary words with up to N single-character *substitutions*
(Hamming distance <= N, length unchanged).

Covers the one gap left by ``rules`` / ``leet_variants`` -- an arbitrary
one-off swap that is not in the leet map (``passward``, ``monkez``,
``drygon``) or a fat-finger typo baked into the password (``passworf``).

Keyspace is ``vocab * L * (A-1)`` for N=1 and explodes for N=2, so it is
opt-in (``--fuzz 1|2``), always **vocab-capped** (top ``--fuzz-vocab`` words
plus the hint tokens), and the substitution alphabet is a small targeted set
rather than full ASCII:

  --fuzz-charset sub   a-z 0-9 ! @ # $ % (default -- deliberate substitutions)
  --fuzz-charset kbd   only keyboard-adjacent keys (fat-finger typos)
  --fuzz-charset l/d/a mask.CHARSETS spec, or any literal string of chars

Variants that are themselves dictionary words are skipped (``dictionary``
already tried them). Breadth-first: every word is fuzzed at position 0
before any is fuzzed at position 1, so a budget cut still covers all words.
"""

from __future__ import annotations

from itertools import combinations

from core import estimate
from modules.mask import CHARSETS

_SUB = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%"
_MIN_LEN = 3
_MAX_LEN = 16


def _build_adjacency() -> dict[str, str]:
    rows = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
    pos = {ch: (r, c) for r, row in enumerate(rows) for c, ch in enumerate(row)}
    adj: dict[str, str] = {}
    for ch, (r, c) in pos.items():
        near = [o for o, (r2, c2) in pos.items()
                if o != ch and abs(r2 - r) <= 1 and abs(c2 - c) <= 1]
        adj[ch] = "".join(near)
    return adj


_ADJ = _build_adjacency()


class FuzzModule:
    name = "fuzz"
    order = 22  # just after rules (20)
    plaintext_only = False

    def __init__(self, n: int = 1, vocab: int = 2000, charset: str = "sub"):
        self.n = max(1, min(int(n), 2))
        self.vocab = vocab
        self.charset = charset
        if self.n >= 2:
            self.budget = 25_000_000  # C(L,2)*(A-1)^2 multiplies fast

    # -- substitution alphabet for a given original character ---------------
    def _repl_for(self, ch: str) -> str:
        if self.charset == "kbd":
            return _ADJ.get(ch.lower(), "")
        if self.charset == "sub":
            pool = _SUB
        elif all(c in CHARSETS for c in self.charset):
            pool = "".join(CHARSETS[c] for c in self.charset)
        else:
            pool = self.charset
        return pool

    def _bases(self, ctx):
        seen: set[str] = set()
        for w in list(ctx.hints.tokens()) + ctx.wordlists.top(self.vocab):
            lw = w.lower()
            if _MIN_LEN <= len(lw) <= _MAX_LEN and lw not in seen:
                seen.add(lw)
                yield lw

    def _estimate(self, ctx) -> int:
        total = 0
        for w in self._bases(ctx):
            per_pos = [len(self._repl_for(c)) for c in w]
            if self.n == 1:
                total += sum(max(k - 1, 0) for k in per_pos)
            else:
                total += sum(max(a - 1, 0) * max(b - 1, 0)
                             for a, b in combinations(per_pos, 2))
        return total

    def note(self, ctx):
        return (f"~{self._estimate(ctx):,} candidates "
                f"(Hamming <={self.n}, top {self.vocab} words + hints, "
                f"charset {self.charset!r}) -- "
                f"{estimate.exhaust_note(self._estimate(ctx), ctx)}")

    def generate(self, ctx):
        wordset = set(ctx.wordlists.words)
        bases = list(self._bases(ctx))
        seen: set[str] = set()

        def emit(v: str):
            if v and v not in seen and v not in wordset:
                seen.add(v)
                return True
            return False

        positions = 1 if self.n == 1 else 2
        # breadth-first over (which positions) then (which words)
        for combo_size in range(1, positions + 1):
            for w in bases:
                idxs = range(len(w))
                for combo in combinations(idxs, combo_size):
                    pools = [self._repl_for(w[i]) for i in combo]
                    if any(not p for p in pools):
                        continue
                    yield from self._spin(w, combo, pools, 0, emit)

    def _spin(self, w, combo, pools, depth, emit):
        if depth == len(combo):
            return
        i = combo[depth]
        orig = w[i]
        for rc in pools[depth]:
            if rc == orig:
                continue
            cand = w[:i] + rc + w[i + 1:]
            if depth + 1 == len(combo):
                if emit(cand):
                    yield cand
            else:
                yield from self._spin(cand, combo, pools, depth + 1, emit)
