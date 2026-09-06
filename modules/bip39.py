"""BIP-39 mnemonic attack: the target read as a sequence of words from the
2048-word BIP-39 English list ('abandon ... zoo').

Two behaviours, picked by ``ctx.mode``:

* plaintext -- a decomposition check on the *exact* target. If it splits
  cleanly into >= 2 BIP-39 words (whitespace-separated, or run together),
  report it. A real 12/15/18/21/24-word seed phrase lands here and the guess
  estimate (2048 ** words) correctly marks it unbreakable; a short "clever"
  2-4 word BIP-39 passphrase lands here too and is marked weak.

* hash -- breadth-first k-word chains (k = 2..4) from the 2048 words with a
  small separator set, budget-capped, exactly as a preimage search would.

The word list is ``data/bip39.txt`` (one word per line). A missing file just
makes the module inactive (yields nothing).
"""

from __future__ import annotations

import os

_SEPS = [" ", "", "-", "_", "."]         # decompose: glue accepted between words
_GEN_SEPS = [" ", "", "-"]               # hash mode: glue we put between words
_MNEMONIC_LENGTHS = frozenset({12, 15, 18, 21, 24})
_MAX_K = 4                               # hash mode: longest chain generated
_MAX_PARTS = 24                          # decompose: never more than a full seed
_MIN_WORD = 3                            # shortest BIP-39 word ('act', 'zoo')
_MAX_WORD = 8                            # longest BIP-39 word ('abandon' is 7)


class Bip39Module:
    name = "bip39"
    # plaintext: a near-free decomposition -- keep it ahead of `wordchain` (also
    # order 7, appended after) so an all-BIP-39 phrase is attributed here, with
    # the right 2048**k keyspace. hash mode: `build()` bumps it past
    # dictionary/rules so its 2048**k blow-up doesn't starve them of budget.
    order = 7

    def __init__(self):
        self._words: frozenset[str] | None = None
        self._ordered: list[str] = []
        self._decomp: tuple[str, list[str] | None] | None = None
        self.budget = 8_000_000

    # -- word list -----------------------------------------------------
    def _load(self, ctx) -> frozenset[str]:
        if self._words is None:
            path = os.path.join(ctx.data_dir, "bip39.txt")
            try:
                with open(path, encoding="utf-8") as fh:
                    raw = [w.strip().lower() for w in fh if w.strip()]
            except OSError:
                raw = []
            seen: set[str] = set()
            self._ordered = [w for w in raw if not (w in seen or seen.add(w))]
            self._words = frozenset(self._ordered)
        return self._words

    # -- plaintext decomposition ------------------------------------
    def _split(self, target: str, words: frozenset[str]) -> list[str] | None:
        # whitespace form: the user typed the word boundaries
        if any(c.isspace() for c in target):
            toks = target.lower().split()
            if 2 <= len(toks) <= _MAX_PARTS and all(t in words for t in toks):
                return toks
            return None

        # run-together form: fewest-parts word-break against the 2048 words
        t = target.lower()
        n = len(t)
        memo: dict[int, list[str] | None] = {}

        def solve(i: int) -> list[str] | None:
            if i == n:
                return []
            if i in memo:
                return memo[i]
            best: list[str] | None = None
            for j in range(min(n, i + _MAX_WORD), i + _MIN_WORD - 1, -1):
                piece = t[i:j]
                if piece not in words:
                    continue
                for sep in _SEPS:
                    k = j + len(sep)
                    if sep and t[j:k] != sep:
                        continue
                    rest = solve(k)
                    if rest is not None:
                        cand = [piece] + rest
                        if best is None or len(cand) < len(best):
                            best = cand
            memo[i] = best
            return best

        parts = solve(0)
        if parts and 2 <= len(parts) <= _MAX_PARTS:
            return parts
        return None

    def _resolve(self, ctx) -> list[str] | None:
        target = ctx.plaintext_target or ""
        if self._decomp is None or self._decomp[0] != target:
            words = self._load(ctx)
            parts = self._split(target, words) if (target and words) else None
            # a run-together target that is itself an ordinary listed word
            # ('password' -> 'pass word', 'sunshine' -> 'sun shine') is a
            # single-word password -- leave it to dictionary / rules
            if parts and not any(c.isspace() for c in target):
                if ctx.wordlists.position(target.lower()) is not None:
                    parts = None
            self._decomp = (target, parts)
        return self._decomp[1]

    def estimate_guesses(self, ctx, found=None):
        parts = self._resolve(ctx)
        if not parts or len(parts) < 2:
            return None
        k = len(parts)
        # an attacker who knows it's BIP-39 words: 2048 choices per slot times
        # the plausible separator set
        guesses = 2048 ** k * len(_SEPS)
        tag = ("valid seed-phrase length" if k in _MNEMONIC_LENGTHS
               else "short BIP-39 passphrase")
        return guesses, f"2048^{k} x {len(_SEPS)} separators  ({tag})"

    def note(self, ctx):
        if ctx.mode == "plaintext":
            parts = self._resolve(ctx)
            if parts:
                return f"target is {len(parts)} BIP-39 words: {' '.join(parts)}"
            return None
        words = self._load(ctx)
        if not words:
            return "data/bip39.txt not found -- module inactive"
        return (f"k=2..{_MAX_K} chains from the {len(words):,} BIP-39 words "
                f"({len(words) ** 2:,} pairs, deeper chains budget-capped)")

    # -- hash-mode generation --------------------------------------
    def _chains_of_k(self, ordered, k: int, seps):
        def rec(prefix: str, depth: int):
            if depth == k:
                yield prefix
                return
            if depth == 0:
                for w in ordered:
                    yield from rec(w, 1)
            else:
                for w in ordered:
                    for g in seps:
                        yield from rec(prefix + g + w, depth + 1)

        yield from rec("", 0)

    def generate(self, ctx):
        words = self._load(ctx)
        if not words:
            return
        if ctx.mode == "plaintext":
            if self._resolve(ctx):
                yield ctx.plaintext_target
            return
        ordered = self._ordered
        # k = 2 first (cheapest, highest value), full separator set
        for a in ordered:
            for b in ordered:
                for g in _GEN_SEPS:
                    yield a + g + b
        # deeper chains: plain / space only, budget caps the blow-up
        for k in range(3, _MAX_K + 1):
            yield from self._chains_of_k(ordered, k, [" ", ""])
