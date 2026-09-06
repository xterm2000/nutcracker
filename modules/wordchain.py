"""Word-chain attack: several dictionary words run together, with any
separator or none at all -- 'hellothisisme', 'hello this is me',
'Correct.Horse.Battery', 'red_dog_house'.

Supersedes the old `combinator` (exactly two words) and `passphrase`
(whitespace-separated only) modules.

Two behaviours, picked by `ctx.mode`:

* plaintext -- a word-break search over the *exact* target. This is not a
  blind guess: it takes the known string and asks whether a realistic
  attack (a passphrase cracker, or a multi-word combinator) would land on
  it. Because a 200k-word list can tile almost *any* alphanumeric string
  out of rare 2-3 char fragments, the acceptance test is deliberately
  strict -- see `decompose`.

* hash -- breadth-first generation of k-word chains (k = 2..chain_words)
  from the top-N vocabulary with a small separator set, capped by the
  per-module budget, exactly as a real preimage search would try them.
"""

from __future__ import annotations

from core.context import CURRENT_YEAR
from modules.rules import leet_variants

# glue tried between words when *generating* (hash mode) -- passphrase
# separators ('', ' ') first so 'let me in' is reached before the combinator-
# style digit/symbol glues eat the budget
GLUE = ["", " ", ".", "_", "-", "1", "123", "!", "@", str(CURRENT_YEAR)]
# glue accepted between words when *decomposing* a known plaintext
SPLIT_SEP = ["", " ", ".", "_", "-", "+"]

_MAX_CHUNK = 20   # longest single word we'll try to peel off a plaintext target
_MAX_PARTS = 10   # give up past this many segments
_COMMON_CUTOFF = 25_000   # "ordinary English word" rank threshold (wiki list)

# short words common enough that a mashup attack really would include them,
# so they don't disqualify an otherwise-clean run-together split
_SHORT_OK = {
    # 2-letter
    "am", "an", "as", "at", "be", "by", "do", "go", "he", "hi", "if", "in",
    "is", "it", "me", "my", "no", "of", "oh", "ok", "on", "or", "so", "to",
    "up", "us", "we",
    # 3-letter connectives / ultra-common
    "the", "and", "you", "are", "for", "not", "but", "her", "his", "our",
    "out", "can", "had", "has", "him", "how", "its", "let", "new", "now",
    "old", "one", "see", "she", "too", "two", "use", "was", "way", "who",
    "why", "yes", "all", "any", "did", "get", "got", "may", "off", "own",
    "per", "put", "say", "she", "than", "that", "them",
}


def _norm(s: str) -> str:
    return s.lower()


def _digits_ok(tok: str, *, at_end: bool) -> bool:
    """A numeric segment: only a short run, and only trailing."""
    return tok.isdigit() and len(tok) <= 4 and at_end


# --- lenient path: the target has whitespace, so the user typed the word
#     boundaries themselves -- accept any dictionary-derived token ----------
def _passphrase_split(target: str, wordset: set[str]) -> list[str] | None:
    toks = target.split()
    if len(toks) < 2:
        return None
    out: list[str] = []
    for raw in toks:
        t = _norm(raw)
        core = t.strip("!@#$%^&*()_+-=[]{};:'\",.<>/?`~")
        if core in wordset:
            out.append(core)
            continue
        stem = core.rstrip("0123456789")
        if stem and stem in wordset:
            out.append(stem)
            continue
        if core.isdigit() and len(core) <= 4:
            out.append(core)
            continue
        if len(core) == 1 and core in "ai":
            out.append(core)
            continue
        matched = next((v for v in leet_variants(core)
                        if v != core and v in wordset), None)
        if matched:
            out.append(matched)
            continue
        return None
    return out


# --- strict path: no whitespace in the target, so we must prove it tiles
#     cleanly into *real* words -- rare cruft and stray digits disqualify --
def _strong_word(chunk: str, wordset: set[str], bundle) -> str | None:
    c = _norm(chunk)
    if not c.isalpha():
        return None
    n = len(c)
    if n >= 5:
        return c if c in wordset else None
    if n == 4:
        if c in wordset:
            return c
        return next((v for v in leet_variants(c)
                     if len(v) == 4 and v in wordset), None)
    if n == 3:
        if c in _SHORT_OK:
            return c
        return c if (c in wordset and bundle.is_common(c, _COMMON_CUTOFF)) else None
    if n == 2:
        return c if c in _SHORT_OK else None
    return None


def _best_segmentation(target: str, wordset: set[str], bundle) -> list[str] | None:
    """Fewest-parts segmentation of `target` into strong words + at most one
    short trailing number, or None."""
    n = len(target)
    memo: dict[int, list[str] | None] = {}

    def solve(i: int, depth: int) -> list[str] | None:
        if i == n:
            return []
        if depth >= _MAX_PARTS or i in memo:
            return memo.get(i)
        best: list[str] | None = None
        # a "chain" is >= 2 words: never let the first piece span the whole
        # target (that's a single-word password -- the dictionary's job)
        hi = min(n, i + _MAX_CHUNK)
        if i == 0 and hi == n:
            hi = n - 1
        for j in range(hi, i + 1, -1):
            piece = target[i:j]
            w: str | None = None
            if piece.isdigit():
                if _digits_ok(piece, at_end=(j == n)):
                    w = piece
            else:
                w = _strong_word(piece, wordset, bundle)
            if w is None:
                continue
            for sep in SPLIT_SEP:
                k = j + len(sep)
                if sep and target[j:k] != sep:
                    continue
                rest = solve(k, depth + 1)
                if rest is not None:
                    cand = [w] + rest
                    if best is None or len(cand) < len(best):
                        best = cand
        memo[i] = best
        return best

    return solve(0, 0)


def _gate(parts: list[str], target: str) -> bool:
    if len(parts) < 2:
        return False
    if len(parts) > max(2, len(target) // 3 + 1):
        return False
    nums = [p for p in parts if p.isdigit()]
    if len(nums) > 1:
        return False
    if nums and parts[-1] != nums[0]:      # number must be last
        return False
    alpha = [p for p in parts if p.isalpha()]
    if len(alpha) < 2:
        return False
    alpha_len = sum(len(p) for p in alpha)
    strong_len = sum(len(p) for p in alpha if len(p) >= 4)
    return strong_len >= 0.5 * alpha_len


def decompose(target: str, ctx_words, extra: list[str] | None = None) -> list[str] | None:
    """Return a word split of `target` that a realistic attack would reach,
    or None. Whitespace targets go through the lenient passphrase path; all
    others must clear the strict `_gate`."""
    if not target:
        return None
    bundle = ctx_words
    real_words = {w.lower() for w in bundle if len(w) >= 2}
    wordset = real_words | {w.lower() for w in (extra or []) if len(w) >= 2}
    if any(c.isspace() for c in target):
        return _passphrase_split(target, wordset)
    # a target that is itself a listed word is a single-word password --
    # let `dictionary` / `rules` report it, don't re-tile it here
    if target.lower() in real_words:
        return None
    parts = _best_segmentation(target, wordset, bundle)
    if parts and _gate(parts, target):
        return parts
    return None


class WordChainModule:
    name = "wordchain"
    # plaintext mode: near-instant decomposition of the exact target -- keep it
    # early (rank ~1, it's the audit verdict). hash mode: a huge k-word-chain
    # keyspace with low relative yield -- `build()` bumps `order` to 26 so it
    # runs after `dictionary`/`rules` instead of starving them of budget.
    order = 7

    def __init__(self, chain_words: int = 3, vocab: int = 800):
        self.chain_words = max(2, chain_words)
        self.vocab = vocab
        self._decomp: tuple[str, list[str] | None] | None = None

    # -- plaintext decomposition -----------------------------------------
    def _resolve(self, ctx) -> list[str] | None:
        target = ctx.plaintext_target or ""
        if self._decomp is None or self._decomp[0] != target:
            parts = decompose(target, ctx.wordlists, ctx.hints.tokens()) if target else None
            self._decomp = (target, parts)
        return self._decomp[1]

    def estimate_guesses(self, ctx, found=None):
        """Plaintext mode only: the decomposition yields a single candidate, so
        `rank` would say ~1. Estimate what a real multi-word attack would spend
        reaching this exact phrase instead: the product of each segment's
        position in the wordlist (a word deep in the list costs that many
        guesses to reach) times the separator choices. Returns
        (guesses, explanation) or None."""
        parts = self._resolve(ctx)
        if not parts or len(parts) < 2:
            return None
        bundle = ctx.wordlists
        hint_low = {t.lower() for t in ctx.hints.tokens()}
        product = 1
        bits: list[str] = []
        for p in parts:
            lp = p.lower()
            pos = bundle.position(lp)
            if pos is None:
                # only reachable because a --word/--name hint put it in scope;
                # a blind attacker pays a deep targeted-wordlist penalty
                pos = 50_000 if lp in hint_low else 200_000
                bits.append(f"{p}~{pos:,}({'hint' if lp in hint_low else 'rare'})")
            else:
                bits.append(f"{p}~{pos:,}")
            product *= max(pos, 1)
        seps = len(SPLIT_SEP)
        total = product * seps
        return total, " x ".join(bits) + f" x {seps} separators"

    def note(self, ctx):
        if ctx.mode != "plaintext":
            v = self.vocab or ctx.limits.chain_vocab
            return (f"k=2..{self.chain_words} chains from the top {v:,} English words "
                    f"(~{v * v:,} pairs, deeper chains budget-capped)")
        parts = self._resolve(ctx)
        if parts and len(parts) >= 2:
            return f"decomposes into {len(parts)} dictionary words: {' + '.join(parts)}"
        return None

    # -- hash-mode generation ------------------------------------------
    def _chains_of_k(self, top, k: int, seps):
        def rec(prefix: str, depth: int):
            if depth == k:
                yield prefix
                return
            if depth == 0:
                for w in top:
                    yield from rec(w, 1)
            else:
                for w in top:
                    for g in seps:
                        yield from rec(prefix + g + w, depth + 1)

        yield from rec("", 0)

    def _generate_hash(self, ctx):
        # frequency-ordered, not load-order: passphrases are built from ordinary
        # English words ('this is my gun'), which sit deep in the merged list
        top = ctx.wordlists.common_words(self.vocab or ctx.limits.chain_vocab)
        # k = 2 first (cheapest, highest value), full glue set + capitalised join
        for a in top:
            ca = a.capitalize()
            for b in top:
                for g in GLUE:
                    yield a + g + b
                yield ca + b.capitalize()
        # deeper chains: plain / space / dot only, budget caps the blow-up
        for k in range(3, self.chain_words + 1):
            yield from self._chains_of_k(top, k, ["", " ", "."])

    # -- entry point --------------------------------------------------
    def generate(self, ctx):
        if ctx.mode != "plaintext":
            yield from self._generate_hash(ctx)
            return
        parts = self._resolve(ctx)
        if parts and len(parts) >= 2:
            yield ctx.plaintext_target
