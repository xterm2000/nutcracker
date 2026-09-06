"""Permute attack: the known hint tokens (--word / --name / --user / --email)
tried in *every order*, glued with each separator, in a few case forms --
optionally with N unknown slots filled from the most common English words.

The gap this fills: you remember most of a passphrase but not the word order
(or you are missing a word or two). `context` only glues *pairs*; `wordchain`
hash mode ignores the hint tokens entirely. This module anchors on exactly
the words you supply.

Opt-in via ``--permute``. Keyspace = perm(t + fill) x separators x cases x
vocab**fill -- ``--permute-fill`` > 0 multiplies hard, so it caps the filler
vocab low and bumps the module budget.

  --word this --word my --word rifle --word gun --permute
      -> 'this my rifle gun', 'my this gun rifle', 'this-my-rifle-gun', ...
  ... --permute --permute-fill 1
      -> also '<common-word> this my rifle gun', 'this my <common-word> ...', ...
"""

from __future__ import annotations

from itertools import permutations, product
from math import factorial

from core import estimate

_DEFAULT_SEPS = ["", " ", "-", "_", "."]
_MAX_TOKENS = 8   # 8! = 40,320 orderings; refuse to factorial-explode past this
_CASE_MULT = {"none": 1, "title": 2, "all": 4}


class PermuteModule:
    name = "permute"
    order = 12
    plaintext_only = False

    def __init__(self, seps=None, fill: int = 0, vocab: int = 200,
                 cases: str = "title"):
        chosen = seps if seps is not None else _DEFAULT_SEPS
        self.seps = list(dict.fromkeys(chosen))
        self.fill = max(0, min(int(fill), 2))
        self.vocab = vocab
        self.cases = cases if cases in _CASE_MULT else "title"
        if self.fill >= 1:
            self.budget = 25_000_000

    # -- helpers -------------------------------------------------------
    def _tokens(self, ctx) -> list[str]:
        return [t for t in ctx.hints.tokens() if t][:_MAX_TOKENS]

    def _fillers(self, ctx) -> list[str]:
        if self.fill <= 0:
            return []
        return list(ctx.wordlists.common_words(self.vocab))

    def _case_forms(self, parts):
        yield parts
        if self.cases in ("title", "all"):
            yield [p.capitalize() for p in parts]
        if self.cases == "all":
            yield [p.upper() for p in parts]
            yield [p.lower() for p in parts]

    def _estimate(self, ctx) -> int:
        t = len(self._tokens(ctx))
        if t < 2:
            return 0
        perms = factorial(min(t + self.fill, _MAX_TOKENS))
        v = max(1, len(self._fillers(ctx))) ** self.fill if self.fill else 1
        return perms * len(self.seps) * _CASE_MULT[self.cases] * v

    def note(self, ctx):
        t = len(self._tokens(ctx))
        if t < 2:
            return None
        extra = (f" + {self.fill} slot(s) from top {self.vocab}"
                 if self.fill else "")
        return (f"~{self._estimate(ctx):,} candidates "
                f"({t} known tokens{extra}, {len(self.seps)} separators) -- "
                f"{estimate.exhaust_note(self._estimate(ctx), ctx)}")

    # -- generation --------------------------------------------------
    def generate(self, ctx):
        toks = self._tokens(ctx)
        if len(toks) < 2:
            return
        seen: set[str] = set()

        def emit(parts):
            for form in self._case_forms(parts):
                for sep in self.seps:
                    s = sep.join(form)
                    if s and s not in seen:
                        seen.add(s)
                        yield s

        if self.fill <= 0:
            for perm in permutations(toks):
                yield from emit(list(perm))
            return

        # filler-major: common_words() is frequency-ordered, so the likeliest
        # missing words are swept against every arrangement first
        for fills in product(self._fillers(ctx), repeat=self.fill):
            for perm in permutations(toks + list(fills)):
                yield from emit(list(perm))
