"""Hybrid attack: each top dictionary word glued to a mask-generated string
(hashcat ``-a 6`` / ``-a 7``).

  --hybrid-mask '?d?d?d?d'        word + every 4-digit string  ->  hunter1990
  --hybrid-mask '?d?d' --hybrid-side prepend   ->  99hunter
  --hybrid-side both (default)    tries append and prepend

Keyspace = vocab x mask x sides -- keep the mask small (the module budget
still caps it, but a wide mask starves everything after it).
"""

from __future__ import annotations

import itertools

from core import estimate
from modules.mask import _parse_mask


class HybridModule:
    name = "hybrid"
    order = 30
    plaintext_only = False

    def __init__(self, mask=None, side="both", vocab=2000):
        self.mask = mask
        self.side = side
        self.vocab = vocab

    def _mask_plan(self):
        return _parse_mask(self.mask) if self.mask else []

    def _mask_strings(self):
        plan = self._mask_plan()
        if not plan:
            return
        for combo in itertools.product(*plan):
            yield "".join(combo)

    def keyspace(self) -> int:
        k = 1
        for pos in self._mask_plan():
            k *= max(len(pos), 1)
        sides = 2 if self.side == "both" else 1
        return k * self.vocab * sides

    def note(self, ctx):
        if not self.mask:
            return None
        mask_k = 1
        for pos in self._mask_plan():
            mask_k *= max(len(pos), 1)
        sides = "append+prepend" if self.side == "both" else self.side
        return (f"~{self.keyspace():,} candidates "
                f"(~{self.vocab} words x {mask_k:,} mask x {sides}) -- "
                f"{estimate.exhaust_note(self.keyspace(), ctx)}")

    def generate(self, ctx):
        if not self.mask:
            return
        want_app = self.side in ("both", "append")
        want_pre = self.side in ("both", "prepend")
        masks = list(self._mask_strings())
        # word-major: top words are frequency-ordered, so a budget cut still
        # sweeps the whole mask against the most likely bases.
        for w in ctx.wordlists.top(self.vocab):
            seen_w: set[str] = set()
            for wv in (w, w.capitalize()):
                if wv in seen_w:
                    continue
                seen_w.add(wv)
                for m in masks:
                    if want_app:
                        yield wv + m
                    if want_pre:
                        yield m + wv
