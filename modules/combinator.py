"""Combinator: join two dictionary words (optionally with a separator or a
short numeric/symbol glue). Keyspace is roughly N**2 * len(GLUE) where N is
limits.combinator_words -- rely on the per-module budget to cap it."""

from __future__ import annotations

from core.context import CURRENT_YEAR

GLUE = ["", ".", "_", "-", "1", "123", "!", "@", str(CURRENT_YEAR)]


class CombinatorModule:
    name = "combinator"
    order = 30

    def __init__(self, words: int = 800):
        self.words = words

    def generate(self, ctx):
        top = ctx.wordlists.top(self.words or ctx.limits.combinator_words)
        for a in top:
            ca = a.capitalize()
            for b in top:
                for g in GLUE:
                    yield a + g + b
                yield ca + b.capitalize()
