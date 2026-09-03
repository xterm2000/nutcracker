"""Straight dictionary attack: every base word, unchanged."""

from __future__ import annotations


class DictionaryModule:
    name = "dictionary"
    order = 10

    def generate(self, ctx):
        yield from ctx.wordlists
