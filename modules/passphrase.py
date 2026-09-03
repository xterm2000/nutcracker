"""Passphrase attack: target is dictionary words separated by whitespace,
e.g. 'mary had a little lamb'. Plaintext mode only -- in hash mode the
combinator module covers multi-word candidates."""

from __future__ import annotations

from modules.rules import leet_variants


def _word_matches(token: str, wordset: set[str]) -> str | None:
    t = token.lower()
    if t in wordset:
        return t
    if t.isdigit() and len(t) <= 4:
        return t
    stripped = t.strip("!@#$%^&*()_+-=[]{};:'\",.<>/?`~")
    if stripped and stripped in wordset:
        return stripped
    core = stripped.rstrip("0123456789")
    if core and core in wordset:
        return core
    for leet in leet_variants(t):
        if leet != t and leet in wordset:
            return leet
    return None


class PassphraseModule:
    name = "passphrase"
    order = 5
    plaintext_only = True

    def __init__(self):
        self._resolved = None

    def note(self, ctx):
        target = ctx.plaintext_target or ""
        if not target.strip() or not any(c.isspace() for c in target):
            return None
        wordset = set(ctx.wordlists)
        wordset |= {t.lower() for t in ctx.hints.tokens()}  # --word extras
        resolved = []
        for tok in target.split():
            w = _word_matches(tok, wordset)
            if w is None:
                return f"not a pure passphrase (token {tok!r} is not dictionary-derived)"
            resolved.append((tok, w))
        self._resolved = resolved
        parts = ", ".join(f"{tok}->{w}" if tok.lower() != w else tok for tok, w in resolved)
        return f"passphrase of {len(resolved)} dictionary words: {parts}"

    def generate(self, ctx):
        if self._resolved is not None:
            yield ctx.plaintext_target
