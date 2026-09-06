"""Target-based guesses built from --user / --email / --name / --dob hints:
the tokens themselves, run through the standard mangling rules, plus
name-part combinations and date suffixes."""

from __future__ import annotations

from core.context import CURRENT_YEAR
from modules.rules import mangle

YEAR_SUFFIXES = [str(y) for y in range(CURRENT_YEAR - 40, CURRENT_YEAR + 2)]


class ContextModule:
    name = "context"
    order = 3

    def generate(self, ctx):
        tokens = ctx.hints.tokens()
        if not tokens:
            return

        seen: set[str] = set()

        def emit(v):
            if v and v not in seen:
                seen.add(v)
                return True
            return False

        dob = ctx.hints.dob_parts()
        dob_sufs: list[str] = []
        if dob:
            d, m, y = dob
            dob_sufs = [
                str(y), str(y)[2:], f"{d:02d}{m:02d}", f"{m:02d}{d:02d}",
                f"{d:02d}{m:02d}{y}", f"{d}{m}{y}",
            ]

        for tok in tokens:
            for v in mangle(tok):
                if emit(v):
                    yield v
            for suf in dob_sufs + YEAR_SUFFIXES:
                for base in (tok, tok.capitalize(), tok.lower()):
                    if emit(base + suf):
                        yield base + suf

        # pairwise glue of hint tokens, tried in a few case forms so a lower-
        # case run-together like 'jimmybbq' is reached, not just 'Jimmybbq'
        # (first+last / user+year are handled above)
        def _cases(s):
            return list(dict.fromkeys((s, s.lower(), s.capitalize())))

        for i, a in enumerate(tokens):
            for b in tokens[i + 1:]:
                for av in _cases(a):
                    for bv in _cases(b):
                        for g in ("", ".", "_", "-"):
                            if emit(av + g + bv):
                                yield av + g + bv
                            if emit(bv + g + av):
                                yield bv + g + av
