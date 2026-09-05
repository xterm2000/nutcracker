"""Birthday-derived dates glued onto known bases -- only active with --dob.

The `dates` module already emits *bare* dates in every format. This module
covers the "<word><date>[<word>]" shape, and not just the exact DOB:

  * a birthday window   -- the month either side of the DOB, years y-1..y+1
                           (catches slightly-wrong recollections and close
                           family birthdays)
  * parents / children  -- every day of years y-50..y-18 and y+18..y+50
                           (assuming a parent/child age gap of 18..50)

Each date is rendered through `dates.date_forms`.

How much structure it builds is controlled by `--depth` (default 1):

  depth 1  <hint-token><date>                        e.g. Solomakha16041949
  depth 2  + <relation-word><date>[<hint-token>]     e.g. mama19491604solomakha
  depth 3  + <hint-token><date><hint-token>, and <word><word><date>

Higher depth multiplies the keyspace fast, so it raises its own budget and
is opt-in.
"""

from __future__ import annotations

import calendar

from modules.dates import date_forms

_CHAIN_BASES = 25   # top-N words used pairwise as extra bases at depth 3

# family / relationship words (several languages) that commonly prefix a
# relative's birth date in a password
RELWORDS = [
    "mama", "papa", "mom", "mum", "dad", "mommy", "daddy", "mother", "father",
    "mummy", "baba", "dida", "dido", "tato", "tata", "nana", "nonna", "nonno",
    "oma", "opa", "granny", "grandma", "grandpa", "granddad", "babcia",
    "dziadek", "son", "daughter", "wife", "husband", "love", "family",
]


def _forms_over(years, months_for) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for y in years:
        for m in months_for(y):
            if not 1 <= m <= 12:
                continue
            for d in range(1, calendar.monthrange(y, m)[1] + 1):
                for f in date_forms(d, m, y):
                    if f not in seen:
                        seen.add(f)
                        out.append(f)
    return out


def birthday_window(d: int, m: int, y: int) -> list[str]:
    return _forms_over(range(y - 1, y + 2), lambda _y: (m - 1, m, m + 1))


def generation_dates(d: int, m: int, y: int) -> list[str]:
    # assume a parent/child gap of 18..50 years: parents were born
    # y-50..y-18, kids are born y+18..y+50 -- every day of those years
    parents = _forms_over(range(y - 50, y - 17), lambda _y: range(1, 13))
    children = _forms_over(range(y + 18, y + 51), lambda _y: range(1, 13))
    return parents + children


class DobWordsModule:
    name = "dobwords"
    order = 24              # after `rules` -- expensive, and only fires with --dob

    def __init__(self, depth: int = 1):
        self.depth = max(1, depth)
        self.budget = 6_000_000 if self.depth < 2 else 25_000_000

    def note(self, ctx):
        if ctx.hints.dob_parts() is None:
            return None
        return (f"depth {self.depth}: gluing birthday + parent/child (18..50yr) "
                "dates onto hint tokens" + (" + relation words" if self.depth >= 2 else ""))

    def generate(self, ctx):
        dob = ctx.hints.dob_parts()
        if dob is None:
            return
        d, m, y = dob
        window = birthday_window(d, m, y)
        dates = window + generation_dates(d, m, y)
        tokens = list(ctx.hints.tokens())

        seen: set[str] = set()

        def emit(v: str) -> bool:
            if v and v not in seen:
                seen.add(v)
                return True
            return False

        # depth 1: <hint-token><date>  (window dates first)
        for suf in dates:
            for tok in tokens:
                for base in (tok, tok.capitalize()):
                    if emit(base + suf):
                        yield base + suf

        # depth 2: <relation-word><date>[<hint-token>]
        if self.depth >= 2:
            for mid in dates:
                for rel in RELWORDS:
                    for pre in (rel, rel.capitalize()):
                        if emit(pre + mid):
                            yield pre + mid
                        for tok in tokens:
                            if emit(pre + mid + tok):
                                yield pre + mid + tok

        # depth 3: <hint-token><date><hint-token>, and <word><word><date>
        if self.depth >= 3:
            for mid in dates:
                for a in tokens:
                    for b in tokens:
                        if emit(a + mid + b):
                            yield a + mid + b
            top = ctx.wordlists.top(min(_CHAIN_BASES, len(ctx.wordlists)))
            for suf in window:
                for a in top:
                    for b in top:
                        if emit(a + b + suf):
                            yield a + b + suf
