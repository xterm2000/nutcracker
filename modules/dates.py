"""Dates & birthdays: bare years, DDMMYYYY / MMDDYYYY / YYYYMMDD and short
forms with and without separators, month-name+year, season+year. If a --dob
hint is given, that exact date is expanded first and exhaustively."""

from __future__ import annotations

import calendar

from core.context import CURRENT_YEAR

MONTHS = [
    "january", "february", "march", "april", "may", "june", "july",
    "august", "september", "october", "november", "december",
]
MONTHS_ABBR = [m[:3] for m in MONTHS]
SEASONS = ["spring", "summer", "autumn", "fall", "winter"]
YEAR_MIN, YEAR_MAX = 1940, CURRENT_YEAR + 2


def _date_forms(d: int, m: int, y: int):
    dd, mm = f"{d:02d}", f"{m:02d}"
    yyyy, yy = str(y), str(y)[2:]
    yield from (
        dd + mm + yyyy, mm + dd + yyyy, yyyy + mm + dd,
        dd + mm + yy, mm + dd + yy, yy + mm + dd,
        f"{d}{m}{yyyy}", f"{d}-{m}-{yyyy}", dd + mm, mm + dd,
    )
    for sep in ("-", "/", "."):
        yield f"{dd}{sep}{mm}{sep}{yyyy}"
        yield f"{mm}{sep}{dd}{sep}{yyyy}"
        yield f"{yyyy}{sep}{mm}{sep}{dd}"


class DateModule:
    name = "dates"
    order = 15

    def generate(self, ctx):
        seen: set[str] = set()

        def emit(v):
            if v and v not in seen:
                seen.add(v)
                return True
            return False

        dob = ctx.hints.dob_parts()
        if dob:
            d, m, y = dob
            for yr in range(y - 2, y + 3):
                for form in _date_forms(d, m, yr):
                    if emit(form):
                        yield form
            for suf in (str(y), str(y)[2:], f"{d:02d}{m:02d}"):
                yield suf

        for y in range(YEAR_MIN, YEAR_MAX + 1):
            if emit(str(y)):
                yield str(y)

        for y in range(YEAR_MIN, YEAR_MAX + 1):
            for m in range(1, 13):
                for d in range(1, calendar.monthrange(y, m)[1] + 1):
                    for form in _date_forms(d, m, y):
                        if emit(form):
                            yield form

        for y in range(YEAR_MIN, YEAR_MAX + 1):
            for name in MONTHS + MONTHS_ABBR + SEASONS:
                for v in (name + str(y), name.capitalize() + str(y),
                          name + str(y)[2:], name.capitalize() + str(y)[2:]):
                    if emit(v):
                        yield v
