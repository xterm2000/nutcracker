"""Numeric PINs: real-frequency 4-digit order first, then date-shaped
(DDMM / MMDD / MMYY / years), then the rest of the 4-digit space. Curated
6-digit PINs always; full 6-digit sweep only with --pin6."""

from __future__ import annotations

# Roughly frequency-ordered (Berry / DataGenetics style).
COMMON_4 = [
    "1234", "1111", "0000", "1212", "7777", "1004", "2000", "4444", "2222",
    "6969", "9999", "3333", "5555", "6666", "1122", "1313", "8888", "4321",
    "2001", "1010", "1478", "2580", "1004", "1979", "2468", "1985", "1986",
    "1987", "1990", "1991", "1989", "1984", "1980", "1994", "1900",
]
COMMON_6 = [
    "123456", "654321", "111111", "000000", "123123", "666666", "121212",
    "112233", "789456", "159753", "147258", "999999", "555555",
    "101010", "202020", "696969", "777777", "123321", "456789",
]


class PinModule:
    name = "pins"
    order = 8

    def __init__(self, six_digit: bool = False):
        self.six_digit = six_digit

    def generate(self, ctx):
        seen: set[str] = set()

        def emit(v):
            if v.isdigit() and v not in seen:
                seen.add(v)
                return True
            return False

        for p in COMMON_4:
            if emit(p):
                yield p

        # date-shaped 4-digit: DDMM and MMDD
        for a in range(1, 32):
            for b in range(1, 13):
                for p in (f"{a:02d}{b:02d}", f"{b:02d}{a:02d}"):
                    if emit(p):
                        yield p
        # years as PINs
        for y in range(1930, 2031):
            if emit(str(y)):
                yield str(y)

        # remainder of the 4-digit space
        for n in range(10000):
            p = f"{n:04d}"
            if emit(p):
                yield p

        for p in COMMON_6:
            if len(p) == 6 and emit(p):
                yield p
        # DDMMYY
        for y in range(0, 100):
            for m in range(1, 13):
                for d in range(1, 32):
                    p = f"{d:02d}{m:02d}{y:02d}"
                    if emit(p):
                        yield p
        if self.six_digit or ctx.limits.pin_six_digit:
            for n in range(1000000):
                p = f"{n:06d}"
                if emit(p):
                    yield p
