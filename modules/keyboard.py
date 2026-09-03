"""Keyboard walks on a QWERTY layout: row runs, column/diagonal walks, and
the well-known curated set (qwerty, 1qaz2wsx, zaq12wsx, ...)."""

from __future__ import annotations

ROWS = ["1234567890-=", "qwertyuiop[]", "asdfghjkl;'", "zxcvbnm,./"]
COLS = ["1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0p;/"]
CURATED = [
    "qwerty", "qwertyuiop", "qwerty123", "qwerty1", "qwerty12", "qazwsx",
    "qazwsxedc", "qweasd", "qweasdzxc", "asdfgh", "asdfghjkl", "asdf", "asdf1234",
    "zxcvbn", "zxcvbnm", "zxcv", "1qaz2wsx", "1qazxsw2", "1qaz2wsx3edc",
    "zaq12wsx", "zaq1xsw2", "1q2w3e4r", "1q2w3e4r5t", "1q2w3e", "q1w2e3r4",
    "!qaz2wsx", "1qaz@wsx", "poiuytrewq", "mnbvcxz", "lkjhgfdsa", "0987654321",
    "147258369", "159357", "789456123",
]
TAILS = ["", "1", "12", "123", "!", "1!", "2024", "2025"]


class KeyboardModule:
    name = "keyboard"
    order = 13

    def generate(self, ctx):
        seen: set[str] = set()

        def emit(v):
            if v and v not in seen:
                seen.add(v)
                return True
            return False

        # left-anchored and right-anchored runs along each row
        for row in ROWS:
            letters = "".join(c for c in row if c.isalnum())
            for n in range(3, len(letters) + 1):
                for run in (letters[:n], letters[:n][::-1], letters[-n:]):
                    if emit(run):
                        yield run
                    if emit(run + "123"):
                        yield run + "123"
                    if emit(run.capitalize()):
                        yield run.capitalize()

        # column / diagonal walks
        for c in COLS:
            base = "".join(ch for ch in c if ch.isalnum())
            if emit(base):
                yield base
        for i in range(len(COLS) - 1):
            walk = "".join(ch for ch in COLS[i] + COLS[i + 1] if ch.isalnum())
            if emit(walk):
                yield walk

        for base in CURATED:
            for tail in TAILS:
                for v in (base + tail, base.capitalize() + tail, base.upper() + tail):
                    if emit(v):
                        yield v
