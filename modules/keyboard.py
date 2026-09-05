"""Keyboard walks on a QWERTY layout: row runs, column/diagonal walks, the
well-known curated set (qwerty, 1qaz2wsx, zaq12wsx, ...), lazy finger-mash
repeats (asdasd, qweqwe, lkjlkjlkj), and interleaved digit / shift-symbol
two-liners (q1w2e3r4, Q!W@E#R$)."""

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
TAILS = ["", "1", "12", "123", "!", "1!", "2024", "2025","2000"]

# digit -> shifted symbol on a US QWERTY keyboard
SHIFT_DIGITS = {"1": "!", "2": "@", "3": "#", "4": "$", "5": "%",
                "6": "^", "7": "&", "8": "*", "9": "(", "0": ")"}

# small adjacent key clusters people mash with two/three/four lazy fingers
MASH = [
    "asd", "sdf", "dsa", "fds", "asdf", "sdfg", "fdsa", "gfds",
    "qwe", "wer", "ewq", "rew", "qwer", "wert", "rewq", "trew",
    "zxc", "xcv", "cxz", "vcx", "zxcv",
    "jkl", "kjl", "lkj", "jklk", "hjkl", "lkjh",
    "uio", "iop", "poi", "oiu", "uiop", "poiu",
    "wsx", "edc", "rfv", "tgb", "yhn", "ujm",
    "aoeu", "htns",  # dvorak home-row mash, seen in the wild
]


def _interleave(base: str) -> list[str]:
    """qwer -> q1w2e3r4 / 1q2w3e4r / Q!W@E#R$ / q!w@e#r$ style two-liners."""
    out: list[str] = []
    letters = [c for c in base if c.isalpha()][:9]
    if len(letters) < 2:
        return out
    digits = [str(i + 1) for i in range(len(letters))]
    syms = [SHIFT_DIGITS[d] for d in digits]
    out.append("".join(l + d for l, d in zip(letters, digits)))          # q1w2e3r4
    out.append("".join(d + l for l, d in zip(letters, digits)))          # 1q2w3e4r
    out.append("".join(l + s for l, s in zip(letters, syms)))            # q!w@e#r$
    out.append("".join(l.upper() + s for l, s in zip(letters, syms)))    # Q!W@E#R$
    out.append("".join(l.upper() + d for l, d in zip(letters, digits)))  # Q1W2E3R4
    return out


class KeyboardModule:
    name = "keyboard"
    order = 9

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

        # finger-mash: a cluster repeated 2-4x (asdasd, qweqwe, lkjlkjlkj, asdfasdf)
        for frag in MASH:
            for reps in (2, 3, 4):
                rep = frag * reps
                for v in (rep, rep.capitalize(), rep + "1", rep + "123", rep + "!"):
                    if emit(v):
                        yield v

        # interleaved digit / shift-symbol two-liners off each row run and cluster
        interleave_bases = ["qwerty", "qwert", "qwer", "asdf", "asdfg", "zxcv",
                            "qaz", "wsx", "qwertyuiop"] + [f for f in MASH if len(f) >= 4]
        for base in interleave_bases:
            for v in _interleave(base):
                if emit(v):
                    yield v

        for base in CURATED:
            for tail in TAILS:
                for v in (base + tail, base.capitalize() + tail, base.upper() + tail):
                    if emit(v):
                        yield v
