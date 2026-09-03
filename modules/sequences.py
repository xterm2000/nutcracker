"""Sequences & repeats: 123456, abcdef, aaaa, 123123, abcabc, qwerty123,
passpass, and top words doubled/mirrored."""

from __future__ import annotations

DIGITS = "0123456789"
ALPHA = "abcdefghijklmnopqrstuvwxyz"
SEQ_BASES = ["abc", "abcd", "abcde", "abcdef", "abcabc", "qwerty", "asdf", "asdfgh"]
SEQ_TAILS = ["", "1", "12", "123", "1234", "12345", "123456", "!", "123!", "007"]
REPEAT_UNITS = ["ab", "abc", "abcd", "12", "123", "1234", "xyz", "asd", "qwe", "aoa", "zxc"]


class SequenceModule:
    name = "sequences"
    order = 12

    def generate(self, ctx):
        seen: set[str] = set()

        def emit(v):
            if v and v not in seen:
                seen.add(v)
                return True
            return False

        # numeric runs, forwards / backwards / offset
        for n in range(3, 11):
            for run in (DIGITS[:n], DIGITS[:n][::-1], DIGITS[-n:], DIGITS[10 - n:][::-1]):
                if emit(run):
                    yield run
        for start in range(0, 8):
            for n in range(3, 8):
                run = "".join(str((start + i) % 10) for i in range(n))
                if emit(run):
                    yield run

        # alpha runs
        for n in range(3, 11):
            for run in (ALPHA[:n], ALPHA[:n][::-1]):
                if emit(run):
                    yield run
                if emit(run + "123"):
                    yield run + "123"

        # single-char repeats
        for ch in ALPHA + DIGITS + "!@#$*":
            for n in (3, 4, 5, 6, 8, 10):
                if emit(ch * n):
                    yield ch * n

        # repeated units
        for unit in REPEAT_UNITS:
            for k in (2, 3, 4):
                if emit(unit * k):
                    yield unit * k

        # base + tail combos
        for base in SEQ_BASES:
            for tail in SEQ_TAILS:
                for v in (base + tail, base.capitalize() + tail, base.upper() + tail):
                    if emit(v):
                        yield v

        for v in ("1a2b3c", "a1b2c3", "1q2w3e", "1q2w3e4r", "q1w2e3", "abc123!"):
            if emit(v):
                yield v

        # top words doubled / mirrored
        for w in ctx.wordlists.top(300):
            for v in (w + w, w + w[::-1], w.capitalize() + w):
                if emit(v):
                    yield v
