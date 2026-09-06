"""Bounded brute force.

  --mask '?u?l?l?l?l?d?d?d?d'   fixed-shape mask (hashcat-style tokens)
  --brute --charset dl --min 4 --max 6   every string over a charset

Mask tokens: ?d digits  ?l lower  ?u upper  ?s symbols  ?a all  literal chars
pass through. Only runs when --mask or --brute is given; keyspace is printed
up front so you can size --module-budget accordingly.
"""

from __future__ import annotations

import itertools

from core import estimate

CHARSETS = {
    "d": "0123456789",
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}
CHARSETS["a"] = CHARSETS["l"] + CHARSETS["u"] + CHARSETS["d"] + CHARSETS["s"]


def _parse_mask(mask: str) -> list[str]:
    positions: list[str] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?" and i + 1 < len(mask):
            token = mask[i + 1]
            positions.append(CHARSETS.get(token, token))
            i += 2
        else:
            positions.append(ch)  # literal
            i += 1
    return positions


def _charset_from_spec(spec: str) -> str:
    out = ""
    for ch in spec:
        out += CHARSETS.get(ch, ch)
    return "".join(dict.fromkeys(out))


class MaskModule:
    name = "mask"
    order = 40
    plaintext_only = False

    def __init__(self, mask=None, brute=False, charset="d", min_len=1, max_len=8):
        self.mask = mask
        self.brute = brute
        self.charset = charset
        self.min_len = min_len
        self.max_len = max_len

    def _plans(self):
        if self.mask:
            yield _parse_mask(self.mask)
        if self.brute:
            cs = _charset_from_spec(self.charset)
            for n in range(self.min_len, self.max_len + 1):
                yield [cs] * n

    def keyspace(self) -> int:
        total = 0
        for plan in self._plans():
            k = 1
            for pos in plan:
                k *= max(len(pos), 1)
            total += k
        return total

    def note(self, ctx):
        if not (self.mask or self.brute):
            return None
        return (f"keyspace ~= {self.keyspace():,} candidates -- "
                f"{estimate.exhaust_note(self.keyspace(), ctx)}")

    def generate(self, ctx):
        for plan in self._plans():
            for combo in itertools.product(*plan):
                yield "".join(combo)
