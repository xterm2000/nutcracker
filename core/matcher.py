"""Decide whether a candidate string is 'the' password.

Two modes:
  * PlaintextMatcher -- candidate == known plaintext (guessability audit)
  * HashMatcher      -- H(candidate) matches one of the target hashes
"""

from __future__ import annotations

import hashlib


class PlaintextMatcher:
    mode = "plaintext"

    def __init__(self, target: str):
        self.target = target

    def matches(self, candidate: str) -> bool:
        return candidate == self.target


class HashMatcher:
    mode = "hash"

    def __init__(self, targets, algo: str, salt_prefix: str = "", salt_suffix: str = ""):
        self.algo = algo.lower()
        self.salt_prefix = salt_prefix
        self.salt_suffix = salt_suffix
        self.bcrypt = self.algo == "bcrypt"
        if self.bcrypt:
            import bcrypt as _bcrypt  # optional dependency

            self._bcrypt = _bcrypt
            self.targets = [t.strip().encode() for t in targets if t.strip()]
        else:
            if self.algo not in hashlib.algorithms_available:
                raise ValueError(f"unsupported hash algo: {self.algo}")
            self.targets = {t.strip().lower() for t in targets if t.strip()}

    def matches(self, candidate: str) -> bool:
        if self.bcrypt:
            cb = candidate.encode()
            for t in self.targets:
                try:
                    if self._bcrypt.checkpw(cb, t):
                        return True
                except ValueError:
                    pass
            return False
        salted = (self.salt_prefix + candidate + self.salt_suffix).encode("utf-8", "ignore")
        return hashlib.new(self.algo, salted).hexdigest() in self.targets
