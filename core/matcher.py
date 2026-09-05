"""Decide whether a candidate string is 'the' password.

Modes:
  * PlaintextMatcher -- candidate == known plaintext (guessability audit)
  * HashMatcher      -- H(candidate) matches one of the target hashes
  * ZipMatcher       -- candidate opens a password-protected .zip archive

All three expose the same surface: a `.mode` string and `.matches(candidate)
-> bool`. Everything else in the pipeline (modules, runner, budgets) only ever
generates candidate strings and calls `.matches()`.
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


class ZipMatcher:
    """Try each candidate as the password of a .zip archive.

    Legacy **ZipCrypto** archives are handled by the stdlib `zipfile`. **WinZip
    AES** archives need the optional `pyzipper` package (lazy-imported, like
    `bcrypt`); without it an AES archive exits with an install hint.

    `mode = "hash"` so `plaintext_only` modules are skipped and `--mask` /
    `--brute` stay available -- same as a real preimage search.

    The archive handle is opened lazily *per process* (`_zf` starts None), so
    a `--jobs N` fork pool gets one handle per worker instead of sharing one
    file offset. Reading a full (smallest) entry means the CRC is verified, so
    a reported match is real -- no ZipCrypto 1/256 header-check false positive.
    """

    mode = "hash"

    def __init__(self, path: str):
        import zipfile

        self.path = path
        self._zipfile = zipfile
        self._zf = None  # opened on first matches(), once per process

        with zipfile.ZipFile(path) as zf:
            encrypted = [i for i in zf.infolist() if i.flag_bits & 0x1]
            if not encrypted:
                raise ValueError(f"no encrypted entries in {path}")
            # smallest non-empty entry = fewest bytes to decrypt+CRC per guess
            sized = [i for i in encrypted if i.file_size > 0] or encrypted
            entry = min(sized, key=lambda i: i.file_size)
            self._entry = entry.filename
            self._aes = entry.compress_type == 99 or b"\x01\x99" in (entry.extra or b"")

        self._pyzipper = None
        if self._aes:
            try:
                import pyzipper
            except ImportError:
                raise SystemExit(
                    f"{path}: WinZip AES encryption -- the stdlib cannot read it.\n"
                    "Install the optional dependency:  pip install pyzipper"
                )
            self._pyzipper = pyzipper

    def _handle(self):
        if self._zf is None:
            opener = self._pyzipper.AESZipFile if self._aes else self._zipfile.ZipFile
            self._zf = opener(self.path)
        return self._zf

    def matches(self, candidate: str) -> bool:
        try:
            self._handle().read(self._entry, pwd=candidate.encode())
            return True
        except Exception:
            # wrong password -> RuntimeError; bad decrypt -> BadZipFile / zlib error
            return False
