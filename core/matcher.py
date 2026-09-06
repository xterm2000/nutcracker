"""Decide whether a candidate string is 'the' password.

Modes:
  * PlaintextMatcher -- candidate == known plaintext (guessability audit)
  * HashMatcher      -- H(candidate) matches one of the target hashes
  * ZipMatcher       -- candidate opens a password-protected .zip archive
  * GpgMatcher       -- candidate decrypts a symmetric (`gpg -c`) OpenPGP file
  * SshKeyMatcher    -- candidate unlocks an encrypted OpenSSH / PEM private key

All expose the same surface: a `.mode` string and `.matches(candidate) ->
bool`. Everything else in the pipeline (modules, runner, budgets) only ever
generates candidate strings and calls `.matches()`.

`GpgMatcher` / `SshKeyMatcher` shell out to the system `gpg` / `ssh-keygen`
once per candidate -- a subprocess spawn is ~1-5 ms floor, and OpenPGP S2K /
OpenSSH bcrypt-pbkdf are deliberately slow, so only the cheap bounded modules
(`context`, `pins`, `dictionary`, `rules` at a modest budget) are realistic;
`--mask` / brute over any real keyspace is not. `--jobs N` helps -- each
`.matches()` blocks on its child, so N workers give a near-linear speed-up
(CPU-bound, like ZipCrypto).
"""

from __future__ import annotations

import hashlib
import os


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


class GpgMatcher:
    """Try each candidate as the passphrase of a **symmetric** OpenPGP file
    (`gpg --symmetric` / `gpg -c`).

    `mode = "hash"` -- plaintext-only modules are skipped, `--mask` / `--brute`
    stay available (though see the module docstring: brute is rarely viable
    here). One `gpg` child per candidate; wrong passphrase exits non-zero fast.

    Only symmetric files. A public-key-encrypted (`gpg -e`) file cannot be
    attacked this way -- it needs the recipient's secret key, not a passphrase
    guess -- and neither can a bare exported secret key (`gpg --export-secret-keys`),
    whose passphrase gpg will not check via `--decrypt`.
    """

    mode = "hash"
    algo = "gpg"

    def __init__(self, path: str, timeout: float = 10.0):
        import shutil
        import subprocess

        self.path = path
        self.timeout = timeout
        self.gpg = shutil.which("gpg") or shutil.which("gpg2")
        if not self.gpg:
            raise SystemExit(
                "--gpg: the 'gpg' binary is not on PATH.\n"
                "Install GnuPG (e.g. 'dnf install gnupg2' / 'apt install gnupg')."
            )
        with open(path, "rb") as fh:            # readability + non-empty check
            if not fh.read(1):
                raise ValueError(f"{path}: empty file")
        # confirm it's a symmetric OpenPGP file before running a doomed attack
        try:
            pkts = subprocess.run(
                [self.gpg, "--batch", "--no-tty", "--list-packets", path],
                capture_output=True, timeout=timeout,
            ).stdout.decode("utf-8", "replace")
        except (subprocess.SubprocessError, OSError) as exc:
            raise ValueError(f"{path}: could not inspect with gpg ({exc})")
        if "symkey enc packet" not in pkts:
            why = ("looks public-key encrypted (needs the secret key, not a passphrase)"
                   if "pubkey enc packet" in pkts else "not a symmetric OpenPGP file")
            raise ValueError(f"{path}: {why}")

    def matches(self, candidate: str) -> bool:
        import subprocess

        try:
            p = subprocess.run(
                [self.gpg, "--batch", "--quiet", "--no-tty", "--yes",
                 "--pinentry-mode", "loopback", "--no-symkey-cache",
                 "--passphrase", candidate,
                 "--output", os.devnull, "--decrypt", self.path],
                capture_output=True, timeout=self.timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        return p.returncode == 0


class SshKeyMatcher:
    """Try each candidate as the passphrase of an encrypted private key
    (OpenSSH's own format or a legacy PEM `id_rsa`), via `ssh-keygen -y`.

    `ssh-keygen -y -P <cand> -f KEY` prints the public key and exits 0 on the
    right passphrase, non-zero otherwise; it never writes the key file.
    `mode = "hash"`. Modern keys use bcrypt-pbkdf (very slow by design) -- keep
    the module budget small.
    """

    mode = "hash"
    algo = "ssh-key"

    def __init__(self, path: str, timeout: float = 10.0):
        import shutil
        import subprocess

        self.path = path
        self.timeout = timeout
        self.keygen = shutil.which("ssh-keygen")
        if not self.keygen:
            raise SystemExit("--sshkey: 'ssh-keygen' is not on PATH (install openssh).")
        # probe with the empty passphrase: rc 0 = unencrypted (nothing to crack);
        # "incorrect passphrase" = an encrypted key we can attack; anything else
        # (bad format, bad permissions, not a key) = bail with ssh-keygen's message.
        try:
            probe = subprocess.run(
                [self.keygen, "-y", "-P", "", "-f", path],
                capture_output=True, timeout=timeout,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            raise ValueError(f"{path}: could not probe with ssh-keygen ({exc})")
        if probe.returncode == 0:
            raise ValueError(f"{path}: private key is not passphrase-protected")
        if b"incorrect passphrase" not in probe.stderr.lower():
            msg = probe.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            raise ValueError(f"{path}: not an attackable private key -- {msg[0]}")

    def matches(self, candidate: str) -> bool:
        import subprocess

        try:
            p = subprocess.run(
                [self.keygen, "-y", "-P", candidate, "-f", self.path],
                capture_output=True, timeout=self.timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        return p.returncode == 0
