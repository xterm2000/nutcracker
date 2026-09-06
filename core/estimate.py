"""Turn a guess count into wall-clock crack-time estimates.

Order-of-magnitude only -- the point is to separate "instant", "a coffee
break", "a year" and "never", not to be precise. Rates are guesses/second for
a single well-funded attacker rig (~8 modern GPUs) and follow the figures the
password-strength literature quotes (hashcat benchmarks, the OWASP / NIST
guidance on work factors).

Used by:
  * crack.py -- the CRACKED verdict block (`crack_time`)
  * the opt-in modules' note() lines (`exhaust_note`) -- time to exhaust the
    keyspace they are about to sweep
"""

from __future__ import annotations

import re

_YEAR = 31_557_600

# offline guesses/sec, single rig, by hashlib algo name (+ 'ntlm', 'bcrypt')
_ALGO_RATE = {
    "md5": 1e11, "sha1": 6e10, "sha224": 1e10, "sha256": 1e10,
    "sha384": 3e9, "sha512": 3e9, "sha3_256": 5e9, "sha3_512": 3e9,
    "blake2b": 4e9, "blake2s": 6e9, "ntlm": 3e11, "bcrypt": 2e4,
}

# scenarios always shown, slowest first: (long label, short label, guesses/sec)
_GENERIC_ROWS = [
    ("online, throttled login (10/s)", "online 10/s", 10),
    ("online, unthrottled (1k/s)", "online 1k/s", 1_000),
    ("offline, memory-hard hash - bcrypt / argon2 (20k/s)", "bcrypt-class", 20_000),
    ("offline, fast hash - MD5 / SHA-1 on a GPU rig (100 G/s)", "fast-hash rig", 1e11),
]


def algo_rate(algo: str | None) -> float | None:
    return _ALGO_RATE.get(algo.lower()) if algo else None


def human_count(n) -> str:
    n = float(n)
    if n >= 1e21:
        return "~" + f"{n:.0e}".replace("e+0", "e").replace("e+", "e")
    for size, name in ((1e18, "quintillion"), (1e15, "quadrillion"),
                       (1e12, "trillion"), (1e9, "billion"),
                       (1e6, "million"), (1e3, "thousand")):
        if n >= size:
            return f"~{n / size:.1f} {name}"
    return f"~{n:,.0f}"


def human_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"

    def _u(value: float, unit: str) -> str:
        return f"{value:.0f} {unit}" if value >= 1.5 else f"1 {unit[:-1]}"

    if seconds < 60:
        return _u(seconds, "seconds")
    if seconds < 3_600:
        return _u(seconds / 60, "minutes")
    if seconds < 86_400:
        return _u(seconds / 3_600, "hours")
    if seconds < _YEAR:
        return _u(seconds / 86_400, "days")
    y = seconds / _YEAR
    if y >= 1e12:
        return "longer than the universe has existed"
    if y >= 1e6:
        return f"~{y:.0e} years"
    return f"~{y:,.0f} years"


def crack_time(guesses, *, algo: str | None = None, zip_mode: bool = False):
    """[(long_label, short_label, human_time)] for `guesses` attempts across
    attack scenarios.

    In hash mode the target algo's own rate is appended as an extra row;
    for --zip a ZipCrypto-on-GPU row is added instead."""
    guesses = max(float(guesses), 1.0)
    rows = list(_GENERIC_ROWS)
    r = algo_rate(algo)
    if r and r not in (rate for _, _, rate in rows):
        rows.append((f"offline, this target's hash ({algo}, {human_count(r)}/s)",
                     f"{algo} (target)", r))
    elif zip_mode:
        rows.append(("offline, ZipCrypto on a GPU (~1 G/s)", "ZipCrypto GPU", 1e9))
    return [(long, short, human_time(guesses / rate)) for long, short, rate in rows]


_POOLS = ((r"[a-z]", 26), (r"[A-Z]", 26), (r"\d", 10),
          (r"[^A-Za-z0-9]", 33))  # ~33 printable ASCII punctuation + space


def brute_keyspace(s: str) -> tuple[int, int]:
    """(character-pool size, pool ** len) for `s` -- the size of a blind brute
    force over exactly the classes the string uses. An upper bound on strength:
    any structure (words, dates, patterns) puts the real number far lower."""
    pool = sum(size for pat, size in _POOLS if re.search(pat, s)) or 1
    return pool, pool ** len(s)


def not_found_report(plaintext, tried, *, algo=None, zip_mode=False,
                     weak_shape=False) -> list[str]:
    """Lines for a NOT-FOUND result: always a lower bound from what was tried;
    in plaintext mode also a brute-force ceiling from the string's composition.

    `weak_shape` = the shape analysis flagged a pattern, so the ceiling is
    optimistic and the real value sits well below it."""
    tried = max(int(tried), 1)
    out: list[str] = []

    fast = algo_rate(algo) or (1e9 if zip_mode else 1e11)
    where = algo or ("ZipCrypto" if zip_mode else "a fast-hash rig")
    slow = 20_000  # bcrypt / argon2 class
    out.append(f"lower bound: it survived {tried:,} candidates -- "
               f"~{human_time(tried / slow)} against a slow hash (bcrypt), "
               f"{human_time(tried / fast)} against {where}")

    if plaintext:
        pool, ks = brute_keyspace(plaintext)
        out.append(f"upper bound (only if truly random): {len(plaintext)} chars "
                   f"over a ~{pool}-char pool ~= {human_count(ks)} guesses -> "
                   f"{human_time((ks / 2) / fast)} even against {where}")
        if weak_shape:
            out.append("a weak shape was flagged above -- the real value sits well "
                       "below that ceiling; treat it as reachable, not strong")
        else:
            out.append("no weak shape matched -- if the ceiling holds this is a "
                       "strong password (assumes no pattern the tool missed)")
    else:
        out.append("the plaintext is needed to say more -- a hash reveals nothing "
                   "about structure")
    return out


def exhaust_note(keyspace, ctx) -> str:
    """Short '~T to exhaust vs X' tail for an opt-in module's note()."""
    matcher = getattr(ctx, "matcher", None)
    algo = getattr(matcher, "algo", None)
    zip_mode = matcher.__class__.__name__ == "ZipMatcher"
    rate = algo_rate(algo) or (1e9 if zip_mode else 1e11)
    where = algo or ("ZipCrypto" if zip_mode else "a fast-hash rig")
    return f"{human_time(keyspace / rate)} to exhaust vs {where}"
