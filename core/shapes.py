"""Post-mortem gap diagnosis for a *plaintext* audit that found nothing.

When the enabled attacks miss the target, this classifies the known string
against a set of well-known weak-password shapes and points at the knob that
would most likely reach it (a bigger budget, a ruleset, a mask, a hint).

Advisory only -- it never changes the crack result or the rank metric, and it
runs solely in plaintext mode (a hash / zip run has no target to inspect).
"""

from __future__ import annotations

import re
from datetime import datetime

CURRENT_YEAR = datetime.now().year

_YEAR_RE = re.compile(r"(?:19[3-9]\d|20[0-4]\d)")
_SYM_TAIL = re.compile(r"([!@#$%^&*()\-+=.,?/\\|~`\[\]{}<>:;'\"]+)$")
_DELEET = {"4": "a", "@": "a", "3": "e", "1": "i", "!": "i",
           "0": "o", "5": "s", "$": "s", "7": "t", "8": "b"}
_KBD_FRAGS = ("qwer", "wert", "erty", "asdf", "sdfg", "zxcv", "xcvb", "1qaz",
              "2wsx", "qazwsx", "yuiop", "hjkl", "poiu", "12qw", "qwaszx")


def _deleet(s: str) -> str:
    return "".join(_DELEET.get(c, c) for c in s)


def _looks_like_date(digits: str) -> str | None:
    fmts = (("%d%m%Y", "DDMMYYYY"), ("%m%d%Y", "MMDDYYYY"), ("%Y%m%d", "YYYYMMDD"),
            ("%d%m%y", "DDMMYY"), ("%m%d%y", "MMDDYY"))
    for fmt, label in fmts:
        if len(digits) != len(datetime(2000, 1, 1).strftime(fmt)):
            continue
        try:
            d = datetime.strptime(digits, fmt)
        except ValueError:
            continue
        if 1900 <= d.year <= CURRENT_YEAR:
            return label
    return None


def _char_classes(s: str) -> int:
    return sum(bool(re.search(p, s)) for p in
               (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))


# per-module: (what the password essentially is, one pointed tip)
_MODULE_WHY = {
    "pins":       ("a numeric PIN",
                   "4-8 digits is at most 10^8 combinations -- brute-forced in under a second"),
    "phone":      ("a phone-number pattern",
                   "phone numbers are public and follow a fixed shape"),
    "sequences":  ("a run or repeat (1234, abcd, aaaa, ...)",
                   "sequences and repeats are the very first thing every cracker tries"),
    "keyboard":   ("a keyboard pattern -- a row walk or finger-mash",
                   "qwerty / asdf / 1qaz2wsx walks are in every wordlist"),
    "dictionary": ("a bare dictionary or breach-list word",
                   "single words fall in the first seconds of any attack"),
    "rules":      ("a dictionary word with predictable mangling (case, digits, punctuation, leet)",
                   "Capitalise + digits + trailing symbol is the single most common "
                   "pattern; tools generate millions of these per second"),
    "dates":      ("built from a date",
                   "a date has only a few thousand possibilities"),
    "dobwords":   ("a known word glued to a birthday date",
                   "a birthday is easy to look up and adds almost no keyspace"),
    "context":    ("built from personal info an attacker can look up (name, email handle, DOB)",
                   "those are the first hints a targeted attacker feeds in"),
    "bip39":      ("a BIP-39 mnemonic word sequence",
                   "a short 2-4 word BIP-39 passphrase is only 2048^words; a real "
                   "12+ word seed is strong but must never be used as a login password"),
    "wordchain":  ("several common words run together",
                   "concatenation only helps if the words are individually rare -- "
                   "use more words, chosen at random"),
    "hybrid":     ("a word plus a short digit / character tail",
                   "word + 4 digits is a named attack mode (hashcat -a 6); the tail adds ~10^4"),
    "fuzz":       ("a dictionary word with one or two characters swapped",
                   "changing a letter or two doesn't help -- crackers fuzz every "
                   "wordlist entry; the base word is still the weak part"),
    "permute":    ("a handful of known words in some order",
                   "if the words are guessable (your pet, team, birth year) the order "
                   "adds almost nothing -- reordering N words is only N! guesses; use "
                   "more words, and pick them at random"),
    "mask":       ("a predictable structural template, small enough to enumerate exhaustively",
                   "length and per-position character sets were guessable"),
    "brute":      ("short enough to fall to plain brute force",
                   "a GPU tries billions of guesses/second offline -- every char you add "
                   "multiplies the work, so length is the only real defence"),
}


def verdict(module: str, rank: int, target: str,
            global_budget: int = 30_000_000) -> tuple[str, list[str]]:
    """Return ('<tier> -- <what it is>', [up to 4 better-practice tips])."""
    n = len(target)

    if module == "bip39":
        # `rank` here is a real 2048**words keyspace (estimate_guesses), not a
        # within-budget hit position -- tier on the actual number
        if rank <= 10 ** 10:
            tier = "very weak"
        elif rank <= 10 ** 14:
            tier = "weak"
        elif rank <= 10 ** 19:
            tier = "brute-forceable offline (fine against a slow hash, lost if the hash leaks)"
        else:
            tier = "strong -- 2048^words is out of reach of offline brute force"
        why, tip = _MODULE_WHY["bip39"]
        return f"{tier} -- {why}", [
            tip,
            "a seed phrase belongs in a wallet, never as a login password",
            "never reuse it -- one breach then exposes every account that shares it",
        ]

    brute_like = module in ("mask", "brute")
    if rank <= 1_000:
        tier = "trivial"
    elif rank <= 100_000:
        tier = "very weak"
    elif rank <= 20_000_000 or not brute_like:
        # anything a wordlist / rule / hint attack reaches is "weak" however
        # deep the rank -- those attacks are cheap and run to completion
        tier = "weak"
    else:
        tier = "brute-forceable offline (fine against a slow hash, lost if the hash leaks)"

    why, tip = _MODULE_WHY.get(
        module, ("reachable by an automated guessing attack",
                 "it matched a generated candidate well within budget"))

    tips: list[str] = []
    if n < 12:
        tips.append(f"only {n} characters -- too short whatever the composition; aim for 16+")
    tips.append(tip)
    tips.append("prefer length over complexity: 4-5 unrelated random words (>=20 chars), "
                "or a password-manager 16+ char random string")
    tips.append("never reuse it -- one breach then exposes every account that shares it")
    return f"{tier} -- {why}", tips[:4]


def diagnose(target: str, hint_tokens: list[str] | None = None) -> list[str]:
    """Return up to 6 human-readable '<shape>: <suggestion>' strings."""
    hint_tokens = hint_tokens or []
    hint_low = {h.lower() for h in hint_tokens}
    t = target
    low = t.lower()
    n = len(t)
    classes = _char_classes(t)
    out: list[str] = []

    def add(msg: str) -> None:
        key = msg[:40]
        if not any(o.startswith(key) for o in out):
            out.append(msg)

    # --- a known hint sits inside the password, with extra stuck on ---------
    for tok in sorted({h for h in hint_tokens if len(h) >= 3}, key=len, reverse=True):
        lt = tok.lower()
        if lt in low and low != lt:
            i = low.index(lt)
            pre, post = t[:i], t[i + len(tok):]
            if post.isdigit() and post:
                add(f"hint {tok!r} + trailing digits {post!r}: "
                    f"--hybrid-mask '{'?d' * min(len(post), 8)}' "
                    f"(word x digit mask), or --rules-file rules/starter.rule")
            elif pre.isdigit() and pre:
                add(f"digits {pre!r} + hint {tok!r}: "
                    f"--hybrid-mask '{'?d' * min(len(pre), 8)}' --hybrid-side prepend")
            else:
                # strip separators; if what's left is empty or another hint,
                # the token<sep>token rule below says it better
                res = (pre + " " + post).strip(" ._-")
                if res and res.lower() not in hint_low:
                    add(f"hint {tok!r} plus {res!r}: pass the other part "
                        f"as its own --word so context glues them, or --rules-file")
            break

    # --- word + digits / word + year (ignoring any trailing symbol) -------
    core_t = _SYM_TAIL.sub("", t)
    m = re.fullmatch(r"((?:[^\W\d_]|['.\-]){3,})(\d{1,4})", core_t)
    if m:
        w, digs = m.groups()
        if _YEAR_RE.fullmatch(digs):
            add(f"word + 4-digit year ({w!r} + {digs}): --rules-file rules/starter.rule "
                f"has year-suffix rules; also raise --module-budget if {w.lower()!r} "
                f"is deep in the wordlist")
        else:
            add(f"word + {len(digs)} digit(s) ({w!r} + {digs!r}): "
                f"--hybrid-mask '{'?d' * len(digs)}' or --rules-file rules/starter.rule")

    # --- trailing punctuation --------------------------------------------
    ms = _SYM_TAIL.search(t)
    if ms and ms.start() > 0:
        add(f"trailing symbol(s) {ms.group(1)!r}: --rules-file (append-char rules "
            f"like $! $. $1$2$3) -- the built-in mangle only tries a couple")

    # --- leet substitution ----------------------------------------------
    if any(c in _DELEET for c in t):
        dl = _deleet(t)
        base = re.sub(r"\d+$", "", dl)
        if len(base) >= 4 and base.isalpha() and base.lower() != low.rstrip("0123456789"):
            add(f"leet substitution -- de-leets to {dl!r}: --rules-file with leet rules, "
                f"or add {base.lower()!r} via --word")

    # --- embedded birthday-style date ----------------------------------
    for mm in re.finditer(r"\d{8}|\d{6}", t):
        label = _looks_like_date(mm.group())
        if label:
            add(f"embedded date {mm.group()!r} ({label}): pass --dob <date> and "
                f"--depth 2 -- the dobwords module glues birthday dates onto known words")
            break

    # --- concatenated Capitalised words -------------------------------
    if t.isalpha() and re.search(r"[a-z][A-Z]", t):
        add("concatenated CapitalisedWords: --chain-words 2 --chain-vocab 3000 "
            "(wordchain), or pass each part as --word")

    # --- token<sep>token --------------------------------------------
    m = re.fullmatch(r"([A-Za-z]{2,})([._\-])([A-Za-z0-9]{2,})", t)
    if m:
        add(f"two tokens joined by {m.group(2)!r}: give both parts as "
            f"--word / --user / --name so context's pairwise glue rebuilds it")

    # --- keyboard walk ----------------------------------------------
    if any(frag in low for frag in _KBD_FRAGS):
        add("looks like a keyboard walk / pattern: the keyboard + sequences modules "
            "cover rows, walks and mashes -- raise --module-budget or check --skip")

    # --- long run-together lowercase letters (passphrase) --------------
    if re.fullmatch(r"[a-z]{12,}", t):
        add(f"{n} lowercase letters, no digits -- likely run-together words: "
            f"--chain-words 3 --chain-vocab 4000 (wordchain), and make sure "
            f"wordchain is not in --skip")

    # --- repeated block ------------------------------------------------
    m = re.fullmatch(r"(.{1,4}?)\1{2,}", t)
    if m:
        add(f"repeated block {m.group(1)!r}: keyboard / sequences cover many of these "
            f"-- check you did not --skip them, or raise --module-budget")

    # --- all digits -------------------------------------------------
    if t.isdigit():
        note = ""
        if n <= 8:
            note = f" -- feasible: --brute --charset d --min {n} --max {n} (10^{n})"
        if n in (4, 6):
            note += "; the pins module covers this length unless it was budget-capped"
        add(f"all-numeric, {n} digits{note or ' -- too long to brute; needs a leak or pattern'}")

    # --- short enough that brute is on the table ----------------------
    elif n <= 9 and not out:
        if t.isalpha() and t.islower():
            cs, size = "l", 26
        elif t.isalpha():
            cs, size = "ul", 52
        elif re.fullmatch(r"[a-z0-9]+", t):
            cs, size = "dl", 36
        elif re.fullmatch(r"[A-Za-z0-9]+", t):
            cs, size = "ul d".replace(" ", ""), 62
        else:
            cs, size = "a", 95
        ks = size ** n
        reach = "feasible for fast hashes" if ks <= 5e11 else f"~{ks:.0e} keyspace, borderline"
        add(f"only {n} chars ({classes} class(es)) -- brute is on the table "
            f"({reach}): --brute --charset {cs} --min {n} --max {n}")

    # --- nothing recognisable + genuinely large keyspace --------------
    if not out:
        if n >= 12 and classes >= 3:
            add(f"{n} chars, {classes} character classes, no recognisable base word: "
                f"not reachable by enumeration -- only a breach list (--wordlist) or a "
                f"target-specific CeWL list would help. This looks like a strong password.")
        else:
            add("no known weak shape matched -- try --wordlist with a bigger list "
                "(rockyou) plus --rules-file rules/starter.rule, or add hints.")

    return out[:6]
