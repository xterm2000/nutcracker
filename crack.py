#!/usr/bin/env python3
"""
Modular dictionary / pattern password cracker -- research & educational use only.

Target modes:
  * plaintext -- you type a password; the tool reports whether (and at what
                 rank) the enabled attacks would reach it. A guessability audit.
  * hash      -- give a hash (or a file of hashes) + algo; the tool runs the
                 same candidate generators as a real preimage search.
  * zip       -- give a password-protected .zip; each candidate is tried as the
                 archive password (ZipCrypto via stdlib; WinZip AES via optional
                 pyzipper). Behaves like hash mode for module selection.

Attacks are pluggable modules in ./modules, run cheapest-first under a budget.

Examples:
  ./crack.py -p 'Summer2024!'
  ./crack.py -p 'mary had a little lamb'
  ./crack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algo md5
  ./crack.py --hashfile hashes.txt --algo sha256 --user jsmith --dob 1990-05-01
  ./crack.py --zip secret.zip --word acme --dob 1990-05-01 --jobs 4
  ./crack.py --hash <h> --algo md5 --brute --charset dl --min 4 --max 6
  ./crack.py -p 'Password2024!' --rules-file rules/starter.rule
  ./crack.py -p 'hunter1990' --hybrid-mask '?d?d?d?d'
  ./crack.py --hash <h> --algo sha1 --wordlist rockyou.txt --rules-file rules/starter.rule
  ./crack.py -p x --only pins,dates          # run just some modules
  ./crack.py -p x --skip wordchain,rules     # or drop some
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.context import CrackContext, Hints, Limits
from core.matcher import HashMatcher, PlaintextMatcher, ZipMatcher
from core import rules_engine, wordlists
import modules
from core.runner import Runner

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _csv(s):
    return [x.strip() for x in s.split(",") if x.strip()]


def _budget_size(s):
    """Parse a candidate-budget size: bare number = millions ('12' -> 12,000,000);
    'k'/'m'/'g' suffix picks the unit explicitly ('500k' -> 500,000)."""
    s = s.strip().lower()
    mult = 1_000_000
    if s and s[-1] in "kmg":
        mult = {"k": 1_000, "m": 1_000_000, "g": 1_000_000_000}[s[-1]]
        s = s[:-1]
    return int(float(s) * mult)


def build_args():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    tgt = ap.add_argument_group("target")
    tgt.add_argument("-p", "--password", help="plaintext password to audit (else prompt)")
    tgt.add_argument("--show", action="store_true", help="prompt with visible input")
    tgt.add_argument("--hash", dest="hash_", metavar="HEX", help="single target hash")
    tgt.add_argument("--hashfile", help="file of target hashes, one per line")
    tgt.add_argument("--zip", dest="zip_", metavar="PATH",
                     help="password-protected .zip to crack (ZipCrypto via stdlib; "
                          "WinZip AES needs the optional 'pyzipper')")
    tgt.add_argument("--algo", default="md5",
                     help="hash algo: md5/sha1/sha256/sha512/... or bcrypt (default md5)")
    tgt.add_argument("--salt-prefix", default="", help="salt prepended before hashing")
    tgt.add_argument("--salt-suffix", default="", help="salt appended before hashing")

    hint = ap.add_argument_group("hints (feed the context module)")
    hint.add_argument("--user", help="target username")
    hint.add_argument("--email", help="target email")
    hint.add_argument("--name", help="target full name, e.g. 'Mary Smith'")
    hint.add_argument("--dob", help="date of birth, e.g. 1990-05-01")
    hint.add_argument("--word", action="append", default=[], metavar="W",
                      help="extra known word (repeatable): pet, company, team...")

    sel = ap.add_argument_group("module selection")
    sel.add_argument("--only", type=_csv, help="run only these modules (csv)")
    sel.add_argument("--skip", type=_csv, help="skip these modules (csv)")
    sel.add_argument("--list-modules", action="store_true", help="print module names and exit")

    wl = ap.add_argument_group("wordlists")
    wl.add_argument("--wordlist", action="append", default=[], metavar="PATH",
                    help="extra wordlist file, loaded before the built-ins (repeatable)")

    rl = ap.add_argument_group("rule-based mangling")
    rl.add_argument("--rules-file", metavar="PATH",
                    help="hashcat-style rule file for the 'rules' module; replaces "
                         "its built-in mangle set (full-line '#' comments allowed). "
                         "See rules/starter.rule")

    hyb = ap.add_argument_group("hybrid (opt-in, adds the hybrid module)")
    hyb.add_argument("--hybrid-mask", metavar="MASK",
                     help="mask glued to each top word, e.g. '?d?d?d?d'")
    hyb.add_argument("--hybrid-side", choices=["append", "prepend", "both"],
                     default="both", help="word+mask, mask+word, or both (default both)")
    hyb.add_argument("--hybrid-vocab", type=int, default=2000,
                     help="top-N words fed to the hybrid module (default 2000)")

    brute = ap.add_argument_group("mask / brute (opt-in, adds the mask module)")
    brute.add_argument("--mask", help="hashcat-style mask, e.g. '?u?l?l?l?d?d?d?d'")
    brute.add_argument("--brute", action="store_true", help="sweep a charset by length")
    brute.add_argument("--charset", default="d", help="brute charset spec: d l u s a or literal chars")
    brute.add_argument("--min", type=int, default=1, dest="min_len")
    brute.add_argument("--max", type=int, default=8, dest="max_len")

    lim = ap.add_argument_group("limits")
    lim.add_argument("--limit", type=int, help="cap words loaded per wordlist")
    lim.add_argument("--module-budget", type=_budget_size, default=3_000_000,
                     help="max candidates per module: bare number = millions, "
                          "or use a k/m/g suffix, e.g. 3, 500k, 1g (default 3 = 3M)")
    lim.add_argument("--budget", type=_budget_size, default=30_000_000,
                     help="global candidate hard stop: bare number = millions, "
                          "or use a k/m/g suffix (default 30 = 30M)")
    lim.add_argument("--chain-vocab", type=int, default=800,
                     help="top-N words fed to the word-chain generator, hash mode (default 800)")
    lim.add_argument("--chain-words", type=int, default=3,
                     help="max words per chain, hash mode (default 3); plaintext decomposition is unbounded")
    lim.add_argument("--depth", type=int, default=1,
                     help="dobwords structure depth (needs --dob): 1 = token+date, "
                          "2 = +relation-word+date+token, 3 = +token+date+token & word+word+date (default 1)")
    lim.add_argument("--pin6", action="store_true", help="also sweep the full 6-digit PIN space")
    lim.add_argument("--jobs", type=int, default=1,
                     help="worker processes for testing candidates (default 1 = sequential); "
                          "mainly worth raising for --algo bcrypt or --zip")
    return ap


def resolve_target(args):
    """Return (matcher, plaintext_target_or_None, label)."""
    if args.zip_:
        import zipfile
        try:
            m = ZipMatcher(args.zip_)
        except (OSError, zipfile.BadZipFile, ValueError) as exc:
            print(f"  ! --zip: {exc}")
            sys.exit(1)
        kind = "AES" if m._aes else "ZipCrypto"
        return m, None, f"zip archive {os.path.basename(args.zip_)} ({kind}, entry {m._entry!r})"

    if args.hash_ or args.hashfile:
        targets = []
        if args.hash_:
            targets.append(args.hash_)
        if args.hashfile:
            with open(args.hashfile, encoding="utf-8") as fh:
                targets += [ln.strip() for ln in fh if ln.strip()]
        m = HashMatcher(targets, args.algo, args.salt_prefix, args.salt_suffix)
        label = f"{len(targets)} {args.algo} hash(es)"
        return m, None, label

    if args.password is not None:
        pw = args.password
    elif args.show:
        pw = input("Password to crack: ")
    else:
        pw = getpass.getpass("Password to crack (hidden): ")
    if not pw:
        print("No password given.")
        sys.exit(1)
    return PlaintextMatcher(pw), pw, "plaintext (guessability audit)"


def main() -> int:
    args = build_args().parse_args()

    if args.list_modules:
        print("modules:", ", ".join(modules.names()))
        return 0

    matcher, plaintext, label = resolve_target(args)

    limits = Limits(
        word_cap=args.limit,
        module_budget=args.module_budget,
        global_budget=args.budget,
        chain_vocab=args.chain_vocab,
        chain_words=args.chain_words,
        dob_depth=args.depth,
        pin_six_digit=args.pin6,
    )
    hints = Hints(username=args.user, email=args.email, name=args.name,
                  dob=args.dob, extra=list(args.word))

    ruleset = None
    if args.rules_file:
        try:
            ruleset = rules_engine.load(args.rules_file)
        except OSError as exc:
            print(f"  ! cannot read --rules-file: {exc}")
            return 1

    print(f"\nTarget : {label}")
    print("Loading wordlists...")
    bundle = wordlists.load(DATA_DIR, limits.word_cap, extra=args.wordlist)
    extra_note = f" (+{len(args.wordlist)} custom)" if args.wordlist else ""
    print(f"  {len(bundle):,} unique base words from {DATA_DIR}{extra_note}")

    ctx = CrackContext(matcher=matcher, wordlists=bundle, hints=hints,
                       limits=limits, data_dir=DATA_DIR, plaintext_target=plaintext)

    mods = modules.build(
        only=args.only, skip=args.skip, mode=ctx.mode,
        chain_words=args.chain_words, chain_vocab=args.chain_vocab,
        dob_depth=args.depth,
        mask=args.mask, brute=args.brute, charset=args.charset,
        min_len=args.min_len, max_len=args.max_len,
        ruleset=ruleset, hybrid_mask=args.hybrid_mask,
        hybrid_side=args.hybrid_side, hybrid_vocab=args.hybrid_vocab,
    )
    print(f"Mode   : {ctx.mode}")
    print("Modules:", " -> ".join(m.name for m in mods))
    if ruleset is not None:
        print(f"Rules  : {len(ruleset):,} from {args.rules_file}")
    if hints.tokens():
        print("Hints  :", ", ".join(hints.tokens()))
    if args.dob and hints.dob_parts() is None:
        print(f"  ! --dob {args.dob!r} not understood (try YYYY-MM-DD or DDMMYYYY) "
              "-- date-based attacks disabled")
    print(f"Budgets: {limits.module_budget:,}/module, {limits.global_budget:,} total")
    print(f"Jobs   : {args.jobs}\n")

    result = Runner(mods, ctx, jobs=args.jobs).run()

    print()
    if result.found is not None:
        print(f"  CRACKED: {result.found!r}")
        print(f"  via module '{result.module}', rank #{result.rank:,}, "
              f"{result.elapsed:.1f}s total")
        return 0
    print(f"  NOT FOUND after {result.total_tried:,} candidates in {result.elapsed:.1f}s")
    print("  per-module:")
    for s in result.stats:
        tag = " (budget hit)" if s.budget_hit else ""
        print(f"    {s.name:<12} {s.tried:>12,}  {s.elapsed:6.1f}s{tag}")
    print("  -> not reachable with the enabled attacks; widen with --mask/--brute,"
          " raise --module-budget, or add hints.")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
