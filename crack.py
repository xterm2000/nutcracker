#!/usr/bin/env python3
"""
Modular dictionary / pattern password cracker -- research & educational use only.

Two target modes:
  * plaintext -- you type a password; the tool reports whether (and at what
                 rank) the enabled attacks would reach it. A guessability audit.
  * hash      -- give a hash (or a file of hashes) + algo; the tool runs the
                 same candidate generators as a real preimage search.

Attacks are pluggable modules in ./modules, run cheapest-first under a budget.

Examples:
  ./crack.py -p 'Summer2024!'
  ./crack.py -p 'mary had a little lamb'
  ./crack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algo md5
  ./crack.py --hashfile hashes.txt --algo sha256 --user jsmith --dob 1990-05-01
  ./crack.py --hash <h> --algo md5 --brute --charset dl --min 4 --max 6
  ./crack.py -p x --only pins,dates          # run just some modules
  ./crack.py -p x --skip combinator,rules    # or drop some
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.context import CrackContext, Hints, Limits
from core.matcher import HashMatcher, PlaintextMatcher
from core import wordlists
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
    lim.add_argument("--combinator-words", type=int, default=800,
                     help="top-N words fed to the combinator (default 800)")
    lim.add_argument("--pin6", action="store_true", help="also sweep the full 6-digit PIN space")
    lim.add_argument("--jobs", type=int, default=1,
                     help="worker processes for testing candidates (default 1 = sequential); "
                          "mainly worth raising for --algo bcrypt")
    return ap


def resolve_target(args):
    """Return (matcher, plaintext_target_or_None, label)."""
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
        combinator_words=args.combinator_words,
        pin_six_digit=args.pin6,
    )
    hints = Hints(username=args.user, email=args.email, name=args.name,
                  dob=args.dob, extra=list(args.word))

    print(f"\nTarget : {label}")
    print("Loading wordlists...")
    bundle = wordlists.load(DATA_DIR, limits.word_cap)
    print(f"  {len(bundle):,} unique base words from {DATA_DIR}")

    ctx = CrackContext(matcher=matcher, wordlists=bundle, hints=hints,
                       limits=limits, data_dir=DATA_DIR, plaintext_target=plaintext)

    mods = modules.build(
        only=args.only, skip=args.skip,
        combinator_words=args.combinator_words,
        mask=args.mask, brute=args.brute, charset=args.charset,
        min_len=args.min_len, max_len=args.max_len,
    )
    print(f"Mode   : {ctx.mode}")
    print("Modules:", " -> ".join(m.name for m in mods))
    if hints.tokens():
        print("Hints  :", ", ".join(hints.tokens()))
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
