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
  * gpg       -- give a symmetric (`gpg -c`) OpenPGP file; each candidate is
                 tried as the passphrase via the system `gpg`. Hash-mode
                 selection. Slow (one gpg per guess) -- cheap modules only.
  * sshkey    -- give an encrypted OpenSSH / PEM private key; each candidate is
                 tried via `ssh-keygen -y`. Hash-mode selection. Slow.

Attacks are pluggable modules in ./modules, run cheapest-first under a budget.

Examples:
  ./crack.py -p 'Summer2024!'
  ./crack.py -p 'mary had a little lamb'
  ./crack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algo md5
  ./crack.py --hashfile hashes.txt --algo sha256 --user jsmith --dob 1990-05-01
  ./crack.py --zip secret.zip --word acme --dob 1990-05-01 --jobs 4
  ./crack.py --gpg secret.txt.gpg --word acme --jobs 4        # symmetric OpenPGP
  ./crack.py --sshkey id_ed25519 --wordlist rockyou.txt --jobs 4
  ./crack.py --hash <h> --algo md5 --brute --charset dl --min 4 --max 6
  ./crack.py -p 'Password2024!' --rules-file rules/starter.rule
  ./crack.py -p 'hunter1990' --hybrid-mask '?d?d?d?d'
  ./crack.py -p 'passwyrd' --fuzz 1                  # dictionary word, 1 char off
  ./crack.py --hash <h> --algo sha1 --wordlist rockyou.txt --rules-file rules/starter.rule
  ./crack.py -p x --only pins,dates          # run just some modules
  ./crack.py -p x --skip wordchain,rules     # or drop some
  OLLAMA_MODEL=llama3.2 ./crack.py -p x      # + a local-LLM second opinion (env-gated)
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.context import CrackContext, Hints, Limits
from core.matcher import (
    GpgMatcher, HashMatcher, PlaintextMatcher, SshKeyMatcher, ZipMatcher,
)
from core import dotenv, estimate, opinion, rules_engine, shapes, term, wordlists
import modules
from core.runner import Runner

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _csv(s):
    return [x.strip() for x in s.split(",") if x.strip()]


def _seps(s):
    """Parse a --permute-sep list: 'space'/'sp' -> ' ', 'none'/'' -> '', else literal."""
    out = []
    for tok in s.split(","):
        t = tok.strip()
        out.append(" " if t in ("space", "sp") else "" if t in ("none", "nil", "") else t)
    return out


def _budget_size(s):
    """Parse a candidate-budget size: bare number = millions ('12' -> 12,000,000);
    'k'/'m'/'g' suffix picks the unit explicitly ('500k' -> 500,000)."""
    s = s.strip().lower()
    mult = 1_000_000
    if s and s[-1] in "kmg":
        mult = {"k": 1_000, "m": 1_000_000, "g": 1_000_000_000}[s[-1]]
        s = s[:-1]
    return int(float(s) * mult)


_VERDICT_COLOUR = {
    "trivial": "bad", "weak": "bad",
    "moderate": "warn", "fair": "warn",
    "strong": "ok", "excellent": "ok",
}


def _second_opinion(report_lines: list[str], subject: str) -> None:
    """Hand the finished report to a local Ollama model (if OLLAMA_MODEL is set)
    and print its free-text opinion in a bordered panel headed by the target,
    the model name and a colour-coded verdict. Silent one-liner when disabled;
    never fatal -- a broken/absent Ollama must not change the exit code."""
    if not opinion.enabled():
        return
    report = "\n".join(report_lines)
    print(term.dim("\n  asking the local model for a second opinion..."))
    data, err = opinion.consult(report)
    if not data:
        print(term.dim(f"  llm opinion unavailable -- {err}"))
        return
    verdict = (data.get("verdict") or "?").strip()
    colour = _VERDICT_COLOUR.get(verdict.lower(), "accent")
    sep = f"   {term.dim('|')}   "
    parts = [subject, data.get("model", "?"), term.style(verdict.upper(), colour)]
    crack_time = (data.get("crack_time") or "").strip()
    if crack_time:
        parts.append(term.style(f"~{crack_time}", colour))
    print(term.panel(data.get("opinion") or "(no opinion returned)",
                     title=sep.join(parts), width=76))


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
    tgt.add_argument("--gpg", dest="gpg_", metavar="PATH",
                     help="symmetric OpenPGP file (gpg -c) to crack -- needs the "
                          "system 'gpg'; slow (one gpg per guess), use --jobs N")
    tgt.add_argument("--sshkey", dest="sshkey_", metavar="PATH",
                     help="encrypted OpenSSH / PEM private key to crack -- needs "
                          "'ssh-keygen'; slow (bcrypt-pbkdf), use --jobs N")
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

    fz = ap.add_argument_group("fuzz (opt-in, adds the fuzz module)")
    fz.add_argument("--fuzz", type=int, choices=(1, 2), metavar="N",
                    help="dictionary words with up to N single-char substitutions "
                         "(Hamming distance <= N); N=2 is much larger, use a small vocab")
    fz.add_argument("--fuzz-vocab", type=int, default=2000,
                    help="top-N words fuzzed, plus the hint tokens (default 2000)")
    fz.add_argument("--fuzz-charset", default="sub", metavar="SPEC",
                    help="substitution alphabet: 'sub' (a-z0-9!@#$%%, default), "
                         "'kbd' (keyboard-adjacent keys only), a mask spec (l/d/u/s/a), "
                         "or a literal string of characters")

    pm = ap.add_argument_group("permute (opt-in, adds the permute module)")
    pm.add_argument("--permute", action="store_true",
                    help="try the known --word/--name/--user tokens in every order, "
                         "glued with each separator (known-words / unknown-order passphrase)")
    pm.add_argument("--permute-sep", type=_seps, default=None, metavar="LIST",
                    help="separator list, e.g. 'none,space,-,_,.' (default: none,space,-,_,.)")
    pm.add_argument("--permute-fill", type=int, choices=(0, 1, 2), default=0,
                    help="also fill N unknown slots from the top common English words "
                         "(default 0; >0 is much larger)")
    pm.add_argument("--permute-vocab", type=int, default=200,
                    help="top-N common words used for --permute-fill slots (default 200)")

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

    out = ap.add_argument_group("output")
    out.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                     help="colourise output (default auto: on when stdout is a terminal; "
                          "also honours NO_COLOR)")
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

    if args.gpg_:
        try:
            m = GpgMatcher(args.gpg_)
        except (OSError, ValueError) as exc:
            print(f"  ! --gpg: {exc}")
            sys.exit(1)
        return m, None, f"symmetric OpenPGP file {os.path.basename(args.gpg_)}"

    if args.sshkey_:
        try:
            m = SshKeyMatcher(args.sshkey_)
        except (OSError, ValueError) as exc:
            print(f"  ! --sshkey: {exc}")
            sys.exit(1)
        return m, None, f"encrypted private key {os.path.basename(args.sshkey_)}"

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
    # a project .env feeds the optional OLLAMA_* knobs; real env vars still win
    dotenv.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    args = build_args().parse_args()
    term.configure(args.color)

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

    D = term.dim

    print(D("\nLoading wordlists..."))
    bundle = wordlists.load(DATA_DIR, limits.word_cap, extra=args.wordlist)
    extra_note = f" (+{len(args.wordlist)} custom)" if args.wordlist else ""

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
        fuzz=args.fuzz, fuzz_vocab=args.fuzz_vocab, fuzz_charset=args.fuzz_charset,
        permute=args.permute, permute_seps=args.permute_sep,
        permute_fill=args.permute_fill, permute_vocab=args.permute_vocab,
    )
    crows = [
        ("target", label),
        ("mode", ctx.mode),
        ("wordlist", f"{len(bundle):,} unique base words{extra_note}"),
        ("modules", f"{len(mods)} enabled"),
    ]
    if ruleset is not None:
        crows.append(("rules", f"{len(ruleset):,} from {args.rules_file}"))
    if hints.tokens():
        crows.append(("hints", ", ".join(hints.tokens())))
    crows.append(("budgets", f"{limits.module_budget:,}/module   "
                             f"{limits.global_budget:,} total"))
    crows.append(("jobs", str(args.jobs)))
    print(term.table(crows, title="RUN", kw=16))
    print(D("  " + " -> ".join(m.name for m in mods)))
    if args.dob and hints.dob_parts() is None:
        print(term.warn(f"  ! --dob {args.dob!r} not understood (try YYYY-MM-DD or DDMMYYYY) "
                        "-- date-based attacks disabled"))
    print()

    result = Runner(mods, ctx, jobs=args.jobs).run()

    print()
    algo = getattr(matcher, "algo", None)
    zip_mode = matcher.__class__.__name__ == "ZipMatcher"

    if result.found is not None:
        # guesses: the cracking module's own local hit position is the fair
        # single-technique figure. wordchain's plaintext decomposition yields
        # just one candidate, so ask the module for a real estimate instead.
        guesses = result.stats[-1].tried if result.stats else (result.rank or 1)
        gnote = None
        mod_inst = next((m for m in mods if m.name == result.module), None)
        est_fn = getattr(mod_inst, "estimate_guesses", None)
        if est_fn:
            try:
                got = est_fn(ctx, result.found)
            except Exception:
                got = None
            if got:
                guesses, gnote = got

        vline, tips = shapes.verdict(result.module, int(guesses),
                                     result.found, limits.global_budget)

        rows = [
            ("result", "CRACKED"),
            ("password", repr(result.found)),
            ("via", f"{result.module}  (rank #{result.rank:,})"),
            ("guesses", f"{estimate.human_count(guesses)}  ({int(guesses):,})"),
        ]
        for _long, short, human in estimate.crack_time(guesses, algo=algo,
                                                       zip_mode=zip_mode):
            rows.append((f"vs {short}", human))
        rows.append(("assessment", vline))
        rows.append(("elapsed", f"{result.elapsed:.1f}s total"))
        print(term.table(rows, title="SUMMARY", kw=16))

        if gnote:
            print(D(f"  guess estimate = {gnote}"))
        print(D("  do better:"))
        for tip in tips:
            print(f"    {D('-')} {tip}")

        _second_opinion([f"{k}: {v}" for k, v in rows]
                        + [f"tip: {t}" for t in tips],
                        subject=repr(result.found))
        return 0

    findings = shapes.diagnose(plaintext, hints.tokens()) if plaintext is not None else []
    weak_shape = bool(findings) and not any(
        p in findings[-1] for p in ("strong password", "no known weak shape"))

    nrows = [
        ("result", "NOT FOUND"),
        ("mode", ctx.mode),
        ("tried", f"{result.total_tried:,} candidates"),
        ("elapsed", f"{result.elapsed:.1f}s"),
    ]
    print(term.table(nrows, title="SUMMARY", kw=16))

    mrows = [(s.name, f"{s.tried:>13,}   {s.elapsed:6.1f}s"
              + ("   budget hit" if s.budget_hit else ""))
             for s in result.stats]
    if mrows:
        print(term.table(mrows, title="per-module", kw=16))

    if findings:
        print(D("  shape analysis (why the enabled attacks may have missed it):"))
        for f in findings:
            print(f"    {D('-')} {f}")

    est_lines = estimate.not_found_report(plaintext, result.total_tried, algo=algo,
                                          zip_mode=zip_mode, weak_shape=weak_shape)
    print(D("  strength estimate (rough -- a NOT FOUND is a floor, not proof):"))
    for line in est_lines:
        print(f"    {D('-')} {line}")
    print(D("  -> widen with --mask / --brute, raise --module-budget, or add hints."))

    subject = repr(plaintext) if plaintext is not None else f"{algo or 'hash'} target"
    _second_opinion([f"{k}: {v}" for k, v in nrows]
                    + [f"shape: {f}" for f in findings]
                    + [f"estimate: {ln}" for ln in est_lines]
                    + (["target plaintext: " + repr(plaintext)] if plaintext else []),
                    subject=subject)
    return 3  # distinct from 1 (real error) and argparse's 2 (usage error)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
