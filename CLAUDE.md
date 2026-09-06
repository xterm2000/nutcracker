# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose & scope

Modular dictionary / pattern password cracker — **research & educational use only**.
Pure standard-library Python 3.12 (the parent-folder gotchas about venvs don't apply
here — there are no dependencies to install). Two optional deps, both lazy-imported and
each needed only for one feature: `bcrypt` (`--algo bcrypt`) and `pyzipper` (`--zip` when
the archive uses WinZip AES; ZipCrypto archives need nothing).

## Gotchas / warnings

- Runs on headless VM `shiva` — no display, no browser. Nothing here needs one.
- **Stdlib only.** No `requirements.txt`, no venv. Do not add a dependency without asking.
  The two optional ones are lazy-imported: `bcrypt` inside `HashMatcher` for `--algo
  bcrypt`, `pyzipper` inside `ZipMatcher` for AES `--zip` archives.
- No test suite, no linter, no CI. Verify changes by running `./crack.py` against a known
  target and checking the reported rank/module.
- Git repo initialized 2026-09-03; **no commits yet**, branch `master`.
- `data/*.txt` (~340k lines) are committed inputs — never regenerate them programmatically.
- Global candidate budgets default high (3M/module, 30M total); an unbounded new generator
  can run for minutes before the budget stops it. Keep generators breadth-first.
- `--module-budget` / `--budget` take a size string (`_budget_size` in `crack.py`), not a
  raw int: bare number = millions (`3` -> 3,000,000), or a `k`/`m`/`g` suffix. Write doc/
  Makefile examples in that form, not as raw digit counts.

## Running

```bash
./crack.py -p 'Summer2024!'                       # plaintext guessability audit
./crack.py -p 'mary had a little lamb'            # passphrase / word-chain audit
./crack.py -p 'correcthorsebattery'              # run-together words, no separators
./crack.py --hash <md5hex> --algo md5             # single-hash preimage search
./crack.py --hashfile hashes.txt --algo sha256 --user jsmith --dob 1990-05-01
./crack.py --hash <h> --algo md5 --brute --charset dl --min 4 --max 6
./crack.py -p x --only pins,dates                 # run just some modules
./crack.py -p x --skip wordchain,rules            # or drop some
./crack.py -p 'Password2024!' --rules-file rules/starter.rule   # hashcat-style ruleset
./crack.py -p 'hunter1990' --hybrid-mask '?d?d?d?d'             # word x mask hybrid
./crack.py --hash <h> --algo md5 --wordlist rockyou.txt --rules-file rules/starter.rule
./crack.py --zip secret.zip --word acme --dob 1990-05-01 --jobs 4   # crack a zip password
./crack.py --list-modules
```

There is no build step, no test suite, and no linter configured. To exercise a change,
run `./crack.py` against a known target and confirm the rank/module it reports.

## Target modes

Selected in `crack.py:resolve_target`, surfaced as `ctx.mode` (`"plaintext"` or `"hash"`):

- **plaintext** (`-p` / prompted): `PlaintextMatcher` — candidate `==` the known string.
  A guessability audit that reports *whether* and *at what rank* the enabled attacks reach it.
- **hash** (`--hash` / `--hashfile` + `--algo`): `HashMatcher` — `H(salt_prefix + candidate
  + salt_suffix)` against a set of target digests (any `hashlib` algo), or `bcrypt.checkpw`
  per target. Same candidate generators as a real preimage search.
- **zip** (`--zip PATH`): `ZipMatcher`, `mode = "hash"` — each candidate is tried against a
  password-protected archive. Legacy **ZipCrypto** via stdlib `zipfile`; **WinZip AES** via
  the optional `pyzipper` (lazy import like `bcrypt` — an AES archive with no `pyzipper`
  installed exits with an install hint). Tests the smallest encrypted entry (full read →
  CRC verified, so no ZipCrypto header-check false positive). The archive handle is opened
  lazily *per process* (`_zf` starts `None`) so `--jobs N` gets one handle per fork worker;
  ZipCrypto is pure-Python CPU-bound, so `--jobs` genuinely helps here.

Modules may set `plaintext_only = True` to be skipped in hash mode (none do currently —
`wordchain` instead branches on `ctx.mode` internally: a word-break decomposition of the
known string in plaintext mode, budgeted k-word chain generation in hash mode).

## Architecture

Flow: `crack.py` parses args → builds `CrackContext` → `modules.build()` returns an ordered
module list → `Runner` iterates each module's `generate(ctx)`, testing every candidate against
`ctx.matcher` under budgets.

- **`core/context.py`** — `CrackContext` (shared state: matcher, wordlists, hints, limits,
  data_dir, plaintext_target). `Hints` turns `--user/--email/--name/--dob/--word` into a
  deduped token list (`.tokens()`) and parsed date parts (`.dob_parts()` — accepts
  separated forms *and* bare `DDMMYYYY`/`MMDDYYYY`/`YYYYMMDD` + 6-digit, day-first
  preferred; `crack.py` warns if `--dob` won't parse). `Limits` holds all
  the caps. `CURRENT_YEAR` is defined here and imported widely for year-suffix generation.
- **`core/wordlists.py`** — loads `data/*.txt` in a fixed cheapest-first order (passwords,
  names, intl given names, surnames, tv/film, world cities, wikipedia) into one deduped
  `WordlistBundle`. Files are `word` or
  `word <freq>` per line; only the first token is used. `--limit` caps words *per file*.
  `--wordlist PATH` (repeatable) prepends extra user lists — loaded **before** the built-ins
  so they take priority in `dictionary`/`rules` order (bring your own rockyou / CeWL list).
  The line number within `english_wikipedia.txt` (frequency-sorted) is kept as an
  English-commonness rank — `bundle.is_common(word, cutoff)` — used by `wordchain` to reject
  splits through rare list cruft. The popularity-ordered first-name lists
  (`female_names.txt`, `male_names.txt`, not surnames) are folded into the same rank map
  (best-of), so short first names (`eve`, `ana`, `kim`) count as real segments.
- **`core/matcher.py`** — the three matchers above (`PlaintextMatcher`, `HashMatcher`,
  `ZipMatcher`). Each exposes `.mode` + `.matches(candidate) -> bool` and nothing else.
- **`core/rules_engine.py`** — hashcat-rule parser/applier (`tokenize`, `apply`, `RuleSet`,
  `load`). Used only when `--rules-file` is given; see the `rules` module note below.
- **`core/shapes.py`** — two analysis helpers, advisory only, never touch the result or rank:
  `diagnose(target, hint_tokens)` on a **plaintext** `NOT FOUND` regex-classifies the target
  against weak shapes (word+year, leet, embedded date, keyboard walk, run-together words,
  brute-feasible, …) and prints which knob would reach it (skipped in hash/zip mode);
  `verdict(module, rank, target)` on any `CRACKED` returns a strength tier + per-module
  "what it is" + better-practice tips, printed under the result.
- **`core/term.py`** — muted 256-colour ANSI helper. `configure(mode)` from `--color`
  (`auto`/`always`/`never`, auto = tty and not `NO_COLOR`); style shortcuts
  (`label/ok/warn/bad/accent/dim/head`) return text unchanged when disabled. Imported by
  `crack.py` and `runner.py`.
- **`core/runner.py`** — the pipeline. Per-module budget (`limits.module_budget` or a module's
  own `budget` attr) and a global `limits.global_budget` hard stop. A module raising an
  exception is caught and logged, not fatal. Returns a `Result` (found/module/rank + per-module
  `ModuleStat`s).

## Modules (`modules/`)

Registered in `modules/__init__.py`. Each is a class exposing: `name` (unique), `order` (int,
**lower runs first** — cheapest / highest-value first; the builder sorts by it), and
`generate(ctx)` yielding candidate strings. Optional: `plaintext_only`, `budget`,
`note(ctx)` (advisory string printed before the module runs).

Run order (by `order`, cheap + bounded first, budget-eaters last):
context 3, pins 5, phone 6, sequences 8, keyboard 9, dictionary 10, dates 14,
**wordchain 7** *(plaintext only — the decomposition check is ≤1 candidate)*,
rules 20, dobwords 24, **wordchain 26** *(hash mode — `build(mode=...)` bumps it here so
its k-word-chain keyspace doesn't starve `dictionary`/`rules` of budget)*,
**hybrid 30** *(opt-in — only with `--hybrid-mask`)*, mask 40.

`keyboard` covers QWERTY row/column walks, the curated set (`qwerty`, `1qaz2wsx`, …),
lazy finger-mash repeats (`asdasd`, `qweqwe`, `lkjlkjlkj`), and interleaved
digit / shift-symbol two-liners (`q1w2e3r4`, `Q!W@E#R$`). A few repeat forms overlap
`sequences.REPEAT_UNITS` (`asd`/`qwe`/`zxc`); `sequences` runs first so it wins the rank.

`hybrid` (`modules/hybrid.py`) glues a hashcat mask onto each of the top `--hybrid-vocab`
words (default 2000), both the word and its `.capitalize()` form. `--hybrid-side`
= `append` (`hunter1990`) / `prepend` (`99hunter`) / `both` (default). Word-major so a
budget cut still sweeps the whole mask against the likeliest bases; keyspace =
vocab × mask × sides, printed via `note()`. Appended only when `--hybrid-mask` is given.

`dobwords` is only live when `--dob` is given (yields nothing otherwise). It glues
birthday-derived dates onto known bases — not the exact DOB only but a birthday *window*
(month either side, y±1) plus every-day sweeps of the parent and child years
y-50..y-18 / y+18..y+50 (assuming an 18–50yr age gap), each rendered via `dates.date_forms`.
`--depth` (default 1) controls the structure: **1** = `<hint-token><date>`; **2** = also
`<relation-word><date>[<hint-token>]` (RELWORDS = `mama/papa/baba/…` in several languages —
catches `mama19491604solomakha`); **3** = also `<hint-token><date><hint-token>` and
`<word><word><date>`. `budget` is 6M at depth 1, 25M at depth ≥ 2 (keyspace multiplies
fast, so 2+ is opt-in). `--depth` is plumbed through `Limits.dob_depth` and `modules.build`.

`wordchain` is always appended (supersedes the old `combinator` + `passphrase` modules:
multiple dictionary words concatenated with any separator or none). In plaintext mode
(`decompose` in `modules/wordchain.py`) it word-breaks the *exact* target — near-instant,
rank ~1 if it segments. Two paths: a target with whitespace takes the lenient passphrase
split (any dictionary-derived token, short connectives allowed — the user typed the
boundaries); a target with **no** whitespace must clear a strict gate — every alpha
segment ≥ 4 chars (or 3 chars *and* common per `is_common`, or a 2-char word from a small
connective set), no interior digits (one short trailing number only), ≥ half the letters
in ≥4-char words, bounded part count. This stops the audit tiling a strong password out of
rare 2-3 char fragments (the failure that killed the old accept-anything version). Hint
tokens (`--word/--user/--name/--email`) count as valid segments, so `MitekSintec` cracks
only with `--word Mitek --word Sintec`; a target that is itself a listed word is left to
`dictionary`/`rules`, not re-tiled here. In hash
mode it generates k-word chains (`k = 2..--chain-words`) from the top `--chain-vocab`
words, keyspace ~ Nᵏ, relying on the module budget to cap. `mask` is appended **only** when
`--mask` or `--brute` is given. `--only` / `--skip` filter by `name` after construction.

`rules` runs its **built-in** breadth-first mangle set unless `--rules-file PATH` is given,
in which case that hashcat-style rule file *replaces* the built-in set: raw words first,
then rule-major (each rule applied across every word, so a budget cut leaves the first N
rules fully applied). With a ruleset loaded the module's `budget` is bumped to 25M
(words × rules multiplies fast). The parser lives in **`core/rules_engine.py`** — a
practical subset of hashcat functions (`: l u c C t TN r d f { } [ ] DN 'N pN zN ZN
$X ^X @X sXY iNX oNX xNM k K`), positions in the `0-9A-Z` alphabet, full-line `#`
comments and blank lines skipped, unsupported tokens (reject/memory rules) skipped so
real-world `.rule` files still load. Sample: `rules/starter.rule` (~73 rules).

`modules/rules.py` also provides `mangle(word)` and `leet_variants(word)`, reused by the
`context` and `wordchain` modules — keep mangling logic there rather than duplicating it.

## Conventions

- New attack = new module class in `modules/`, added to `ALWAYS` (and `names()`) in
  `modules/__init__.py`. Pick an `order` that reflects its cost/value relative to the list above.
- Generators should be **breadth-first** where possible (shallow variants for every word before
  deep ones) so a budget cutoff still gives even coverage — see `RulesModule._generate_builtin`.
- `from __future__ import annotations` at the top of every module; `str | None`-style hints.
- Deduplicate within a generator with a local `seen` set + `emit()` helper (pattern used in
  `context`, `rules`).

## Data

`data/` holds the eight plaintext wordlists (~340k lines total), committed to the repo. They are
inputs, not generated — don't rewrite them programmatically.

`rules/` holds committed hashcat-style rule files (`starter.rule`) for `--rules-file`. Also
inputs — hand-maintained, not generated.
