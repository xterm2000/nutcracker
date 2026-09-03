# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose & scope

Modular dictionary / pattern password cracker — **research & educational use only**.
Pure standard-library Python 3.12 (the parent-folder gotchas about venvs don't apply
here — there are no dependencies to install). The only optional dependency is `bcrypt`,
imported lazily and only when `--algo bcrypt` is used.

## Gotchas / warnings

- Runs on headless VM `shiva` — no display, no browser. Nothing here needs one.
- **Stdlib only.** No `requirements.txt`, no venv. Do not add a dependency without asking;
  `bcrypt` is the sole optional one and is imported lazily inside `HashMatcher` only for
  `--algo bcrypt`.
- No test suite, no linter, no CI. Verify changes by running `./crack.py` against a known
  target and checking the reported rank/module.
- Git repo initialized 2026-09-03; **no commits yet**, branch `master`.
- `data/*.txt` (~280k lines) are committed inputs — never regenerate them programmatically.
- Global candidate budgets default high (3M/module, 30M total); an unbounded new generator
  can run for minutes before the budget stops it. Keep generators breadth-first.

## Running

```bash
./crack.py -p 'Summer2024!'                       # plaintext guessability audit
./crack.py -p 'mary had a little lamb'            # passphrase audit
./crack.py --hash <md5hex> --algo md5             # single-hash preimage search
./crack.py --hashfile hashes.txt --algo sha256 --user jsmith --dob 1990-05-01
./crack.py --hash <h> --algo md5 --brute --charset dl --min 4 --max 6
./crack.py -p x --only pins,dates                 # run just some modules
./crack.py -p x --skip combinator,rules           # or drop some
./crack.py --list-modules
```

There is no build step, no test suite, and no linter configured. To exercise a change,
run `./crack.py` against a known target and confirm the rank/module it reports.

## Two target modes

Selected in `crack.py:resolve_target`, surfaced as `ctx.mode` (`"plaintext"` or `"hash"`):

- **plaintext** (`-p` / prompted): `PlaintextMatcher` — candidate `==` the known string.
  A guessability audit that reports *whether* and *at what rank* the enabled attacks reach it.
- **hash** (`--hash` / `--hashfile` + `--algo`): `HashMatcher` — `H(salt_prefix + candidate
  + salt_suffix)` against a set of target digests (any `hashlib` algo), or `bcrypt.checkpw`
  per target. Same candidate generators as a real preimage search.

Modules with `plaintext_only = True` (currently only `passphrase`) are skipped in hash mode.

## Architecture

Flow: `crack.py` parses args → builds `CrackContext` → `modules.build()` returns an ordered
module list → `Runner` iterates each module's `generate(ctx)`, testing every candidate against
`ctx.matcher` under budgets.

- **`core/context.py`** — `CrackContext` (shared state: matcher, wordlists, hints, limits,
  data_dir, plaintext_target). `Hints` turns `--user/--email/--name/--dob/--word` into a
  deduped token list (`.tokens()`) and parsed date parts (`.dob_parts()`). `Limits` holds all
  the caps. `CURRENT_YEAR` is defined here and imported widely for year-suffix generation.
- **`core/wordlists.py`** — loads `data/*.txt` in a fixed cheapest-first order (passwords,
  names, surnames, tv/film, wikipedia) into one deduped `WordlistBundle`. Files are `word` or
  `word <freq>` per line; only the first token is used. `--limit` caps words *per file*.
- **`core/matcher.py`** — the two matchers above.
- **`core/runner.py`** — the pipeline. Per-module budget (`limits.module_budget` or a module's
  own `budget` attr) and a global `limits.global_budget` hard stop. A module raising an
  exception is caught and logged, not fatal. Returns a `Result` (found/module/rank + per-module
  `ModuleStat`s).

## Modules (`modules/`)

Registered in `modules/__init__.py`. Each is a class exposing: `name` (unique), `order` (int,
**lower runs first** — cheapest / highest-value first; the builder sorts by it), and
`generate(ctx)` yielding candidate strings. Optional: `plaintext_only`, `budget`,
`note(ctx)` (advisory string printed before the module runs).

Run order today (by `order`): context 3, passphrase 5, phone 6, pins 8, dictionary 10,
sequences 12, keyboard 13, dates 15, rules 20, combinator 30, mask 40.

`combinator` is always appended (keyspace ~ N² · len(GLUE), N = `--combinator-words`, relies
on the module budget to cap). `mask` is appended **only** when `--mask` or `--brute` is given.
`--only` / `--skip` filter by `name` after construction.

`modules/rules.py` also provides `mangle(word)` and `leet_variants(word)`, reused by the
`context` and `passphrase` modules — keep mangling logic there rather than duplicating it.

## Conventions

- New attack = new module class in `modules/`, added to `ALWAYS` (and `names()`) in
  `modules/__init__.py`. Pick an `order` that reflects its cost/value relative to the list above.
- Generators should be **breadth-first** where possible (shallow variants for every word before
  deep ones) so a budget cutoff still gives even coverage — see the ordering in `RulesModule.generate`.
- `from __future__ import annotations` at the top of every module; `str | None`-style hints.
- Deduplicate within a generator with a local `seen` set + `emit()` helper (pattern used in
  `context`, `rules`).

## Data

`data/` holds the six plaintext wordlists (~280k lines total), committed to the repo. They are
inputs, not generated — don't rewrite them programmatically.
