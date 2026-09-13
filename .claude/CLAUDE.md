# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose & scope

Modular dictionary / pattern password cracker — **research & educational use only**.
Pure standard-library Python 3.12 (the parent-folder caveats about venvs don't apply
here — there are no dependencies to install). Two optional Python deps, both
lazy-imported and each needed only for one feature: `bcrypt` (`--algo bcrypt`) and
`pyzipper` (`--zip` when the archive uses WinZip AES; ZipCrypto archives need nothing).
Two optional *external binaries* (no package): `gpg` for `--gpg` (symmetric OpenPGP)
and `ssh-keygen` for `--sshkey` (encrypted private key) — the matcher shells out once
per candidate. One optional *integration*, no package: `core/opinion.py` calls a local
**Ollama** over `urllib` when `OLLAMA_MODEL` is set — an LLM second opinion at end of run.

## Caveats / warnings

- Runs on headless VM `shiva` — no display, no browser. Nothing here needs one.
- **Stdlib only.** No `requirements.txt`, no venv. Do not add a dependency without asking.
  The two optional ones are lazy-imported: `bcrypt` inside `HashMatcher` for `--algo
  bcrypt`, `pyzipper` inside `ZipMatcher` for AES `--zip` archives. `core/opinion.py`
  talks to Ollama with **stdlib `urllib` only** (no `ollama` package) — keep it that way.
- **`--gpg` / `--sshkey` are subprocess-per-candidate** (`GpgMatcher` / `SshKeyMatcher`
  in `core/matcher.py`, `mode = "hash"`). A `gpg`/`ssh-keygen` spawn is a ~1-5 ms floor
  and the KDFs (OpenPGP S2K, OpenSSH bcrypt-pbkdf) are slow by design, so only the cheap
  bounded modules (`context`, `pins`, `dictionary`, `rules` at a modest budget) are
  realistic — `--mask`/`--brute` over any real keyspace is not. Each guess has a 10 s
  timeout (a hang = non-match, never a crash). `--jobs N` gives a near-linear speed-up
  (fork workers, one subprocess each — like ZipCrypto). `--gpg` is **symmetric-only**
  (`gpg -c`): a `gpg -e` public-key file or a bare exported secret key can't be attacked
  with a passphrase guess. `--sshkey` requires an *encrypted* key (unencrypted → startup
  error). Crack-time rates live in `core/estimate.py:_ALGO_RATE` (`gpg` 1e7/s GPU,
  `ssh-key` 5e3/s) — order-of-magnitude offline-cracker figures.
- The **Ollama second opinion is opt-in and must stay non-fatal**: off unless `OLLAMA_MODEL`
  is set, and every failure path returns `(None, reason)` — it must never raise or change
  the exit code. In `-p` mode the report sent to Ollama contains the plaintext.
- **Testing caveat:** `crack.py` auto-loads `.env` at startup (`dotenv.load`), so if
  `OLLAMA_MODEL` is set there **every run fires a real inference call at the remote
  Ollama GPU** (`OLLAMA_URL` in `.env` points off-box). When running `./crack.py`
  repeatedly to verify a change, prefix `OLLAMA_MODEL= ` to suppress the opinion call —
  don't hammer the GPU.
- No test suite, no linter, no CI. Verify changes by running `OLLAMA_MODEL= ./crack.py`
  against a known target and checking the reported rank/module.
- `crack.py` exit codes: **0** cracked, **1** real error, **2** bad CLI args (argparse),
  **3** NOT FOUND in budget. `test.sh` mirrors them; the `Makefile` run-a-crack targets
  (`run`/`audit`/`script`) treat 3 as success via `$(call keep3)` but still fail on 1/2.
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
./crack.py --gpg secret.txt.gpg --jobs 4 --only context,pins,dictionary,rules   # symmetric OpenPGP
./crack.py --sshkey id_ed25519 --wordlist rockyou.txt --jobs 4     # SSH key passphrase
./crack.py -p 'hey jimmy barbecue' --name 'Jimmy Barbeque' --permute   # known words, any order
OLLAMA_MODEL=llama3.2 ./crack.py -p 'Summer2024!'   # + local-LLM opinion (env-gated, opt-in)
./crack.py --list-modules
```

Output per run: a `RUN` table (config), per-module progress with `module N% / total N%`,
a `SUMMARY` table (result / guesses / crack-time ladder / assessment), tips or the
NOT-FOUND strength estimate, and — if `OLLAMA_MODEL` set — an `LLM OPINION` panel.
`test.sh` exposes every `crack.py` flag + the `OLLAMA_*` vars as `${VAR:-default}` knobs.

There is no build step, no test suite, and no linter configured. To exercise a change,
run `./crack.py` against a known target and confirm the rank/module it reports.

## Target modes

Selected in `crack.py:resolve_target`, surfaced as `ctx.mode` (`"plaintext"` or `"hash"` —
zip/gpg/sshkey all report `"hash"`):

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
- **gpg** (`--gpg PATH`): `GpgMatcher`, `mode = "hash"`, `algo = "gpg"` — each candidate
  is a `gpg --batch --pinentry-mode loopback --passphrase … --decrypt` child; return 0 =
  hit. **Symmetric OpenPGP only** (`gpg -c`): a public-key (`gpg -e`) file or a bare
  exported secret key can't be attacked this way. Needs `gpg`/`gpg2` on PATH (missing →
  `SystemExit` with an install hint). 10 s per-guess timeout. Subprocess-bound → keep to
  cheap modules + small `--module-budget`, raise `--jobs`.
- **sshkey** (`--sshkey PATH`): `SshKeyMatcher`, `mode = "hash"`, `algo = "ssh-key"` —
  each candidate runs `ssh-keygen -y -P <cand> -f KEY` (return 0 = hit; writes nothing).
  Startup probe with the empty passphrase rejects an unencrypted key. Modern OpenSSH
  format + legacy PEM both work; bcrypt-pbkdf is very slow, so same guidance as `--gpg`.

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
  (best-of), so short first names (`eve`, `ana`, `kim`) count as real segments — but
  a second map `english_rank` keeps the `english_wikipedia.txt` order *without* names,
  and `bundle.common_words(n)` returns the top-n by that (used for `wordchain`'s
  hash-mode vocab, where names would be noise). `bundle.position(word)` gives the
  1-based load-order index of a word (cached) — how many guesses a wordlist attack
  spends before reaching it, used by `wordchain.estimate_guesses`.
- **`core/matcher.py`** — the five matchers above (`PlaintextMatcher`, `HashMatcher`,
  `ZipMatcher`, `GpgMatcher`, `SshKeyMatcher`). Each exposes `.mode` + `.matches(candidate)
  -> bool` (`HashMatcher`/`GpgMatcher`/`SshKeyMatcher` also carry an `.algo` string the
  estimate/crack-time code reads — `"gpg"` / `"ssh-key"` map to rates in `estimate.py`).
- **`core/rules_engine.py`** — hashcat-rule parser/applier (`tokenize`, `apply`, `RuleSet`,
  `load`). Used only when `--rules-file` is given; see the `rules` module note below.
- **`core/shapes.py`** — two analysis helpers, advisory only, never touch the result or rank:
  `diagnose(target, hint_tokens)` on a **plaintext** `NOT FOUND` regex-classifies the target
  against weak shapes (word+year, leet, embedded date, keyboard walk, run-together words,
  brute-feasible, …) and prints which knob would reach it (skipped in hash/zip mode);
  `verdict(module, guesses, target)` on any `CRACKED` returns a strength tier + per-module
  "what it is" + better-practice tips, printed under the result (`crack.py` feeds it the
  guess estimate below, not the raw rank).
- **`core/estimate.py`** — guess-count → wall-clock. `crack_time(guesses, algo=, zip_mode=)`
  returns `(label, human_time)` rows for a ladder of attack scenarios (throttled online,
  unthrottled, bcrypt-rate offline, fast-hash GPU rig, + the target's own algo in hash mode);
  `exhaust_note(keyspace, ctx)` is the short "N to exhaust vs md5" tail the opt-in modules
  (`mask`, `hybrid`, `fuzz`, `permute`) append to their `note()`. Rates are order-of-magnitude
  (`_ALGO_RATE`). `crack.py` prints the `crack_time` table under every `CRACKED`; the guess
  count is the cracking module's own local hit position (`result.stats[-1].tried`), except
  `wordchain` plaintext which supplies `estimate_guesses(ctx, found)` (∏ segment wordlist
  positions × separators) since its decomposition only ever yields one candidate.
  On `NOT FOUND`, `not_found_report(plaintext, tried, algo=, zip_mode=, weak_shape=)` prints a
  **lower bound** (candidates survived → time at a slow vs fast hash, both modes) and, in
  plaintext mode only, an honest **upper bound** — `brute_keyspace()` (char-pool ** length,
  the zxcvbn-style ceiling), annotated "reachable, not strong" when the shape analysis flagged
  a pattern (`weak_shape`, derived from `diagnose()`'s last line). Hash mode gets the floor
  only — no string, no structure estimate.
- **`core/opinion.py`** — optional LLM second opinion. `consult(report)` POSTs the run's
  report text to a local **Ollama** (`/api/chat` or `/api/generate` per `OLLAMA_URL`,
  `format: json`, pure `urllib` — no `ollama` package) and returns
  `({verdict, crack_time, opinion, model}, None)` or `(None, reason)`; never raises, so a
  missing/broken Ollama can't change the exit code. **Off unless `OLLAMA_MODEL` is set**
  (`enabled()`); other env: `OLLAMA_URL` (full endpoint, wins) / `OLLAMA_HOST` (bare
  host/IP ok, default `localhost:11434`), `OLLAMA_TEMPERATURE`, `OLLAMA_TIMEOUT`,
  `OLLAMA_NUM_CTX` — all also loadable from a gitignored `.env` (`core/dotenv.py`, real
  env wins). The model returns three keys (`_FIELDS`): a one-word `verdict`, a short
  `crack_time` phrase, and a free-text `opinion` paragraph — the report it's sent includes
  the tool's own crack-time ladder and it's told to say whether those figures hold.
  `crack.py`'s `_second_opinion(report, subject)` calls it at the very end of both the
  CRACKED and NOT FOUND paths and prints the opinion as a bordered `term.panel` headed by
  the target, the model name, a colour-coded verdict and the model's `~crack_time`.
  In `-p` mode the report includes the plaintext, so it goes to whatever `OLLAMA_URL` /
  `OLLAMA_HOST` points at (localhost by default).
- **`core/term.py`** — muted 256-colour ANSI helper. `configure(mode)` from `--color`
  (`auto`/`always`/`never`, auto = tty and not `NO_COLOR`); style shortcuts
  (`label/ok/warn/bad/accent/dim/head`) return text unchanged when disabled. Also
  `table(rows, title=, kw=, vw=)` — a plain-ASCII box table from `(key, value)` pairs
  (values wider than `vw` truncated with `~`), used for the `RUN` / `SUMMARY` /
  `per-module` tables `crack.py` prints, and `panel(body, title=, width=)` — a bordered
  box that word-wraps free text under an optional header row (the header keeps its own
  ANSI, measured by visible width), used for the `LLM OPINION`. Imported by `crack.py`
  and `runner.py`.
- **`core/runner.py`** — the pipeline. Per-module budget (`limits.module_budget` or a module's
  own `budget` attr) and a global `limits.global_budget` hard stop. A module raising an
  exception is caught and logged, not fatal. Returns a `Result` (found/module/rank + per-module
  `ModuleStat`s). Logs one `each step:` line up front (`_target_clause()` — how every candidate
  is checked: plaintext compare / `md5` digest vs N hashes / zip password), a `trying <plain
  description>` line per module (`_MODULE_ACTION`), and progress via `_Progress`, which doubles
  its print interval every 5 lines (announcing each reduction) so a 25M-candidate module logs a
  handful of lines, not 25. Each progress line and the per-module `done:` line show
  `module N% / total N%` (progress through this module's effective budget and the global
  budget). `_Progress` is shared with `core/parallel.py` (passed in as `progress=`).

## Modules (`modules/`)

Registered in `modules/__init__.py`. Each is a class exposing: `name` (unique), `order` (int,
**lower runs first** — cheapest / highest-value first; the builder sorts by it), and
`generate(ctx)` yielding candidate strings. Optional: `plaintext_only`, `budget`,
`note(ctx)` (advisory string printed before the module runs).

Run order (by `order`, cheap + bounded first, budget-eaters last):
context 3, pins 5, phone 6, **bip39 7**, **wordchain 7**, sequences 8, keyboard 9,
dictionary 10, **permute 12** *(opt-in — only with `--permute`)*, dates 14,
*(bip39 & wordchain 7 are plaintext-mode: a decomposition check, ≤1 candidate;
bip39 is appended first so it claims the rank for an all-BIP-39 phrase)*,
rules 20, **fuzz 22** *(opt-in — only with `--fuzz`)*, dobwords 24,
**wordchain 26 / bip39 27** *(hash mode — `build(mode=...)` bumps both here so their
k-word-chain keyspaces don't starve `dictionary`/`rules` of budget)*,
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

`fuzz` (`modules/fuzz.py`) is opt-in via `--fuzz N` (N clamped to 1–2). It yields the
top `--fuzz-vocab` words (default 2000) *plus the hint tokens* with up to N
single-character substitutions — length-preserving, i.e. Hamming distance ≤ N — the
one gap `rules`/`leet_variants` leave (an arbitrary non-leet swap, an embedded typo).
`--fuzz-charset`: `sub` (default, `a–z0–9!@#$%`), `kbd` (keyboard-adjacent keys only,
from a QWERTY-grid adjacency map built at import), a `mask.CHARSETS` spec, or a literal
string. Variants already in the wordlist are skipped (`dictionary` covers them);
breadth-first over (position-combos, then words) so a budget cut keeps even coverage.
Keyspace ≈ vocab × L × (A−1) at N=1; N=2 multiplies by `C(L,2)·(A−1)` so it bumps its
own `budget` to 25M and still wants `--fuzz-vocab` in the low hundreds. `note()` prints
the estimate. Plumbed through `modules.build(fuzz=, fuzz_vocab=, fuzz_charset=)`.

`permute` (`modules/permute.py`) is opt-in via `--permute`. It takes the hint
tokens (`--word`/`--name`/`--user`/`--email`, via `ctx.hints.tokens()`, capped at
8 to bound the factorial), tries them in **every order**, glued with each
separator (`--permute-sep`, default `none,space,-,_,.`), in plain + Capitalised
(+ UPPER/lower with `cases="all"`) forms. `--permute-fill N` (0–2) additionally
inserts `N` unknown slots drawn from `bundle.common_words(--permute-vocab)`
(default top 200, frequency-ordered) — filler-major so the likeliest missing
words sweep every arrangement first; `budget` bumps to 25M when fill ≥ 1.
Keyspace = `perm(t+fill) × seps × cases × vocab^fill`; `note()` prints it. Fills
the "I know most of a passphrase but not the word order / am missing a word or
two" gap that `context` (pairs only) and hash-mode `wordchain` (ignores hints)
leave. Plumbed through `modules.build(permute=, permute_seps=, permute_fill=,
permute_vocab=)`.

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
words **by English frequency** (`bundle.common_words()` — `english_rank`, the
`english_wikipedia.txt` line order with name lists excluded, *not* the merged
load-order `top()` which front-loads breach passwords). Keyspace ~ Nᵏ, module
budget caps it; k=2 pairs use the full `GLUE` set (`''`/`' '` first), k≥3 only
`''`/`' '`/`'.'`. This reaches 2-word (and short 3-word) common-English
passphrases; a long passphrase stays out of reach (correctly) — use `--wordlist`
with a phrase list for known quotes. `mask` is appended **only** when `--mask` or
`--brute` is given. `--only` / `--skip` filter by `name` after construction.

`bip39` (`modules/bip39.py`, always appended) reads the target as a sequence of
words from the 2048-word BIP-39 English list (`data/bip39.txt`, one word/line;
missing file → module inactive). Plaintext: a fewest-parts word-break of the
exact target (whitespace form or run-together), ≥2 words → reported;
`estimate_guesses` returns `2048**words × seps` — a real 12/15/18/21/24-word seed
lands here as **strong** (out of brute-force reach), a 2-4 word "clever"
passphrase as very weak / weak. Hash mode: breadth-first k=2..4 chains from the
2048 words (`_GEN_SEPS` = `' '`/`''`/`'-'`; k≥3 only `' '`/`''`), `budget` 8M.
`shapes.verdict` has a `bip39` branch that tiers on the real keyspace, not the
within-budget rank. Runs at order 7 just before `wordchain` so an all-BIP-39
phrase is attributed to `bip39`; `wordchain` still handles phrases with any
non-BIP-39 word.

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

`data/` holds the eight general wordlists (~340k lines total) loaded by
`core/wordlists.py`, plus `bip39.txt` (the 2048-word BIP-39 English list, used
only by the `bip39` module). All committed inputs, not generated — don't rewrite
them programmatically.

`rules/` holds committed hashcat-style rule files (`starter.rule`) for `--rules-file`. Also
inputs — hand-maintained, not generated.
