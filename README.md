# password

A modular dictionary / pattern password cracker. **Research & educational use only** —
use it to audit the guessability of passwords you are authorised to test.

Pure Python 3.12 standard library. The only optional dependency is `bcrypt`
(`pip install bcrypt`), needed solely for `--algo bcrypt`.

```bash
./crack.py -p 'Summer2024!'
```

---

## How it works

The tool has **three target modes**:

| Mode | How you invoke it | What it tells you |
|------|-------------------|-------------------|
| **plaintext** (guessability audit) | `-p PASSWORD` (or prompt) | *whether* the enabled attacks reach the password, which module found it, and at what **rank** (how many guesses in) |
| **hash** (preimage search) | `--hash HEX` / `--hashfile FILE` + `--algo` | runs the same candidate generators as a real cracking run against your hash(es) |
| **zip** (archive password) | `--zip archive.zip` | tries each candidate as the archive password (ZipCrypto built in; WinZip AES needs `pip install pyzipper`) |

Candidates come from pluggable **modules** in `modules/`, run cheapest-first under a
per-module budget (default 3M candidates) and a global hard stop (default 30M). Each
module is a focused generator: PINs, dates, keyboard walks, dictionary + mangling
rules (built-in or a hashcat `.rule` file), multi-word chains, hint-based guesses,
word×mask hybrids, masks/brute force, etc.

```
./crack.py --list-modules
```

Run order (cheapest / highest-value first, budget-eaters last):
`context → pins → phone → sequences → keyboard → dictionary → dates → rules →
dobwords → wordchain → hybrid → mask`. (`wordchain`'s plaintext decomposition runs
early, at rank ~1; its hash-mode generator runs late. `dobwords` only does anything
with `--dob`; `hybrid` only with `--hybrid-mask`; `mask` only with `--mask`/`--brute`.)

Wordlists live in `data/` (passwords, first names, international given names,
surnames, TV/film, world cities, English Wikipedia — ~240k unique words after
de-dup).

---

## Cookbook

### Choosing an attack — what to reach for

Two things decide everything: **what you have** (a plaintext to audit, or a hash to
break) and **what you know about the owner**. Start narrow with what you know, then
widen.

#### Plaintext vs hash

|  | plaintext (`-p`) | hash (`--hash` / `--hashfile`) |
|---|---|---|
| Answers | *at what rank* this would be guessed | *what* the password behind the digest is |
| Cost per candidate | one `==` — effectively free | one hash; md5/sha fast, **bcrypt slow → add `--jobs N`** |
| Budgets | rarely bite; the audit resolves fast | the real constraint — raise `--module-budget` / `--budget`, or narrow with `--only` |
| `wordchain` | word-*breaks* the exact string (rank ~1 if it segments) | *generates* k-word chains — tune `--chain-words`, `--chain-vocab` |
| First move | just run it, no flags | add every hint you have, *then* widen |

`--zip archive.zip` is a third mode that behaves like **hash** for module selection
(same generators, budgets, `--jobs`); it just tests candidates against the archive
instead of a digest. ZipCrypto is built in; WinZip AES needs `pip install pyzipper`.

#### What do you know about the target?

| You know… | Reach for | Notes |
|---|---|---|
| nothing | default run | every module, cheapest-first — the baseline |
| it's a phrase / several words | `wordchain` (automatic) | keep the spaces if you know them (lenient split); run-together must pass the strict gate |
| real name / username / email | `--name` / `--user` / `--email` → `context` | tokens get mangled, glued, date-suffixed |
| date of birth | `--dob` → `dates` + `dobwords` | `dobwords` also sweeps parent/child birth years; `--depth 2` for `mama<date>…` shapes |
| pet / employer / team / kids' names | `--word X --word Y` (repeatable) | fed to `context` **and** accepted as a `wordchain` segment |
| the *shape*, e.g. `Xxxxx9999` | `--mask '?u?l?l?l?l?d?d?d?d'` | exact length; literals pass through (`Acme?d?d?d`) |
| a word + an unknown numeric tail | `--hybrid-mask '?d?d?d?d'` | top words × mask; `--hybrid-side prepend` for `99word` |
| you have a better wordlist (rockyou, CeWL scrape, breach dump) | `--wordlist FILE` | loaded first → priority in `dictionary` / `rules` |
| a rockyou-style / policy-specific ruleset | `--rules-file rules/starter.rule` | any hashcat `.rule`; **replaces** built-in mangling |
| nothing, and you'll pay for brute force | `--brute --charset … --min --max` | last resort; keyspace printed up front |

#### Module quick-reference

| Module | Use it for | Don't bother when |
|---|---|---|
| `context` | any run where you passed `--name/--user/--email/--word/--dob` | no hints (it yields nothing) |
| `pins` | 4–6 digit numeric codes | the target has letters |
| `phone` | a value that could be a phone number | — |
| `sequences` | `123456`, `abcabc`, `aaaa`, doubled words | — |
| `keyboard` | `qwerty`, `1qaz2wsx`, `asdasd`, `Q!W@E#R$` | — |
| `dictionary` | the plain word, unchanged | — (it's cheap) |
| `dates` | bare years, `DDMMYYYY`, `Summer2024`, month names | no date component expected |
| `rules` | word + case / leet / digits / years — the common human pattern | — (supply `--rules-file` to swap the rule set) |
| `wordchain` | passphrases, run-together words | a strong random string (it refuses correctly anyway) |
| `dobwords` | `--dob` known **and** you suspect name+birthday | no `--dob` (inert) |
| `hybrid` | word + fixed-width mask, either side | the mask would be wide (`?a?a?a?a` = millions per word) |
| `mask` | a known exact shape | the shape is unknown — use `rules`/`hybrid` |

#### Cutting redundant work

- `context` already does *token + year/date suffix*. If all you have is hints and a
  suspected date, `--only context,dates,dobwords` skips the ~240k-word
  `dictionary` / `rules` sweep entirely.
- `keyboard` and `sequences` overlap on a few repeats (`asdasd`, `qweqwe`); `sequences`
  runs first and wins the rank, so `--skip keyboard` costs little when budget is tight
  and the target is obviously a sequence.
- `--rules-file` **replaces** the built-in `rules` mangling — you never get both. The
  built-in set is roughly `best64`; a larger `.rule` file is more thorough at 10–50×
  the candidates, so raise `--budget` alongside it.
- If the pattern is clearly *word + 4 digits*, run `--only hybrid --hybrid-mask '?d?d?d?d'`
  instead of a full `rules` pass — it covers every 4-digit tail, not just years.
- In hash mode `wordchain`'s generator competes with `rules` for budget; the builder
  already runs it *after* `rules`. If `rules` is still getting starved, lower
  `--chain-vocab` / `--chain-words`.

### Audit a single password

```bash
./crack.py -p 'Summer2024!'
```

Reports something like `CRACKED: 'Summer2024!' via module 'rules', rank #1,234,567`.
A low rank means the password is weak; "NOT FOUND" means none of the enabled attacks
reached it within budget.

A `CRACKED` result is followed by an **assessment** — a strength tier, what the
password essentially *is* (the module that found it), and a few pointed
better-practice tips:

```
  assessment: weak -- a dictionary word with predictable mangling (case, digits, punctuation, leet)
  do better:
    - only 11 characters -- too short whatever the composition; aim for 16+
    - Capitalise + digits + trailing symbol is the single most common pattern
    - prefer length over complexity: 4-5 unrelated random words, or a password manager
    - never reuse it
```

### Audit without leaking the password into your shell history

```bash
./crack.py                 # prompts, input hidden
./crack.py --show          # prompts, input visible
```

### Audit a passphrase or run-together words

```bash
./crack.py -p 'correct horse battery staple'
./crack.py -p 'mary had a little lamb'
./crack.py -p 'correcthorsebattery'          # no separators
./crack.py -p 'Hello.This.Is.Me'             # any separator, any case
```

The `wordchain` module word-breaks the exact string. A string with **spaces** is treated
as a passphrase — every token just has to be dictionary-derived. A string with **no
spaces** has to clear a stricter bar (real words ≥ 4 chars, or short common ones; at most
one short trailing number; a bounded number of parts) so that a strong password isn't
"cracked" by tiling it out of obscure two-letter list entries. If it passes, the
decomposition prints and the audit confirms it at rank ~1. In hash mode the same module
instead *generates* k-word chains (`--chain-words`, default 3) from the top `--chain-vocab`
words.

### Use what you know about the target (hints)

Hints feed the `context` module (and `dates` for `--dob`): the tokens themselves,
mangled, glued together, and suffixed with dates / years.

```bash
./crack.py -p 'Mary.Smith90' \
  --name 'Mary Smith' --user msmith --email mary.smith@acme.com --dob 1990-05-01

# repeat --word for pets, employer, sports team, kids' names...
./crack.py -p 'Fluffy2019' --word Fluffy --word Acme --word Wildcats
```

`--dob` accepts separated forms *and* bare digits (`22041983`, `19830422`,
`220483` — day-first preferred); you get a warning if it can't be parsed.

With `--dob`, the `dobwords` module glues birthday dates onto known bases in
every format (`DDMMYYYY`, `MMDDYYYY`, `YYYYMMDD`, `YYYYDDMM`, two-digit-year and
separator variants). It doesn't stop at the exact date: it sweeps a month either
side, plus the parent and child years (`dob_year - 50 … -18` and `+18 … +50`,
every day — an assumed 18–50yr age gap), so `Fluffy14061962` is reachable from a
1990 DOB.

`--depth` (default 1) sets how much structure it builds:

| depth | shape | example |
|---|---|---|
| 1 | `<hint-token><date>` | `Solomakha16041949` |
| 2 | + `<relation-word><date>[<hint-token>]` | `mama19491604solomakha` |
| 3 | + `<hint-token><date><hint-token>`, `<word><word><date>` | |

Depth ≥ 2 multiplies the keyspace fast (it raises its own budget to 25M), so it's opt-in.

```bash
./crack.py -p 'Fluffy01051990' --word Fluffy --dob 1990-05-01
./crack.py --hash <h> --algo md5 --word solomakha --dob 22041983 --depth 2
```

### Crack a hash

```bash
# md5 of "password"
./crack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algo md5

# other algos: any hashlib name
./crack.py --hash <hex> --algo sha1
./crack.py --hash <hex> --algo sha256
./crack.py --hash <hex> --algo sha512

# bcrypt (needs: pip install bcrypt) — pass the full modular-crypt string
./crack.py --hash '$2b$12$...' --algo bcrypt
```

### Crack a file of hashes at once

```bash
./crack.py --hashfile hashes.txt --algo sha256
```

One hash per line; the run stops at the first match found (all hashes share one
candidate stream).

### Salted hashes

```bash
# H(salt + password)
./crack.py --hash <hex> --algo sha256 --salt-prefix 's3cr3t'

# H(password + salt)
./crack.py --hash <hex> --algo md5 --salt-suffix 'deadbeef'
```

### Crack a password-protected ZIP

```bash
./crack.py --zip secret.zip
./crack.py --zip secret.zip --word acme --word 2021 --dob 1988-03-15 --jobs 4
```

Every module runs exactly as in hash mode — hints, `dobwords`, `--mask`, `--rules-file`,
`--wordlist` all apply. The header line reports which encryption was detected and which
entry is being tested:

```
Target : zip archive secret.zip (ZipCrypto, entry 'notes.txt')
```

- **ZipCrypto** (legacy PKWARE) works with the standard library, no install. ~10–50k
  candidates/sec per core — raise `--jobs` (it's pure-Python CPU-bound, so parallelism
  helps, unlike fast hashes).
- **WinZip AES** archives need `pip install pyzipper`; without it you get a one-line
  install hint. AES uses PBKDF2 (deliberately slow), so stick to the cheap pattern
  modules (`--only context,dates,dobwords,pins,keyboard`) and hints.
- The smallest encrypted entry is used and its CRC is verified on every guess, so a
  reported match is real (no ZipCrypto false positives).
- Check what you have first: `unzip -v secret.zip` (Method column) or
  `7z l -slt secret.zip | grep Method`.

### Run only some attacks (fast, targeted)

```bash
./crack.py -p '4790'            --only pins
./crack.py -p 'qwerty123'       --only keyboard,sequences
./crack.py -p '15031988'        --only dates --dob 1988-03-15
./crack.py -p x --skip wordchain,rules     # everything except the expensive two
```

### Custom rules (hashcat-style)

`--rules-file PATH` points the `rules` module at a hashcat-style rule file — one rule
per line, functions applied left-to-right, full-line `#` comments and blank lines
ignored. It **replaces** the module's built-in mangle set. A starter set lives at
`rules/starter.rule` (~73 rules: case, digit/year/punctuation suffixes, prefixes,
reverse/duplicate/reflect, leet).

```bash
./crack.py -p 'Password2024!' --rules-file rules/starter.rule
./crack.py --hash <hex> --algo md5 --wordlist rockyou.txt --rules-file rules/starter.rule
```

Supported functions: `: l u c C t TN r d f { } [ ] DN 'N pN zN ZN $X ^X @X sXY iNX oNX
xNM k K` (positions use hashcat's `0-9A-Z`). Unsupported tokens are skipped so a real
`.rule` file still loads. With a ruleset the module's budget is raised to 25M
(words × rules multiplies fast) — raise `--budget` too if you cap it.

### Bring your own wordlist

`--wordlist PATH` (repeatable) loads extra lists **before** the built-in `data/*.txt`,
so your words win priority in `dictionary` / `rules` ordering.

```bash
./crack.py --hash <hex> --algo sha1 --wordlist rockyou.txt
./crack.py -p 'AcmeCorp99' --wordlist company-terms.txt --rules-file rules/starter.rule
```

### Hybrid attack (word + mask)

`--hybrid-mask MASK` adds the `hybrid` module: each of the top `--hybrid-vocab` words
(default 2000), plus its capitalized form, glued to every string the mask generates.
`--hybrid-side` = `append` (`hunter1990`), `prepend` (`99hunter`), or `both` (default).
Keyspace = vocab × mask × sides, printed up front — keep the mask small.

```bash
./crack.py -p 'hunter1990'  --hybrid-mask '?d?d?d?d'
./crack.py -p '99london'     --hybrid-mask '?d?d' --hybrid-side prepend
./crack.py --hash <hex> --algo md5 --hybrid-mask '?d?d?d?d' --hybrid-vocab 5000
```

### Mask attack (known password shape)

Only runs when `--mask` or `--brute` is given; the keyspace is printed up front.
Mask tokens: `?d` digit, `?l` lower, `?u` upper, `?s` symbol, `?a` all; anything
else is a literal.

```bash
# "Ussss9999" shape: capital + 4 lowercase + 4 digits
./crack.py --hash <hex> --algo md5 --mask '?u?l?l?l?l?d?d?d?d'

# fixed prefix, unknown 3-digit tail
./crack.py -p 'Acme042' --mask 'Acme?d?d?d'
```

### Brute force a charset by length

```bash
# all 4–6 char strings over lowercase + digits
./crack.py --hash <hex> --algo md5 --brute --charset dl --min 4 --max 6

# all 1–8 digit numbers (default charset is 'd')
./crack.py --hash <hex> --algo sha1 --brute --max 8

# charset spec: d l u s a, or literal characters, combined — e.g. "dl", "lu-_"
./crack.py --hash <hex> --algo md5 --brute --charset 'abc123' --min 3 --max 5
```

### Tune the effort

`--module-budget` and `--budget` take a **size**, not a raw candidate count: a bare
number means millions (`3` = 3,000,000), or add a `k`/`m`/`g` suffix to pick the unit
explicitly (`500k` = 500,000, `1g` = 1,000,000,000).

```bash
# quick pass: cap each wordlist, shrink budgets
./crack.py -p 'hunter2' --limit 5000 --module-budget 500k --budget 5

# deeper pass: wider word-chain vocab, full 6-digit PIN sweep
./crack.py --hash <hex> --algo md5 --chain-vocab 2000 --module-budget 20 --pin6
```

| Flag | Meaning | Default |
|------|---------|---------|
| `--zip PATH` | crack a password-protected .zip (ZipCrypto built in; AES needs `pyzipper`) | — |
| `--jobs N` | worker processes for candidate testing (helps for `bcrypt` / `--zip`) | 1 |
| `--limit N` | words loaded per wordlist file | all |
| `--wordlist PATH` | extra wordlist, loaded before built-ins (repeatable) | — |
| `--rules-file PATH` | hashcat-style rule file (replaces built-in mangling) | — |
| `--hybrid-mask MASK` | adds the hybrid module: top words × this mask | — |
| `--hybrid-side` | `append` / `prepend` / `both` | `both` |
| `--hybrid-vocab N` | top-N words for the hybrid module | 2000 |
| `--module-budget SIZE` | max candidates per module (bare=millions, or k/m/g) | `3` (3M) |
| `--budget SIZE` | global candidate hard stop (bare=millions, or k/m/g) | `30` (30M) |
| `--chain-vocab N` | top-N words fed to the hash-mode word-chain generator | 800 |
| `--chain-words N` | max words per chain in hash mode (plaintext is unbounded) | 3 |
| `--pin6` | also sweep the full 6-digit PIN space (10⁶) | off |
| `--color` | `auto` / `always` / `never` (auto = on for a terminal; honours `NO_COLOR`) | `auto` |

### Wrap a run in a script

When you're iterating on one target with different hints and budgets, drive it from a
small shell wrapper instead of retyping flags. Build the arguments into a bash **array**
(not a string) so nothing is re-split or glob-expanded, and don't let a `NOT FOUND` exit
code (`2`) abort the script.

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- target -----------------------------------------------------------------
PASSP="jimmybbq"                           # only used to build a self-test hash
ALGO="md5"
HASH="${HASH:-$(printf '%s' "$PASSP" | md5sum | awk '{print $1}')}"   # or: export HASH=...

# --- what you know about the owner ----------------------------------------
WORDS="Barbeque bbq"                        # space-separated; each becomes --word X
DOB=""                                     # empty string to disable
UNAME=""                                   # --user  : login / handle
EMAIL=""                                   # --email : full address
NAME="Jimmy Barbeque"                       # --name  : full name, e.g. "Mary Smith"

# --- extra inputs -----------------------------------------------------------
WORDLIST=""                                # --wordlist   : extra list, loaded first (rockyou.txt, cewl.txt)
RULES=""                                   # --rules-file : hashcat-style ruleset (rules/starter.rule)
HYBRID_MASK=""                             # --hybrid-mask: e.g. '?d?d?d?d' (adds the hybrid module)

# --- effort knobs ---------------------------------------------------------
BUDGET=150            # global budget, millions
MODULE_BUDGET=10      # per-module budget, millions
DEPTH=3               # dobwords structure depth
JOBS=1
BRUTE=1              # 1 = append the digit brute sweep (?d x1-8), 0 = skip
EXTRA=()             # ad-hoc flags, e.g. EXTRA=(--only dobwords --rules-file rules/starter.rule)

# --- assemble -------------------------------------------------------------
read -ra WORD_LIST <<< "$WORDS"
ARGS=(--hash "$HASH" --algo "$ALGO"
      --budget "$BUDGET" --module-budget "$MODULE_BUDGET"
      --depth "$DEPTH" --jobs "$JOBS")
[[ -n "$DOB"         ]] && ARGS+=(--dob "$DOB")
[[ -n "$UNAME"       ]] && ARGS+=(--user "$UNAME")
[[ -n "$EMAIL"       ]] && ARGS+=(--email "$EMAIL")
[[ -n "$NAME"        ]] && ARGS+=(--name "$NAME")
[[ -n "$WORDLIST"    ]] && ARGS+=(--wordlist "$WORDLIST")
[[ -n "$RULES"       ]] && ARGS+=(--rules-file "$RULES")
[[ -n "$HYBRID_MASK" ]] && ARGS+=(--hybrid-mask "$HYBRID_MASK")
[[ "$BRUTE" == 1     ]] && ARGS+=(--brute)
for w in "${WORD_LIST[@]}"; do ARGS+=(--word "$w"); done
[[ ${#EXTRA[@]} -gt 0 ]] && ARGS+=("${EXTRA[@]}")

clear
printf 'pass  == %s ==\n' "$PASSP"
printf 'hash  == %s ==\n' "$HASH"
printf 'algo  == %s ==\n' "$ALGO"
printf 'words == %s ==\n' "$WORDS"
printf 'dob   == %s ==\n' "$DOB"
[[ -n "$UNAME$EMAIL$NAME" ]] && printf 'ident == user:%s email:%s name:%s ==\n' "$UNAME" "$EMAIL" "$NAME"
printf 'args  == %s ==\n' "${ARGS[*]}"

# --- run ------------------------------------------------------------------
rc=0
time ./crack.py "${ARGS[@]}" || rc=$?
case $rc in
  0) echo ">>> CRACKED" ;;
  2) echo ">>> not found in budget - raise BUDGET/MODULE_BUDGET, or EXTRA=(--mask '<shape>')" ;;
  *) echo ">>> crack.py exited $rc" ;;
esac
exit $rc
```

- **`HASH`** falls back to hashing `PASSP` so the script is self-testing; `export HASH=…`
  (and set `PASSP=` / `ALGO=`) to point it at a real target. Swap `--hash` for `--zip
  archive.zip` or `-p "$PASSP"` to change mode.
- **`ARGS` is an array** — `"${ARGS[@]}"` passes each flag as one word. (`make run
  ARGS="…"` can't do this: it splits the string again, so quote-sensitive values like
  `--mask` or a `--word` with spaces break. Call `./crack.py` directly.)
- **`WORDS` / `DOB` / `UNAME` / `EMAIL` / `NAME`** are the target hints — each is added
  only when non-empty, so leave the ones you don't know as `""`. `WORDS` splits on
  spaces into repeated `--word`; the rest map to `--user` / `--email` / `--name` /
  `--dob` and all feed the same hint-token list.
- **`WORDLIST` / `RULES` / `HYBRID_MASK`** wire in `--wordlist` (your own list, loaded
  ahead of the built-ins), `--rules-file` (hashcat ruleset), and `--hybrid-mask` (turns
  on the hybrid module) — again only when set.
- **`BUDGET` / `MODULE_BUDGET`** are the size strings from
  [Tune the effort](#tune-the-effort) — a bare number means millions.
- **`BRUTE=1`** adds `--brute` with default charset (`?d`, length 1–8) as a last-resort
  module; set `0` for a quick pass, or put a shaped `--mask` in `EXTRA` instead.
- **`EXTRA=(...)`** is the extension point for `--only` / `--skip`, `--rules-file`,
  `--wordlist`, `--hybrid-mask`, `--mask`, `--pin6`, …

### Interpreting "NOT FOUND"

The per-module table shows how many candidates each attack tried and whether it hit
its budget. To go further: add `--mask` / `--brute`, raise `--module-budget`, feed
more hints, or drop `--limit`.

In **plaintext mode** a `NOT FOUND` is followed by a **shape analysis** — the tool
regex-classifies the password you gave against known weak shapes (word + year, leet
substitution, embedded birthday, keyboard walk, run-together words, short-enough-to-
brute, …) and names the knob that would most likely reach it, e.g.:

```
  shape analysis (why the enabled attacks may have missed it):
    - word + 4-digit year ('hunter' + 1990): --rules-file rules/starter.rule has
      year-suffix rules; also raise --module-budget if 'hunter' is deep in the wordlist
    - embedded date '16041983' (DDMMYYYY): pass --dob <date> and --depth 2
```

It is advisory only and never changes the result or the rank. Hash / zip runs skip it
(there is no plaintext to inspect).

---

## Layout

```
crack.py         CLI entry point + argument parsing
core/            context (shared state, hints, limits), matcher (plaintext/hash/zip),
                 wordlists (loader), runner (budgeted pipeline), rules_engine (hashcat rules),
                 shapes (NOT-FOUND gap diagnosis + CRACKED assessment),
                 term (muted ANSI colour), parallel (--jobs fork pool)
modules/         one file per attack; registered in modules/__init__.py
data/            wordlists (*.txt), committed
rules/           hashcat-style rule files for --rules-file (starter.rule), committed
```

See `CLAUDE.md` for architecture and the module contract if you want to add an attack.
