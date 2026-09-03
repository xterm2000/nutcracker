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

The tool has **two target modes**:

| Mode | How you invoke it | What it tells you |
|------|-------------------|-------------------|
| **plaintext** (guessability audit) | `-p PASSWORD` (or prompt) | *whether* the enabled attacks reach the password, which module found it, and at what **rank** (how many guesses in) |
| **hash** (preimage search) | `--hash HEX` / `--hashfile FILE` + `--algo` | runs the same candidate generators as a real cracking run against your hash(es) |

Candidates come from pluggable **modules** in `modules/`, run cheapest-first under a
per-module budget (default 3M candidates) and a global hard stop (default 30M). Each
module is a focused generator: PINs, dates, keyboard walks, dictionary + mangling
rules, word combinator, hint-based guesses, masks/brute force, etc.

```
./crack.py --list-modules
```

Run order (cheapest / highest-value first): `context → passphrase → phone → pins →
dictionary → sequences → keyboard → dates → rules → combinator → mask`.

Wordlists live in `data/` (passwords, first names, surnames, TV/film, English
Wikipedia — ~280k unique words after de-dup).

---

## Cookbook

### Audit a single password

```bash
./crack.py -p 'Summer2024!'
```

Reports something like `CRACKED: 'Summer2024!' via module 'rules', rank #1,234,567`.
A low rank means the password is weak; "NOT FOUND" means none of the enabled attacks
reached it within budget.

### Audit without leaking the password into your shell history

```bash
./crack.py                 # prompts, input hidden
./crack.py --show          # prompts, input visible
```

### Audit a passphrase

```bash
./crack.py -p 'correct horse battery staple'
./crack.py -p 'mary had a little lamb'
```

The `passphrase` module first checks whether every token is dictionary-derived and
prints what it resolved; the audit then confirms the exact string.

### Use what you know about the target (hints)

Hints feed the `context` module (and `dates` for `--dob`): the tokens themselves,
mangled, glued together, and suffixed with dates / years.

```bash
./crack.py -p 'Mary.Smith90' \
  --name 'Mary Smith' --user msmith --email mary.smith@acme.com --dob 1990-05-01

# repeat --word for pets, employer, sports team, kids' names...
./crack.py -p 'Fluffy2019' --word Fluffy --word Acme --word Wildcats
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

### Run only some attacks (fast, targeted)

```bash
./crack.py -p '4790'            --only pins
./crack.py -p 'qwerty123'       --only keyboard,sequences
./crack.py -p '15031988'        --only dates --dob 1988-03-15
./crack.py -p x --skip combinator,rules    # everything except the expensive two
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

```bash
# quick pass: cap each wordlist, shrink budgets
./crack.py -p 'hunter2' --limit 5000 --module-budget 500000 --budget 5000000

# deeper pass: bigger combinator, full 6-digit PIN sweep
./crack.py -p 'hunter2' --combinator-words 2000 --module-budget 20000000 --pin6
```

| Flag | Meaning | Default |
|------|---------|---------|
| `--limit N` | words loaded per wordlist file | all |
| `--module-budget N` | max candidates per module | 3,000,000 |
| `--budget N` | global candidate hard stop | 30,000,000 |
| `--combinator-words N` | top-N words fed to the word combinator | 800 |
| `--pin6` | also sweep the full 6-digit PIN space (10⁶) | off |

### Interpreting "NOT FOUND"

The per-module table shows how many candidates each attack tried and whether it hit
its budget. To go further: add `--mask` / `--brute`, raise `--module-budget`, feed
more hints, or drop `--limit`.

---

## Layout

```
crack.py         CLI entry point + argument parsing
core/            context (shared state, hints, limits), matcher (plaintext/hash),
                 wordlists (loader), runner (budgeted pipeline)
modules/         one file per attack; registered in modules/__init__.py
data/            wordlists (*.txt), committed
```

See `CLAUDE.md` for architecture and the module contract if you want to add an attack.
