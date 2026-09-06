# password

A modular dictionary / pattern password cracker. **Research & educational use only** —
use it to audit the guessability of passwords you are authorised to test.

Pure Python 3.12 standard library. The only optional *package* is `bcrypt`
(`pip install bcrypt`), needed solely for `--algo bcrypt` (WinZip-AES `--zip`
also wants `pyzipper`). `--gpg` / `--sshkey` shell out to the system `gpg` /
`ssh-keygen` binaries — no Python package, but those tools must be installed.

```bash
./crack.py -p 'Summer2024!'
```

---

## How it works

The tool has **five target modes**:

| Mode | How you invoke it | What it tells you |
|------|-------------------|-------------------|
| **plaintext** (guessability audit) | `-p PASSWORD` (or prompt) | *whether* the enabled attacks reach the password, which module found it, and at what **rank** (how many guesses in) |
| **hash** (preimage search) | `--hash HEX` / `--hashfile FILE` + `--algo` | runs the same candidate generators as a real cracking run against your hash(es) |
| **zip** (archive password) | `--zip archive.zip` | tries each candidate as the archive password (ZipCrypto built in; WinZip AES needs `pip install pyzipper`) |
| **gpg** (symmetric OpenPGP) | `--gpg file.gpg` | tries each candidate as the passphrase of a `gpg -c` file, via the system `gpg`. **Symmetric only** — see caveats below |
| **sshkey** (private-key passphrase) | `--sshkey id_ed25519` | tries each candidate as the passphrase of an encrypted OpenSSH / PEM private key, via `ssh-keygen -y` |

`gpg` and `sshkey` behave like **hash** mode for module selection, but each guess
is a **subprocess spawn** (~1–5 ms floor) against a **deliberately slow** KDF
(OpenPGP S2K, OpenSSH bcrypt-pbkdf). Realistic scope: `context`, `pins`,
`dictionary`, and `rules` at a modest `--module-budget` — **not** `--mask` /
`--brute` over any real keyspace. Raise `--jobs N` (near-linear speed-up, CPU-bound
like ZipCrypto). Further caveats:

- **`--gpg` is symmetric-only.** A public-key-encrypted file (`gpg -e`) can't be
  attacked with a passphrase guess — it needs the recipient's secret key. A bare
  exported secret key (`gpg --export-secret-keys`) isn't supported either (`gpg
  --decrypt` won't verify its passphrase).
- **`--sshkey` needs an *encrypted* key.** An unencrypted key errors out at startup
  (nothing to crack). Works for both the modern OpenSSH format and legacy PEM.
- Both need the binary on `PATH` (`gpg` / `gpg2`, `ssh-keygen`); a missing binary
  exits with an install hint.
- Each guess has a **10 s timeout**; a hang counts as a non-match, not a crash.
- The crack-time ladder for these modes uses order-of-magnitude offline-cracker
  rates (`gpg` ≈ 1e7/s on a GPU, `ssh-key` ≈ 5e3/s — bcrypt-pbkdf is slow by design).

Candidates come from pluggable **modules** in `modules/`, run cheapest-first under a
per-module budget (default 3M candidates) and a global hard stop (default 30M). Each
module is a focused generator: PINs, dates, keyboard walks, dictionary + mangling
rules (built-in or a hashcat `.rule` file), multi-word chains, hint-based guesses,
word×mask hybrids, masks/brute force, etc.

```
./crack.py --list-modules
```

Run order (cheapest / highest-value first, budget-eaters last):
`context → pins → phone → bip39 → wordchain → sequences → keyboard → dictionary →
permute → dates → rules → fuzz → dobwords → hybrid → mask`. (`bip39` and
`wordchain`'s plaintext decompositions run early, at rank ~1; their hash-mode
generators run late. `dobwords` only does anything with `--dob`; `permute` only
with `--permute`; `fuzz` only with `--fuzz`; `hybrid` only with `--hybrid-mask`;
`mask` only with `--mask`/`--brute`.)

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
| `wordchain` / `bip39` | word-*break* the exact string (rank ~1 if it segments) | *generate* k-word chains — `wordchain` tunes `--chain-words` / `--chain-vocab`, `bip39` fixed at k≤4 |
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
| `bip39` | a target made of BIP-39 mnemonic words (seed phrase, or a short passphrase built from them) | any word isn't in the 2048-list (`wordchain` takes over) |
| `wordchain` | passphrases, run-together words | a strong random string (it refuses correctly anyway) |
| `permute` | you know most of a passphrase's words but not their order (or are missing one or two) | fewer than 2 `--word`/hint tokens (inert) |
| `dobwords` | `--dob` known **and** you suspect name+birthday | no `--dob` (inert) |
| `fuzz` | a word with one odd internal char swap (`passwyrd`, `monkez`) that `rules`/leet miss | `--fuzz` not given (inert); the tail is a suffix (use `hybrid`) |
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

A run prints a **`RUN`** table (target, mode, wordlist size, module count, hints,
budgets), then per-module progress, then a **`SUMMARY`** table. On `CRACKED` the
summary carries the guess count, the time to crack at each attack rate, the
strength assessment and the elapsed time; a few pointed better-practice tips
follow it:

```
+-----------------------------------------------------------------------------+
| SUMMARY                                                                     |
+------------------+----------------------------------------------------------+
| result           | CRACKED                                                  |
| password         | 'hey jimmy barbecue 123123@##'                           |
| via              | wordchain  (rank #53,489)                                |
| guesses          | ~101.5 trillion  (101,491,825,756,596)                   |
| vs online 10/s   | ~321,608 years                                           |
| vs online 1k/s   | ~3,216 years                                             |
| vs bcrypt-class  | ~161 years                                               |
| vs fast-hash rig | 17 minutes                                               |
| assessment       | weak -- several common words run together                |
| elapsed          | 0.1s total                                               |
+------------------+----------------------------------------------------------+
  guess estimate = hey~74,197 x jimmy~682 x barbecue~30,389 x 123123~11 x 6 separators
  do better:
    - concatenation only helps if the words are individually rare -- use more words, chosen at random
    - prefer length over complexity: 4-5 unrelated random words, or a password manager
    - never reuse it
```

The guess count is the cracking module's own hit position — for `wordchain`'s
plaintext decomposition (which only ever emits one candidate) it is estimated as
the product of each word's depth in the wordlist × separator choices. The time
rows are order-of-magnitude (hashcat-benchmark rates for a single ~8-GPU rig);
in hash mode a row for the target's actual algorithm is added. The same
"N to exhaust vs `<algo>`" figure is appended to the `mask` / `hybrid` / `fuzz` /
`permute` keyspace lines so you can size `--module-budget` against real effort.

### Second opinion from a local model (opt-in)

Set `OLLAMA_MODEL` and the run ends by handing its report to a local
[Ollama](https://ollama.com) model and printing the reply as a bordered panel —
headed by the target, the model name, a colour-coded one-word verdict and the
model's own offline crack-time estimate, with its free-text reasoning wrapped
below (the report it sees includes the tool's own crack-time ladder, and the
model is asked to say whether those figures look right):

```bash
OLLAMA_MODEL=llama3.2 ./crack.py -p 'Summer2024!'
```

```
+------------------------------------------------------------------------------+
| 'Summer2024!'   |   llama3.2   |   WEAK   |   ~seconds on a GPU               |
+------------------------------------------------------------------------------+
| I agree with the tool and its timing: this is a common word plus a year and  |
| a symbol, the single most common real-world pattern, so any wordlist-plus-   |
| rules attack reaches it early. Offline against an unsalted fast hash it       |
| falls in seconds; even an online-throttled attack gets there in days. The    |
| change that helps most is a 4-5 word random passphrase from a manager.       |
+------------------------------------------------------------------------------+
```

Pure stdlib (`urllib` against Ollama's HTTP API — no `ollama` package). Env knobs
(also read from a gitignored `.env`, real env wins): `OLLAMA_URL` (full endpoint,
wins if set) or `OLLAMA_HOST` (bare host/IP fine, default `localhost:11434`),
`OLLAMA_TEMPERATURE` (0.2), `OLLAMA_TIMEOUT` (60s), `OLLAMA_NUM_CTX`. The model is
asked for JSON with three keys — `verdict`, `crack_time` and `opinion` — and a missing model,
unreachable server, timeout or unparseable reply prints one dim line and **never
changes the exit code**. Note: in `-p` mode the report includes the password, so
it is sent to whatever `OLLAMA_URL` / `OLLAMA_HOST` points at (nothing leaves the
machine on the localhost default).

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
words **ordered by English frequency** (`the`, `is`, `my`, `gun` — not the breach-password
order the other modules use). This reaches a 2-word — and, with a raised budget, a short
3-word — passphrase of ordinary words; a longer passphrase stays uncrackable (that's the
point of one). For a *known* phrase (a movie quote, a lyric) use `--wordlist` with a
phrase list instead.

### BIP-39 mnemonics

The `bip39` module reads the target as a sequence of words from the 2048-word
BIP-39 English list (`data/bip39.txt`):

```bash
./crack.py -p 'legal winner thank year wave sausage worth useful legal winner thank yellow'
./crack.py -p 'abandonabilityzoo'          # run-together, still detected
```

In plaintext mode it word-breaks the exact target; ≥ 2 BIP-39 words and it
reports the split. The guess estimate is `2048 ** words × separators`, so a real
12/15/18/21/24-word seed phrase is flagged **strong** (out of offline
brute-force reach) while a 2-4 word "clever" BIP-39 passphrase is **very weak /
weak**. In hash mode it generates k=2..4 word chains from the 2048 words
(budget-capped). It runs just before `wordchain` and claims the result for an
all-BIP-39 phrase; `wordchain` handles any phrase with a non-BIP-39 word.

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

### Crack a symmetric GPG file (`gpg -c`)

```bash
./crack.py --gpg secret.txt.gpg --jobs 4
./crack.py --gpg secret.txt.gpg --word acme --dob 1990-05-01 --only context,pins,dictionary,rules
```

Each candidate is fed to `gpg --batch --pinentry-mode loopback --passphrase … --decrypt`.
The header line reads `Target : symmetric OpenPGP file secret.txt.gpg`.

- **Symmetric only.** `gpg -e` (public-key) files need the recipient's secret key,
  not a passphrase — they can't be attacked here. A bare exported secret key isn't
  supported either.
- One `gpg` process per guess (~1–5 ms floor) and OpenPGP's S2K is iterated by
  design, so keep to the cheap modules and a small `--module-budget`; `--mask` /
  `--brute` are impractical. Raise `--jobs`.
- Needs `gpg` (or `gpg2`) on `PATH`; a 10 s per-guess timeout treats a hang as a miss.

### Crack an SSH private-key passphrase

```bash
./crack.py --sshkey ~/.ssh/id_ed25519 --jobs 4 --wordlist rockyou.txt
./crack.py --sshkey id_rsa --only context,pins,dictionary,rules
```

Each candidate runs `ssh-keygen -y -P <cand> -f KEY` (prints the public key on
success, writes nothing). Header: `Target : encrypted private key id_ed25519`.

- The key **must be passphrase-protected** — an unencrypted key errors out at
  startup. Both the modern OpenSSH format and legacy PEM `id_rsa` work.
- Modern keys use **bcrypt-pbkdf** (very slow by design) — cheap modules only,
  small budget, and `--jobs N` for the near-linear speed-up.
- Needs `ssh-keygen` on `PATH`; 10 s per-guess timeout.

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

### Fuzz attack (Hamming-distance variants)

`--fuzz N` (N = 1 or 2) adds the `fuzz` module: every one of the top
`--fuzz-vocab` words (default 2000) **plus the hint tokens**, with up to `N`
single-character substitutions (same length — Hamming distance ≤ N). This is the
one thing `rules`/leet don't cover: an arbitrary one-off swap (`passwyrd`,
`monkez`, `drygon`) or a fat-finger typo baked in (`passworf`). Variants that are
themselves dictionary words are skipped (`dictionary` already tried them).

Keyspace is `vocab × L × (A−1)` for N=1 and explodes for N=2, so it is always
vocab-capped and the substitution alphabet is small, not full ASCII:

| `--fuzz-charset` | alphabet | ~per word (L=7) | models |
|---|---|--:|---|
| `sub` (default) | `a–z 0–9 ! @ # $ %` | ~270 | a deliberate "made it stronger" swap |
| `kbd` | keyboard-adjacent keys only | ~40 | an accidental fat-finger typo |
| `l` / `d` / `u` / `s` / `a` | `mask` charset spec | varies | — |
| *(literal)* | the exact characters you pass | varies | — |

```bash
./crack.py -p 'passwyrd' --fuzz 1                        # ~0.5M candidates
./crack.py -p 'passworf' --fuzz 1 --fuzz-charset kbd     # typo model, ~70k
./crack.py --hash <hex> --algo md5 --word acme --fuzz 1  # also fuzzes 'acme'
./crack.py -p 'p&sswl0rd' --fuzz 2 --fuzz-vocab 300      # N=2 needs a tiny vocab
```

N=2 raises the module budget to 25M and still needs `--fuzz-vocab` in the low
hundreds — `C(L,2)·(A−1)²` is ~27k candidates per word.

### Permute attack (known words, unknown order)

`--permute` adds the `permute` module: it takes the words you supply as hints
(`--word`, plus tokens from `--name`/`--user`/`--email`) and tries them in
**every order**, glued with each separator, in plain and Capitalised forms. This
is the "I remember the words in my passphrase but not the order" case —
`context` only ever glues *pairs*, and the hash-mode word-chain generator draws
from a frequency list, not from your hints.

```bash
./crack.py --hash <hex> --algo md5 \
  --word correct --word horse --word battery --word staple --permute
# 'correct horse battery staple', 'staple-battery-horse-correct', ...  (4! x 5 seps)

# missing a word or two? --permute-fill N pulls N slots from the top common words:
./crack.py --hash <hex> --algo md5 \
  --word this --word my --word rifle --word gun --permute --permute-fill 1
# -> 'this is my rifle gun', 'this my rifle gun today', ...
```

Keyspace = `perm(tokens + fill) × separators × cases × vocab^fill`, printed up
front. Tokens are capped at 8 (`8! = 40,320`). `--permute-sep` overrides the
separator list (`none,space,-,_,.` by default); `--permute-fill` (0–2, default 0)
and `--permute-vocab` (default 200) control the gap-filling — `fill ≥ 1` raises
the module budget to 25M. An 8-word passphrase with 6 known words and 2 gaps is
`perm(8) × vocab²` ≈ tractable only with a small `--permute-vocab` and a raised
`--budget`; more than 2 unknown words stays out of reach (as it should).

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
| `--gpg PATH` | crack a symmetric OpenPGP file (`gpg -c`); needs system `gpg`; slow — cheap modules only | — |
| `--sshkey PATH` | crack an encrypted OpenSSH / PEM private-key passphrase; needs `ssh-keygen`; slow | — |
| `--jobs N` | worker processes for candidate testing (helps for `bcrypt` / `--zip` / `--gpg` / `--sshkey`) | 1 |
| `--limit N` | words loaded per wordlist file | all |
| `--wordlist PATH` | extra wordlist, loaded before built-ins (repeatable) | — |
| `--rules-file PATH` | hashcat-style rule file (replaces built-in mangling) | — |
| `--hybrid-mask MASK` | adds the hybrid module: top words × this mask | — |
| `--hybrid-side` | `append` / `prepend` / `both` | `both` |
| `--hybrid-vocab N` | top-N words for the hybrid module | 2000 |
| `--fuzz N` | adds the fuzz module: words with ≤ N char substitutions (N ∈ {1,2}) | — |
| `--fuzz-vocab N` | top-N words fuzzed, plus hint tokens | 2000 |
| `--fuzz-charset SPEC` | substitution alphabet: `sub` / `kbd` / mask spec / literal | `sub` |
| `--permute` | adds the permute module: hint tokens in every order × separators | — |
| `--permute-sep LIST` | separator list, e.g. `none,space,-,_,.` | `none,space,-,_,.` |
| `--permute-fill N` | also fill N unknown slots from the top common words (N ∈ {0,1,2}) | `0` |
| `--permute-vocab N` | top-N common words used for `--permute-fill` slots | 200 |
| `--module-budget SIZE` | max candidates per module (bare=millions, or k/m/g) | `3` (3M) |
| `--budget SIZE` | global candidate hard stop (bare=millions, or k/m/g) | `30` (30M) |
| `--chain-vocab N` | top-N words (by English frequency) fed to the hash-mode word-chain generator | 800 |
| `--chain-words N` | max words per chain in hash mode (plaintext is unbounded) | 3 |
| `--pin6` | also sweep the full 6-digit PIN space (10⁶) | off |
| `--color` | `auto` / `always` / `never` (auto = on for a terminal; honours `NO_COLOR`) | `auto` |

### Wrap a run in a script

When you're iterating on one target with different hints and budgets, drive it from a
small shell wrapper instead of retyping flags. **`test.sh` in the repo is exactly this** —
every `crack.py` flag exposed as a `${VAR:-default}` you can override on the command line,
each appended to a bash **array** (not a string) so quote-sensitive values (`--name`,
`--mask`, a `--word` with spaces) survive, and a `|| rc=$?` so a `NOT FOUND` exit (`3`)
doesn't abort the script:

```bash
PASSP='s3cr3t' ./test.sh                       # self-test: md5(PASSP), then crack it
HASH=<hex> ALGO=sha1 ./test.sh                 # crack a real digest
HASH=0 PASSP='mary had a lamb' ./test.sh       # plaintext guessability audit (-p)
ZIP=secret.zip WORDS='acme 1990' JOBS=4 ./test.sh
GPG=secret.txt.gpg JOBS=4 MODULE_BUDGET=20 ONLY=context,pins,dictionary,rules ./test.sh
SSHKEY=id_ed25519 WORDLIST=rockyou.txt JOBS=4 ./test.sh
PASSP='Password2024!' FUZZ=1 PERMUTE=1 BUDGET=300 ./test.sh
```

Assembly pattern (abbreviated — see `test.sh` for the full set):

```bash
read -ra WORD_LIST <<< "$WORDS"
if   [[ -n "$ZIP" ]];      then ARGS=(--zip "$ZIP")
elif [[ -n "$GPG" ]];      then ARGS=(--gpg "$GPG")
elif [[ -n "$SSHKEY" ]];   then ARGS=(--sshkey "$SSHKEY")
elif [[ "$HASH" == 0 ]];   then ARGS=(-p "$PASSP")           # empty PASSP -> crack.py prompts
else                            ARGS=(--hash "$HASH" --algo "$ALGO")
fi
ARGS+=(--budget "$BUDGET" --module-budget "$MODULE_BUDGET" --depth "$DEPTH" --jobs "$JOBS")
[[ -n "$NAME"  ]] && ARGS+=(--name "$NAME")                  # ... one guard per flag ...
[[ -n "$FUZZ"  ]] && ARGS+=(--fuzz "$FUZZ")
[[ -n "$PERMUTE" ]] && ARGS+=(--permute)
for w in "${WORD_LIST[@]}"; do ARGS+=(--word "$w"); done
rc=0; time ./crack.py "${ARGS[@]}" || rc=$?
```

- **Target mode** is `HASH`: unset ⇒ self-test on `md5(PASSP)` (or `${ALGO}sum` if that
  coreutils tool exists); `<hex>` ⇒ crack that digest; **`0` ⇒ plaintext audit** via `-p`
  (empty `PASSP` ⇒ `crack.py` prompts, `SHOW=1` ⇒ visible). `HASHFILE`, `ZIP`, `GPG`
  (symmetric OpenPGP file) and `SSHKEY` (encrypted private key) override the target
  entirely — the last two are subprocess-slow, so pair them with a small `MODULE_BUDGET`,
  `ONLY=…` and a high `JOBS`. `LIST_MODULES=1` just prints the module list and exits.
- **Every knob is added only when non-empty**, so the crack.py default applies when you
  leave one blank. `WORDS` and `WORDLIST` split on spaces into repeated `--word` /
  `--wordlist`; everything else maps 1:1.
- **`make run ARGS="…"` can't replace this** — it re-splits the string, breaking quoted
  values. Call `./crack.py` (or `./test.sh`) directly.
- **`EXTRA=(...)`** stays as the escape hatch for anything not yet wired to a variable.

### Interpreting "NOT FOUND"

The `SUMMARY` table gives the outcome, total candidates tried and elapsed time; the
`per-module` table below it shows how many candidates each attack tried and whether it
hit its budget. To go further: add `--mask` / `--brute`, raise `--module-budget`, feed
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

It is advisory only and never changes the result or the rank. Hash / zip / gpg /
sshkey runs skip it (there is no plaintext to inspect).

A `NOT FOUND` also prints a **rough strength estimate** — a floor, not a proof:

```
  strength estimate (rough -- a NOT FOUND is a floor, not proof):
    - lower bound: it survived 3,787,976 candidates -- ~3 minutes against a slow hash
      (bcrypt), instantly against a fast-hash rig
    - upper bound (only if truly random): 16 chars over a ~95-char pool ~= ~4e31 guesses
      -> longer than the universe has existed even against a fast-hash rig
    - no weak shape matched -- if the ceiling holds this is a strong password
```

The **lower bound** (both modes) is just "it survived N guesses". The **upper bound**
(plaintext only) is the brute-force ceiling from the string's own composition
(pool-size ^ length) — the real value only if the password has no structure; when the
shape analysis flagged a pattern the line says so and marks it "reachable, not strong".
Hash mode gets the floor only: a digest reveals nothing about structure.

---

## Layout

```
crack.py         CLI entry point + argument parsing
core/            context (shared state, hints, limits), matcher (plaintext/hash/zip/gpg/sshkey),
                 wordlists (loader), runner (budgeted pipeline), rules_engine (hashcat rules),
                 shapes (NOT-FOUND gap diagnosis + CRACKED assessment),
                 term (muted ANSI colour), parallel (--jobs fork pool)
modules/         one file per attack; registered in modules/__init__.py
data/            wordlists (*.txt), committed
rules/           hashcat-style rule files for --rules-file (starter.rule), committed
```

See `CLAUDE.md` for architecture and the module contract if you want to add an attack.
