#!/usr/bin/env bash
# author: Mitek (Xterm2000) @05/09/2026

# test.sh -- a re-runnable wrapper around ./crack.py for iterating on ONE
# target with different hints, attacks and budgets, instead of retyping flags.
#
# How it works:
#   * every crack.py flag has a shell variable below, all in ${VAR:-default}
#     form -- override any of them on the command line without editing:
#         PASSP='s3cr3t' FUZZ=1 BUDGET=300 ./test.sh
#   * an empty value drops that flag entirely (the crack.py default applies)
#   * every set knob is appended to an ARGS bash *array* (never a string), so
#     quoted values with spaces (--name, --mask) survive intact -- this is why
#     `make run ARGS="..."` can't be used here.
#
# Target mode is picked by HASH:
#   unset     self-test  -- md5(PASSP), then crack that digest        (default)
#   <hex>     hash mode   -- crack that exact digest (set ALGO to match)
#   0         plaintext   -- guessability audit of PASSP via -p (no hashing);
#                            empty PASSP -> crack.py prompts (SHOW=1 = visible)
# HASHFILE / ZIP override the target entirely when set.
#
# Exit code mirrors crack.py: 0 = cracked, 3 = not found in budget, other = error.
# The `|| rc=$?` keeps `set -e` from aborting on the expected exit 3.
#
# See README.md "Wrap a run in a script" for the annotated walk-through.

set -euo pipefail
cd "$(dirname "$0")"

# Load a project .env (OLLAMA_* etc) if present -- an inline VAR=... still wins
# because these are read with ${VAR:-...} below. crack.py loads it too.
[[ -f .env ]] && { set -a; . ./.env; set +a; }

# --- target --------------------------------------------------------------
PASSP="${PASSP:-jimmybbq}"                # the password string (self-test / -p)
ALGO="${ALGO:-md5}"                       # --algo   : md5/sha1/sha256/.../bcrypt
HASH="${HASH:-}"                          # unset=self-test, <hex>=digest, 0=plaintext
HASHFILE="${HASHFILE:-}"                  # --hashfile : file of digests, one per line
ZIP="${ZIP:-}"                            # --zip      : password-protected .zip to crack
SHOW="${SHOW:-}"                          # non-empty + HASH=0 + empty PASSP: --show (visible prompt)
SALT_PREFIX="${SALT_PREFIX:-}"            # --salt-prefix : salt prepended before hashing
SALT_SUFFIX="${SALT_SUFFIX:-}"           # --salt-suffix : salt appended before hashing

# self-test: no HASH/HASHFILE/ZIP given -> hash PASSP ourselves and crack that.
# Use the coreutils tool for $ALGO if it exists ("${ALGO}sum"), else fall back to
# md5 (and pin ALGO to match, so the digest and --algo never disagree).
if [[ -z "$HASH" && -z "$HASHFILE" && -z "$ZIP" ]]; then
    if command -v "${ALGO}sum" >/dev/null 2>&1; then
        HASH="$(printf '%s' "$PASSP" | "${ALGO}sum" | awk '{print $1}')"
    else
        HASH="$(printf '%s' "$PASSP" | md5sum | awk '{print $1}')"
        ALGO="md5"
    fi
fi

# --- what you know about the owner -------------------------------------
# Hints. WORDS splits on spaces into repeated --word; the rest map 1:1.
WORDS="${WORDS:-jimmy}"                   # --word (xN) : pet, company, team, nickname...
DOB="${DOB:-}"                            # --dob   : date of birth, e.g. 1990-05-01
UNAME="${UNAME:-}"                        # --user  : login / handle
EMAIL="${EMAIL:-}"                        # --email : full address
NAME="${NAME:-}"                          # --name  : full name, e.g. "Mary Smith"

# --- module selection ------------------------------------------------
ONLY="${ONLY:-}"                          # --only  : csv of module names to run
SKIP="${SKIP:-}"                          # --skip  : csv of module names to drop
LIST_MODULES="${LIST_MODULES:-}"         # non-empty: just print module names and exit

# --- extra wordlists / rules --------------------------------------
WORDLIST="${WORDLIST:-}"                  # --wordlist (xN, space-separated): rockyou.txt, cewl.txt
RULES="${RULES:-}"                        # --rules-file : hashcat-style ruleset (rules/starter.rule)

# --- hybrid attack (opt-in) --------------------------------------
HYBRID_MASK="${HYBRID_MASK:-}"           # --hybrid-mask  : e.g. '?d?d?d?d' (adds the hybrid module)
HYBRID_SIDE="${HYBRID_SIDE:-}"           # --hybrid-side  : append / prepend / both
HYBRID_VOCAB="${HYBRID_VOCAB:-}"         # --hybrid-vocab : top-N words fed to hybrid

# --- fuzz attack (opt-in) ---------------------------------------
FUZZ="${FUZZ:-}"                          # --fuzz N (1 or 2): words +/- N char substitutions
FUZZ_VOCAB="${FUZZ_VOCAB:-}"             # --fuzz-vocab   : top-N words fuzzed
FUZZ_CHARSET="${FUZZ_CHARSET:-}"         # --fuzz-charset : sub / kbd / mask spec / literal

# --- permute attack (opt-in) ----------------------------------
PERMUTE="${PERMUTE:-}"                    # non-empty: --permute (hint tokens in every order)
PERMUTE_SEP="${PERMUTE_SEP:-}"           # --permute-sep   : e.g. 'none,space,-,_,.'
PERMUTE_FILL="${PERMUTE_FILL:-}"         # --permute-fill N (0-2): fill N unknown slots from common words
PERMUTE_VOCAB="${PERMUTE_VOCAB:-}"       # --permute-vocab : top-N common words for the fill slots

# --- mask / brute (opt-in) ----------------------------------
MASK="${MASK:-}"                          # --mask   : hashcat-style mask, e.g. '?u?l?l?l?d?d?d?d'
BRUTE="${BRUTE:-1}"                       # 1 = append --brute digit sweep, 0 = skip
CHARSET="${CHARSET:-}"                    # --charset : brute charset spec (d l u s a or literal)
MIN="${MIN:-}"                            # --min    : brute min length
MAX="${MAX:-}"                            # --max    : brute max length

# --- limits / effort ---------------------------------------
# BUDGET / MODULE_BUDGET are size strings: bare number = millions (150 -> 150M).
BUDGET="${BUDGET:-150}"                   # --budget        : global candidate hard stop
MODULE_BUDGET="${MODULE_BUDGET:-10}"      # --module-budget : per-module cap
LIMIT="${LIMIT:-}"                        # --limit         : cap words loaded per wordlist file
CHAIN_VOCAB="${CHAIN_VOCAB:-}"           # --chain-vocab   : top-N words for hash-mode wordchain
CHAIN_WORDS="${CHAIN_WORDS:-}"           # --chain-words   : max words per chain (hash mode)
DEPTH="${DEPTH:-3}"                       # --depth         : dobwords structure depth (needs DOB)
PIN6="${PIN6:-}"                          # non-empty: --pin6 (sweep the full 6-digit PIN space)
JOBS="${JOBS:-1}"                         # --jobs          : worker processes (raise for bcrypt / --zip)
COLOR="${COLOR:-}"                        # --color         : auto / always / never

EXTRA=()                                  # escape hatch for anything else, e.g.
#   EXTRA=(--only dobwords --rules-file rules/starter.rule)

# --- LLM second opinion (opt-in, Ollama) --------------------
# When OLLAMA_MODEL is set, crack.py sends the final report to an Ollama model
# and prints its opinion as a table. Usually these come from .env (sourced
# above); set/override any of them inline too. Re-exported so the child sees them.
OLLAMA_MODEL="${OLLAMA_MODEL:-}"          # e.g. gemma2:latest / llama3.2   (empty = off)
OLLAMA_URL="${OLLAMA_URL:-}"              # full endpoint, wins if set (.../api/chat|generate)
OLLAMA_HOST="${OLLAMA_HOST:-}"            # host or base URL if OLLAMA_URL unset (bare IP ok)
OLLAMA_TEMPERATURE="${OLLAMA_TEMPERATURE:-}"   # default 0.2
OLLAMA_TIMEOUT="${OLLAMA_TIMEOUT:-}"           # seconds, default 60
OLLAMA_NUM_CTX="${OLLAMA_NUM_CTX:-}"           # context window override
export OLLAMA_MODEL OLLAMA_URL OLLAMA_HOST OLLAMA_TEMPERATURE OLLAMA_TIMEOUT OLLAMA_NUM_CTX

# --- list-modules shortcut ---------------------------------
if [[ -n "$LIST_MODULES" ]]; then
    exec ./crack.py --list-modules
fi

# --- assemble ---------------------------------------------
# Build the flag list as an array so nothing is re-split or glob-expanded.
read -ra WORD_LIST     <<< "$WORDS"
read -ra WORDLIST_LIST <<< "$WORDLIST"

if [[ -n "$ZIP" ]]; then
    ARGS=(--zip "$ZIP")
elif [[ -n "$HASHFILE" ]]; then
    ARGS=(--hashfile "$HASHFILE" --algo "$ALGO")
elif [[ "$HASH" == 0 ]]; then
    if   [[ -n "$PASSP" ]]; then ARGS=(-p "$PASSP")
    elif [[ -n "$SHOW"  ]]; then ARGS=(--show)
    else                         ARGS=()          # empty PASSP -> crack.py hidden prompt
    fi
else
    ARGS=(--hash "$HASH" --algo "$ALGO")
fi

ARGS+=(--budget "$BUDGET" --module-budget "$MODULE_BUDGET" --depth "$DEPTH" --jobs "$JOBS")

[[ -n "$SALT_PREFIX"   ]] && ARGS+=(--salt-prefix "$SALT_PREFIX")
[[ -n "$SALT_SUFFIX"   ]] && ARGS+=(--salt-suffix "$SALT_SUFFIX")
[[ -n "$DOB"           ]] && ARGS+=(--dob "$DOB")
[[ -n "$UNAME"         ]] && ARGS+=(--user "$UNAME")
[[ -n "$EMAIL"         ]] && ARGS+=(--email "$EMAIL")
[[ -n "$NAME"          ]] && ARGS+=(--name "$NAME")
[[ -n "$ONLY"          ]] && ARGS+=(--only "$ONLY")
[[ -n "$SKIP"          ]] && ARGS+=(--skip "$SKIP")
[[ -n "$RULES"         ]] && ARGS+=(--rules-file "$RULES")
[[ -n "$HYBRID_MASK"   ]] && ARGS+=(--hybrid-mask "$HYBRID_MASK")
[[ -n "$HYBRID_SIDE"   ]] && ARGS+=(--hybrid-side "$HYBRID_SIDE")
[[ -n "$HYBRID_VOCAB"  ]] && ARGS+=(--hybrid-vocab "$HYBRID_VOCAB")
[[ -n "$FUZZ"          ]] && ARGS+=(--fuzz "$FUZZ")
[[ -n "$FUZZ_VOCAB"    ]] && ARGS+=(--fuzz-vocab "$FUZZ_VOCAB")
[[ -n "$FUZZ_CHARSET"  ]] && ARGS+=(--fuzz-charset "$FUZZ_CHARSET")
[[ -n "$PERMUTE"       ]] && ARGS+=(--permute)
[[ -n "$PERMUTE_SEP"   ]] && ARGS+=(--permute-sep "$PERMUTE_SEP")
[[ -n "$PERMUTE_FILL"  ]] && ARGS+=(--permute-fill "$PERMUTE_FILL")
[[ -n "$PERMUTE_VOCAB" ]] && ARGS+=(--permute-vocab "$PERMUTE_VOCAB")
[[ -n "$MASK"          ]] && ARGS+=(--mask "$MASK")
[[ "$BRUTE" == 1       ]] && ARGS+=(--brute)
[[ -n "$CHARSET"       ]] && ARGS+=(--charset "$CHARSET")
[[ -n "$MIN"           ]] && ARGS+=(--min "$MIN")
[[ -n "$MAX"           ]] && ARGS+=(--max "$MAX")
[[ -n "$LIMIT"         ]] && ARGS+=(--limit "$LIMIT")
[[ -n "$CHAIN_VOCAB"   ]] && ARGS+=(--chain-vocab "$CHAIN_VOCAB")
[[ -n "$CHAIN_WORDS"   ]] && ARGS+=(--chain-words "$CHAIN_WORDS")
[[ -n "$PIN6"          ]] && ARGS+=(--pin6)
[[ -n "$COLOR"         ]] && ARGS+=(--color "$COLOR")

for wl in "${WORDLIST_LIST[@]:-}"; do [[ -n "$wl" ]] && ARGS+=(--wordlist "$wl"); done
for w  in "${WORD_LIST[@]:-}";     do [[ -n "$w"  ]] && ARGS+=(--word "$w"); done
[[ ${#EXTRA[@]} -gt 0 ]] && ARGS+=("${EXTRA[@]}")

# --- banner: an ASCII table of what this run will do -----
# (crack.py prints its own RUN / SUMMARY tables; this one adds what only the
#  wrapper knows -- the plaintext under a self-test, and the full arg line.)
KW=16                                      # match crack.py's RUN / SUMMARY tables
VW=56
trow() {                                   # trow <key> <value>  (value truncated to VW)
    local v="$2"
    (( ${#v} > VW )) && v="${v:0:VW-1}~"
    printf '| %-*s | %-*s |\n' "$KW" "$1" "$VW" "$v"
}
tbar() { printf '+%s+%s+\n' "$(printf -- '-%.0s' $(seq $((KW+2))))" "$(printf -- '-%.0s' $(seq $((VW+2))))"; }

clear
tbar
printf '| %-*s |\n' "$((KW+VW+3))" "test.sh"
tbar
if   [[ -n "$ZIP"      ]]; then trow mode "zip archive"; trow target "$ZIP"
elif [[ -n "$HASHFILE" ]]; then trow mode "hashfile ($ALGO)"; trow target "$HASHFILE"
elif [[ "$HASH" == 0   ]]; then trow mode "plaintext audit (-p)"; trow pass "${PASSP:-<prompt>}"
else
    trow mode "self-test / hash ($ALGO)"
    trow pass "$PASSP"
    trow hash "$HASH"
fi
trow words "$WORDS"
[[ -n "$DOB"              ]] && trow dob "$DOB"
[[ -n "$UNAME$EMAIL$NAME" ]] && trow ident "user:$UNAME email:$EMAIL name:$NAME"
trow budget "${BUDGET}M global / ${MODULE_BUDGET}M per-module   jobs:$JOBS"
[[ -n "$OLLAMA_MODEL" ]] && trow opinion "ollama $OLLAMA_MODEL @ ${OLLAMA_URL:-${OLLAMA_HOST:-localhost:11434}}"
tbar
printf 'args: ./crack.py %s\n\n' "${ARGS[*]}"

# --- run ----------------------------------------------
# `|| rc=$?` stops `set -e` aborting on crack.py's exit 3 (not found in budget).
rc=0
time ./crack.py "${ARGS[@]}" || rc=$?
case $rc in
  0) echo ">>> CRACKED" ;;
  3) echo ">>> not found in budget - raise BUDGET/MODULE_BUDGET, or EXTRA=(--mask '<shape>')" ;;
  *) echo ">>> crack.py exited $rc" ;;
esac
exit $rc
