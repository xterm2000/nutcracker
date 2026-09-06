#!/usr/bin/env bash
set -euo pipefail

# --- target -----------------------------------------------------------------
PASSP="mama1604solomakha1983sasha"              # only used to build a self-test hash
ALGO="md5"
HASH="${HASH:-$(printf '%s' "$PASSP" | md5sum | awk '{print $1}')}"   # or: export HASH=...

# --- what you know about the owner ----------------------------------------
WORDS="solomakha mama sasha"               # space-separated; each becomes --word X
DOB="22041983"                             # empty string to disable

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
[[ -n "$DOB"  ]] && ARGS+=(--dob "$DOB")
[[ "$BRUTE" == 1 ]] && ARGS+=(--brute)
for w in "${WORD_LIST[@]}"; do ARGS+=(--word "$w"); done
[[ ${#EXTRA[@]} -gt 0 ]] && ARGS+=("${EXTRA[@]}")

clear
printf 'pass  == %s ==\n' "$PASSP"
printf 'hash  == %s ==\n' "$HASH"
printf 'algo  == %s ==\n' "$ALGO"
printf 'words == %s ==\n' "$WORDS"
printf 'dob   == %s ==\n' "$DOB"
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
