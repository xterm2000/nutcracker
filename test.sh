#!/usr/bin/env bash
set -euo pipefail

# --- target -----------------------------------------------------------------
PASSP='p@$$word123'              # only used to build a self-test hash
ALGO="md5"
HASH="${HASH:-$(printf '%s' "$PASSP" | md5sum | awk '{print $1}')}"   # or: export HASH=...

# --- what you know about the owner ----------------------------------------
WORDS="word1 word2"   # space-separated; each becomes --word X
DOB=""                             # empty string to disable
UNAME=""                                   # --user  : login / handle
EMAIL=""                                   # --email : full address
NAME=""                                    # --name  : full name, e.g. "Mary Smith"

# --- extra inputs -------------------------------------------------------------
WORDLIST=""                                # --wordlist  : extra list, loaded first (rockyou.txt, cewl.txt)
RULES=""                                   # --rules-file: hashcat-style ruleset (rules/starter.rule)
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
