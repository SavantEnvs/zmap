#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

ZBL="$SRC/mayhem/build/normal/src/zblocklist"
JA4="$SRC/mayhem/build/test_ja4ts"
for x in "$ZBL" "$JA4"; do
  [ -x "$x" ] || { echo "missing $x: mayhem/build.sh did not produce it" >&2; emit_ctrf "zmap" 0 1 0; exit 1; }
done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
printf '%s\n' '10.0.0.0/8         # private subnet' '192.168.0.0/16     # private subnet' \
  '128.255.0.0/16     # university of iowa' '141.212.120.0/24   # halderman lab' > "$T/blocklist"
printf '%s\n' '141.212.0.0/16    # university of michigan' > "$T/allowlist"
IPS=(61.193.80.24 195.19.1.6 114.34.253.25 180.69.174.9 38.134.130.203 192.168.1.50 98.125.221.180
     197.160.60.150 47.139.63.128 95.224.78.221 170.114.52.252 10.0.0.5 128.255.134.1 141.212.120.10 141.212.12.6)
printf '%s\n' "${IPS[@]}" > "$T/ips"
for ip in "${IPS[@]}"; do
  for c in '# some comment here' ' # some comment here' ',google.com,data' $'\t#some comment here'; do
    printf '%s%s\n' "$ip" "$c"
  done
done > "$T/ips-commented"

MINUS_BL=$(printf '%s\n' 61.193.80.24 195.19.1.6 114.34.253.25 180.69.174.9 38.134.130.203 98.125.221.180 \
  197.160.60.150 47.139.63.128 95.224.78.221 170.114.52.252 141.212.12.6 | sort)
WL_ONLY=$(printf '%s\n' 141.212.120.10 141.212.12.6 | sort)
WL_MINUS_BL=141.212.12.6

passed=0; failed=0
check() { # name expected actual
  if [ -n "$3" ] && [ "$2" = "$3" ]; then passed=$((passed+1)); echo "PASS $1"
  else failed=$((failed+1)); echo "FAIL $1" >&2; printf 'expected:\n%s\nactual:\n%s\n' "$2" "$3" >&2; fi
}

check zblocklist_blocklist "$MINUS_BL" "$("$ZBL" -b "$T/blocklist" < "$T/ips" | sort)"
check zblocklist_allowlist "$WL_ONLY" "$("$ZBL" -w "$T/allowlist" < "$T/ips" | sort)"
check zblocklist_allow_and_block "$WL_MINUS_BL" "$("$ZBL" -w "$T/allowlist" -b "$T/blocklist" < "$T/ips" | sort)"
dups=$(for _ in 1 2 3 4 5; do cat "$T/ips"; done | "$ZBL" -b "$T/blocklist")
check zblocklist_dedup_count "11" "$(printf '%s\n' "$dups" | grep -c .)"
check zblocklist_dedup_set "$MINUS_BL" "$(printf '%s\n' "$dups" | sort)"
check zblocklist_comment_characters "$MINUS_BL" "$("$ZBL" -b "$T/blocklist" < "$T/ips-commented" | sed 's/^\([0-9.]*\).*/\1/' | sort -u)"

ja4_out="$("$JA4" 2>&1)"
ja4_pass=$(printf '%s\n' "$ja4_out" | grep -c '^PASS')
ja4_fail=$(printf '%s\n' "$ja4_out" | grep -c '^FAIL')
if [ "$ja4_pass" -eq 10 ] && [ "$ja4_fail" -eq 0 ]; then
  passed=$((passed+10)); echo "PASS ja4ts known-answer (10)"
else
  failed=$((failed+1)); echo "FAIL ja4ts known-answer: pass=$ja4_pass fail=$ja4_fail" >&2; printf '%s\n' "$ja4_out" >&2
fi

emit_ctrf "zmap-oracle" "$passed" "$failed" 0
