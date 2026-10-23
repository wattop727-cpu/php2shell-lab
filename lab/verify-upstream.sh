#!/usr/bin/env bash
# Run the upstream PHP 8.5.12 regression tests against both engines.
# The tests live in the 8.5.12 tree; running them against 8.5.11 is intentional.
set -uo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(dirname "$LAB")"
SRC="$PROJ/src/php-8.5.12"
P="$PROJ/runtime"
LOGS="$LAB/logs"
mkdir -p "$LOGS"

for v in 8.5.11 8.5.12; do
  [[ -x "$P/php-$v/bin/php-cgi" ]] || {
    echo "missing $P/php-$v/bin/php-cgi; rebuild with --enable-cgi" >&2
    exit 1
  }
done

fail=0
run_test() {
  local ver="$1" test="$2" want="$3" label="$4"
  local log="$LOGS/upstream-$ver-$(basename "$test").log" got
  if ( cd "$SRC" &&
       TEST_PHP_EXECUTABLE="$P/php-$ver/bin/php" \
       TEST_PHP_CGI_EXECUTABLE="$P/php-$ver/bin/php-cgi" \
       NO_COLOR=1 "$P/php-$ver/bin/php" run-tests.php -q "$test" ) >"$log" 2>&1; then
    got=PASS
  else
    got=FAIL
  fi
  printf '  %-7s %-50s %-4s (want %s)\n' "$ver" "$label" "$got" "$want"
  [[ "$got" == "$want" ]] || fail=1
}

echo "== upstream regression tests =="
run_test 8.5.11 Zend/tests/oom_unserialize_016.phpt FAIL "oom_unserialize_016 (stale BG(unserialize))"
run_test 8.5.12 Zend/tests/oom_unserialize_016.phpt PASS "oom_unserialize_016 (stale BG(unserialize))"
run_test 8.5.11 ext/session/tests/rfc1867_no_user_code.phpt FAIL "rfc1867_no_user_code (pre-RINIT session)"
run_test 8.5.12 ext/session/tests/rfc1867_no_user_code.phpt PASS "rfc1867_no_user_code (pre-RINIT session)"
run_test 8.5.11 tests/basic/oom_rfc1867_upload_progress.phpt PASS "oom_rfc1867_upload_progress (OOM point only)"
run_test 8.5.12 tests/basic/oom_rfc1867_upload_progress.phpt PASS "oom_rfc1867_upload_progress (OOM point only)"

echo
echo "note: oom_rfc1867_upload_progress passes on both engines. It asserts the"
echo "      OOM output, not that a persistent worker survives the next request;"
echo "      that differential is exercised by lab/ctf.py Level 3."

if (( fail )); then
  echo "unexpected result: see $LOGS/upstream-*.log" >&2
  exit 1
fi
echo "all expectations met"
