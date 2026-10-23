#!/usr/bin/env bash
# Start the php2shell A/B lab. Both servers bind to loopback only.
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(dirname "$LAB")"
VULN="$PROJ/runtime/php-8.5.11/bin/php"
FIXED="$PROJ/runtime/php-8.5.12/bin/php"
WWW="$LAB/www"
LOGS="$LAB/logs"
mkdir -p "$LOGS"

for b in "$VULN" "$FIXED"; do
  [[ -x "$b" ]] || { echo "missing $b (build the runtimes first)" >&2; exit 1; }
done

"$LAB/stop.sh" >/dev/null 2>&1 || true

start_one() {
  local name="$1" bin="$2" port="$3"
  local sess="$LOGS/sess-$name"
  mkdir -p "$sess"
  nohup "$bin" -n \
    -d memory_limit=8M \
    -d display_errors=1 \
    -d log_errors=0 \
    -d max_file_uploads=200000 \
    -d max_multipart_body_parts=200000 \
    -d post_max_size=1G \
    -d upload_max_filesize=1G \
    -d session.upload_progress.enabled=1 \
    -d session.save_path="$sess" \
    -d session.upload_progress.freq=1 \
    -d session.upload_progress.min_freq=0 \
    -d session.use_strict_mode=0 \
    -S "127.0.0.1:$port" -t "$WWW" \
    >"$LOGS/server-$name.log" 2>&1 &
  echo $! >"$LAB/.pid-$name"
}

start_one vuln "$VULN" 8111
start_one patched "$FIXED" 8112

for port in 8111 8112; do
  for _ in $(seq 1 50); do
    curl -fsS -m 1 "http://127.0.0.1:$port/probe.php" >/dev/null 2>&1 && break
    sleep 0.1
  done
done

echo "vulnerable: http://127.0.0.1:8111   (PHP 8.5.11)"
echo "patched:    http://127.0.0.1:8112   (PHP 8.5.12)"
echo "logs:       $LOGS"
