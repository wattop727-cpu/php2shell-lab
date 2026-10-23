#!/usr/bin/env bash
# Stop the php2shell A/B lab.
LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for name in vuln patched; do
  pidfile="$LAB/.pid-$name"
  if [[ -f "$pidfile" ]]; then
    kill "$(cat "$pidfile")" 2>/dev/null || true
    rm -f "$pidfile"
  fi
done
exit 0
