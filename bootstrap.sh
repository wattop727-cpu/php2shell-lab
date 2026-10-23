#!/usr/bin/env bash
# Fetch and build the vulnerable (8.5.11) and patched (8.5.12) PHP engines.
# Builds both the CLI (used by the lab server) and CGI (used by upstream tests).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="https://www.php.net/distributions"
VERSIONS=(8.5.11 8.5.12)

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing build dependency: $1" >&2
    echo "install a C toolchain and make (e.g. base-devel / build-essential)" >&2
    exit 1
  }
}
need curl
need tar
need make
need cc

mkdir -p "$ROOT/src" "$ROOT/runtime"

for v in "${VERSIONS[@]}"; do
  src="$ROOT/src/php-$v"
  prefix="$ROOT/runtime/php-$v"

  if [[ -x "$prefix/bin/php" && -x "$prefix/bin/php-cgi" ]]; then
    echo "== PHP $v already built at $prefix"
    continue
  fi

  if [[ ! -d "$src" ]]; then
    echo "== downloading PHP $v"
    tgz="$ROOT/src/php-$v.tar.gz"
    curl -fL --retry 3 --retry-delay 2 -o "$tgz" "$BASE/php-$v.tar.gz"
    tar -xzf "$tgz" -C "$ROOT/src"
    rm -f "$tgz"
  fi

  echo "== building PHP $v"
  (
    cd "$src"
    ./configure \
      --prefix="$prefix" \
      --disable-all \
      --enable-cli \
      --enable-cgi \
      --enable-session \
      --disable-phpdbg \
      --without-pear \
      CFLAGS='-O1 -g'
    make -j"$(nproc)"
    make install
  )
  echo "== installed $prefix/bin/php and $prefix/bin/php-cgi"
done

echo
echo "done. Next:"
echo "  python3 lab/ctf.py"
echo "  ./lab/verify-upstream.sh"
