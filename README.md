# php2shell lab (CVE-2026-109618 / CVE-2026-109619)

A self-contained, loopback-only A/B lab for understanding **php2shell**, the two
critical PHP-core memory-safety bugs disclosed on 2026-10-21.

| CVE | Class | Impact |
|---|---|---|
| CVE-2026-109618 | upload-progress unserializer use-after-free | remote process-memory disclosure + RCE |
| CVE-2026-109619 | fatal-error backtrace UAF / OPcache type confusion | RCE |

Both are CVSS 9.2, affect PHP 5.4+, and live **below the application**: a
"Hello World" page is enough. Fixed in PHP **8.2.35, 8.3.36, 8.4.27, 8.5.12**
(EOL branches got source backports). Reported by Wiz Research on 2026-08-24,
disclosed 2026-10-21 after details leaked.

This lab builds real **PHP 8.5.11 (vulnerable)** and **PHP 8.5.12 (fixed)**
from the official release tarballs and runs both on `127.0.0.1`. No Docker
daemon is required; `bootstrap.sh` builds natively. It reproduces two of the
underlying primitives, not the full heap-groomed RCE chain.

## From a clean checkout

`src/` and `runtime/` are gitignored. Build both engines first:

```sh
./bootstrap.sh        # fetch PHP 8.5.11/8.5.12, build php + php-cgi
```

Requires `curl`, `tar`, `make`, and a C compiler (`base-devel` /
`build-essential`), plus network access to `php.net`. No `re2c` or `autoconf`
is needed: the official tarballs ship generated parsers and `configure`.

## Quick start

The runtimes are already built in this checkout. On a fresh clone, run
`./bootstrap.sh` first.

```sh
python3 lab/ctf.py
```

Expected:

```
== Level 1: fingerprint ==
FLAG-1: FLAG{php2shell_8_5_11_is_vulnerable_8_5_12_is_fixed}
== Level 2: stale BG(unserialize) after fatal OOM ==
PHP 8.5.11 -> LEAKED
PHP 8.5.12 -> clean
FLAG-2: ...
== Level 3: stale PS(id) across requests ==
8.5.11 worker after two-request sequence: DEAD
8.5.12 worker after two-request sequence: alive
FLAG-3: ...
```

Manual use:

```sh
./lab/run.sh      # vulnerable :8111, patched :8112, loopback only
./lab/stop.sh
```

Logs land in `lab/logs`. To run the actual upstream 8.5.12 regression tests
against both engines:

```sh
./lab/verify-upstream.sh
```

## The three levels

### Level 1 - fingerprint (`lab/exploit/probe.py`)

`probe.php` reports `PHP_VERSION` and whether it is >= 8.5.12. This is the
recon step: php2shell is a *version* problem, not a plugin/CMS problem.

### Level 2 - stale `BG(unserialize)` (`lab/challenges/stale_state.php`)

This is the shape of the new `Zend/tests/oom_unserialize_016.phpt`:

1. `unserialize()` a large structure until the 8 MB `memory_limit` is hit.
2. The fatal OOM tears down the request heap but, on 8.5.11, leaves
   `BG(unserialize)` (the unserializer's var_hash table) published.
3. A shutdown-time `unserialize('a:1:{i:0;R:1;}')` then resolves `R:1` into the
   **aborted previous array** instead of its own.
4. The flag is at index 0 of that aborted array, so `$r[0][0]` is the flag on
   8.5.11. On 8.5.12 the delayed-OOM cleanup reset the var_hash and `R:1`
   means "this array" (`*RECURSION*`).

This is the stale-global-state primitive behind CVE-2026-109619's family.

### Level 3 - stale `PS(id)` across requests (`lab/exploit/disclose.py`)

This is the shape of `tests/basic/oom_rfc1867_upload_progress.phpt`. Multipart
parsing happens during **request startup, before RINIT**:

1. **Request A** is a multipart upload with `PHPSESSID` +
   `PHP_SESSION_UPLOAD_PROGRESS` and thousands of file parts. The progress
   handler re-encodes `$_SESSION` until `memory_limit` is exhausted. The OOM
   aborts the request before `MULTIPART_EVENT_END`, so the session cleanup that
   would release `PS(id)` never runs.
2. **Request B** has the session id and progress key but **no file part**, so
   `MULTIPART_EVENT_FILE_START` never runs and `PS(id)` is not overwritten.
   `MULTIPART_EVENT_END -> php_session_rfc1867_cleanup()` then dereferences the
   freed `PS(id)` before session RINIT resets it.
3. On 8.5.11 the worker dies (the freed `zend_string` header is not a valid
   length/content pair). On 8.5.12 `MULTIPART_EVENT_START` calls
   `php_rinit_session_globals()` early, so the worker survives and handles the
   request normally.

Turning that dangling `PS(id)` dereference into a controlled memory disclosure
(the `PHPSESSID` cookie leak described by Wiz) or RCE requires cross-request
heap grooming and is intentionally left as the research exercise. The lab
demonstrates the bug is reachable; it is not a weaponized exploit.

## Upstream regression tests

`lab/verify-upstream.sh` runs the tests that shipped with 8.5.12 against both
engines (CGI build required):

| Test | 8.5.11 | 8.5.12 | What it proves |
|---|---|---|---|
| `Zend/tests/oom_unserialize_016.phpt` | FAIL | PASS | `BG(unserialize)` var_hash survives a fatal OOM |
| `ext/session/tests/rfc1867_no_user_code.phpt` | FAIL | PASS | pre-RINIT progress update damages the session record |
| `tests/basic/oom_rfc1867_upload_progress.phpt` | PASS | PASS | OOM happens at the expected point in both |

The last row is deliberately not a differential: that test asserts the fatal
OOM output, not that a persistent worker survives the next request. The
cross-request consequence is what `lab/ctf.py` Level 3 exercises.

## Why the fix is interesting

PHP 8.5.12 is not a one-liner. It adds a **fallible allocator** and a
**delayed-OOM state machine**, plus early session-global resets. See
[`lab/patch-notes.md`](lab/patch-notes.md) for the actual 8.5.11 -> 8.5.12
hunks and the tests that encode each reproducer.

Key ideas:

- `ZEND_HAS_OOM()` / `EG(delayed_oom)`: record an OOM instead of longjmp-ing out
  in the middle of initialization, then handle it at a safe point.
- `femalloc`/`fecalloc`/`ferealloc`: callers can recover from allocation
  failure instead of leaving partial state behind.
- `shutdown_executor()` clears `EG(last_fatal_error_backtrace)` and related
  executor globals before the next request can use them.
- `PS(in_rfc1867_update)`: during upload-progress, session data is decoded as
  `__PHP_Incomplete_Class` only - no autoload, `__wakeup`, `__unserialize`, or
  serialization callbacks run before RINIT.
- `php_rinit_session_globals()` at `MULTIPART_EVENT_START` clears the previous
  request's `PS(id)` before parsing can use it.

## Layout

```
bootstrap.sh             fetch + build both engines from php.net
runtime/php-8.5.11/      built vulnerable PHP (php + php-cgi)
runtime/php-8.5.12/      built patched PHP (php + php-cgi)
src/php-8.5.11/          official release source (PHP 8.5.11)
src/php-8.5.12/          official release source (PHP 8.5.12)
lab/www/                 app (index.php, probe.php)
lab/challenges/          Level 2 CLI reproducer
lab/exploit/             probe, RFC1867 OOM sender, two-request probe
lab/flags/               flags (don't peek)
lab/run.sh, stop.sh      manual A/B servers
lab/ctf.py               driver for all levels
lab/verify-upstream.sh   upstream 8.5.12 regression tests vs both engines
lab/patch-notes.md       patch analysis
```

`src/` and `runtime/` are gitignored; `bootstrap.sh` recreates them.

## Rebuilding

`./bootstrap.sh` is idempotent: it skips engines that already have both
`php` and `php-cgi`, and rebuilds from an existing `src/` tree if the runtime
is missing. To rebuild one engine manually:

```sh
cd src/php-8.5.11
./configure --prefix="$PWD/../../runtime/php-8.5.11" \
  --disable-all --enable-cli --enable-cgi --enable-session --disable-phpdbg \
  --without-pear CFLAGS='-O1 -g'
make -j"$(nproc)" && make install
```

Same for 8.5.12. `--enable-cgi` is needed by `verify-upstream.sh`; the lab
servers use the CLI `php -S` binary. The official tarballs ship generated
parsers, so `re2c` is not needed.

## Safety

- Both servers bind to `127.0.0.1` only.
- `disclose.py` and `rfc1867_oom.py` refuse non-loopback targets.
- This is an isolated teaching lab. Do not point these scripts at systems you
  do not own. For production, the only complete fix is the patched PHP release.

## References

- PHP security release: <https://www.php.net/archive/2026.php>
- Wiz Research technical writeup: <https://www.wiz.io/blog/php2shell-php-rce>
- Sansec analysis / exploitability notes: <https://sansec.io/research/php2shell>
- Tenable FAQ: <https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote>
- NCSC-NL operational repo: <https://github.com/NCSC-NL/php2shell>
