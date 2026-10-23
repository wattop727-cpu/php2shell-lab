# php2shell: what changed between PHP 8.5.11 and 8.5.12

These are excerpts from the official release tarballs in `../src/`, picked to
explain the lab. Line numbers are from 8.5.12.

## Root cause in one paragraph

A web SAPI parses the request body **before** module RINIT. If a request dies
half-way through that pre-initialization window - typically an out-of-memory
`zend_error_noreturn(E_ERROR, ...)` bailout - PHP's request heap is destroyed
but some executor/extension globals still point into it. A later request on the
same worker (FPM process, `mod_php` process, etc.) can consume that stale state
as if it were live. Session upload progress gives an attacker a way to enter
this window and to allocate/free attacker-influenced data there.

8.5.12 fixes it at the engine level, not by special-casing sessions.

## 1. Delayed OOM + fallible allocation (`Zend/zend_alloc.h`)

```c
typedef enum _zend_oom_state {
    ZEND_OOM_STATE_NONE = 0,
    ZEND_OOM_STATE_PENDING,
    ZEND_OOM_STATE_HANDLING,
    ZEND_OOM_STATE_HANDLED
} zend_oom_state;

typedef struct _zend_oom_info {
    zend_oom_state state;
    uint32_t lineno;
    zend_string *message;
    zend_string *filename;
} zend_oom_info;

#define ZEND_HAS_OOM() (UNEXPECTED(EG(delayed_oom).state != ZEND_OOM_STATE_NONE))
```

The old allocator longjmp-ed (bailout) at the point the limit was exceeded.
The new code records a pending OOM and handles it at a safe point, so partially
initialized structures can be unwound normally. It also adds fallible variants:

```c
ZEND_API void* _femalloc(size_t size ...);
ZEND_API void* _fecalloc(size_t nmemb, size_t size ...);
ZEND_API void* _ferealloc(void *ptr, size_t size ...);
#define femalloc(size, fallible) ...
```

`Zend/zend_alloc.c` gains `zend_mm_delayed_error_or_panic()`,
`zend_handle_delayed_oom()` and `zend_mm_oom_info_dtor()`. Large parts of the
tree were converted to the fallible API - hence the 659-line `zend_alloc.c`
diff and the many `Zend/tests/oom_*.phpt` tests.

## 2. Executor globals cleaned before reuse (`Zend/zend_execute_API.c`)

In `shutdown_executor()`, after freeing the object store:

```c
+	/* may be used by zend_error_zstr_at before init_executor */
+	ZVAL_UNDEF(&EG(last_fatal_error_backtrace));
+	EG(record_errors) = false;
+	EG(num_errors) = 0;
+	EG(errors) = NULL;
+	EG(error_handling) = EH_NORMAL;
+	EG(exception) = NULL;
```

`EG(last_fatal_error_backtrace)` is the pointer behind CVE-2026-109619's
fatal-error backtrace UAF: it could survive a fatal OOM and be used by the next
request. `zend_call_function()` and the VM now also check `ZEND_HAS_OOM()` and
call `zend_handle_delayed_oom()` instead of continuing with partial state.

## 3. No uncaught-exception walk while handling OOM (`Zend/zend.c`)

```c
-	if (EG(exception)) {
+	if (EG(exception) && EXPECTED(EG(delayed_oom).state != ZEND_OOM_STATE_HANDLING)) {
```

and after execution:

```c
 	zend_execute(op_array, retval);
+	if (ZEND_HAS_OOM()) {
+		zend_handle_delayed_oom();
+	}
```

## 4. Session upload progress (`ext/session/session.c`)

### a. No user code during pre-RINIT decoding

```c
+	PS(in_rfc1867_update) = false;
```

```c
+/* The upload progress handler ... decodes and re-encodes the session during
+ * request startup, before RINIT, when no user code may run. Objects are then
+ * kept as __PHP_Incomplete_Class: no autoloading, no unserialize_callback_func,
+ * no __wakeup() or __unserialize(), and they are written back unchanged. */
+static void php_session_unserialize_init(php_unserialize_data_t *var_hash)
+{
+	PHP_VAR_UNSERIALIZE_INIT(*var_hash);
+	if (PS(in_rfc1867_update)) {
+		php_var_unserialize_set_incomplete_classes_only(*var_hash, true);
+	}
+}
```

All session serializers switch from `PHP_VAR_(UN)SERIALIZE_INIT` to these
helpers. This closes the "run a gadget before the app even starts" angle.

### b. Clear previous request's session globals at parse start

```c
 		case MULTIPART_EVENT_START: {
 			multipart_event_start *data = (multipart_event_start *) event_data;
+
+			/* This runs before RINIT, so we need to clear these early */
+			php_rinit_session_globals();
+
 			progress = ecalloc(1, sizeof(php_session_rfc1867_progress));
```

This is the exact fix for the Level 3 stale `PS(id)` (which was set in
`MULTIPART_EVENT_FILE_START` and released only in the END cleanup or RSHUTDOWN).

### c. Handle initialization failure; do not install `$_SESSION` early

```c
-	php_session_initialize();
-	PS(session_status) = php_session_active;
+	PS(in_rfc1867_update) = true;
+	if (php_session_initialize() == FAILURE || PS(session_status) != php_session_active) {
+		PS(in_rfc1867_update) = false;
+		return;
+	}
```

and at END:

```c
+			/* $_SESSION was populated in incomplete_classes_only mode */
+			zend_string *session_var_name = ZSTR_INIT_LITERAL("_SESSION", 0);
+			zend_delete_global_variable(session_var_name);
+			zend_string_release_ex(session_var_name, 0);
```

Also: `request_parse_body()` no longer runs the progress handler after modules
are active, and a failed `s_create_sid` aborts instead of falling back to a
fresh id.

## 5. The tests that encode the reproducers

- `Zend/tests/oom_unserialize_016.phpt` - "OOM unserialize() cleans up
  BG(unserialize) after a delayed OOM". Exactly the Level 2 primitive.
- `tests/basic/oom_rfc1867_upload_progress.phpt` - forces OOM in the
  upload-progress re-encode via many file parts / huge field/name /
  huge progress value. Level 3 uses the "many file parts" shape.
- `Zend/tests/oom_request_parsing.phpt` - POST parsing OOM at
  `memory_limit=8M`; uses `php-cgi` and `fatal_error_backtraces=Off`.
- `ext/session/tests/rfc1867_no_user_code.phpt` - checks that the progress
  handler resolves no classes, preserves the session record, and removes the
  temporary `$_SESSION`.

Observed with `lab/verify-upstream.sh` (CGI build):

| Test | 8.5.11 | 8.5.12 |
|---|---|---|
| `oom_unserialize_016.phpt` | FAIL (leaked array) | PASS |
| `rfc1867_no_user_code.phpt` | FAIL (record damaged) | PASS |
| `oom_rfc1867_upload_progress.phpt` | PASS | PASS |

The RFC1867 OOM test passes on both because it only asserts where the fatal OOM
is reported; it does not send a second request. The stale-worker consequence is
covered by Level 3 instead.

## 6. Map to the lab

| Level | Primitive | 8.5.11 | 8.5.12 |
|---|---|---|---|
| 1 | version fingerprint | `PHP/8.5.11` | `PHP/8.5.12` |
| 2 | stale `BG(unserialize)` after fatal OOM | `R:1` resolves into aborted array, flag leaks | var_hash reset, `*RECURSION*` |
| 3 | stale `PS(id)` across requests (RFC1867) | freed id dereferenced, worker dies | globals reset at `MULTIPART_EVENT_START`, request succeeds |

The public `php2shell` exploit goes further: it uses the disclosure primitive to
defeat ASLR, then heap-grooms the freed request heap to build a write/execute
primitive. That multi-step work is the part this lab deliberately does not
automate.
