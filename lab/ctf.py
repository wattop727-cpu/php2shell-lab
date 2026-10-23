#!/usr/bin/env python3
"""php2shell CTF driver (local lab only).

  Level 1  fingerprint 8.5.11 vs 8.5.12
  Level 2  stale BG(unserialize) after a fatal OOM (CLI)
  Level 3  stale PS(id) survives into the next worker request (HTTP)

Run:  python3 lab/ctf.py
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

LAB = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(LAB)
RUNTIME = os.path.join(PROJ, "runtime")
WWW = os.path.join(LAB, "www")
FLAGS = os.path.join(LAB, "flags")
VULN_PORT, FIXED_PORT = 8111, 8112


def flag(name):
    with open(os.path.join(FLAGS, name)) as f:
        return f.read().strip()


def alive(port):
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:%d/probe.php" % port, timeout=2
        ) as r:
            return json.loads(r.read())
    except Exception:
        return None


def php(version, *args, **kw):
    return subprocess.run(
        [os.path.join(RUNTIME, "php-" + version, "bin", "php"), "-n"] + list(args),
        capture_output=True,
        text=True,
        timeout=120,
        **kw,
    )


def router_sh():
    subprocess.run([os.path.join(LAB, "run.sh")], check=True)
    for _ in range(50):
        if alive(VULN_PORT) and alive(FIXED_PORT):
            return
        time.sleep(0.1)
    raise SystemExit("servers did not start")


def level1():
    print("\n== Level 1: fingerprint ==")
    v, f = alive(VULN_PORT), alive(FIXED_PORT)
    print("8111 -> PHP", v["version"], "patched:", v["patched_8_5_12"])
    print("8112 -> PHP", f["version"], "patched:", f["patched_8_5_12"])
    if not v["patched_8_5_12"] and f["patched_8_5_12"]:
        print("FLAG-1:", flag("flag1.txt"))
        return True
    print("unexpected version pair")
    return False


def level2():
    print("\n== Level 2: stale BG(unserialize) after fatal OOM ==")
    script = os.path.join(LAB, "challenges", "stale_state.php")
    ok = True
    for version in ("8.5.11", "8.5.12"):
        r = php(
            version,
            "-d",
            "memory_limit=8M",
            "-d",
            "display_errors=1",
            script,
        )
        out = r.stdout + r.stderr
        leaked = "FLAG-2:" in out
        print("PHP %s -> %s" % (version, "LEAKED" if leaked else "clean"))
        if version == "8.5.11" and not leaked:
            ok = False
        if version == "8.5.12" and leaked:
            ok = False
    if ok:
        print("FLAG-2:", flag("flag2.txt"))
        print("  (8.5.11 resolved R:1 into the aborted array; 8.5.12 reset the var_hash)")
    return ok


def level3():
    print("\n== Level 3: stale PS(id) across requests ==")
    script = os.path.join(LAB, "exploit", "disclose.py")

    def attack(port):
        subprocess.run(
            [sys.executable, script, "127.0.0.1", str(port), "8000"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        time.sleep(0.3)
        return alive(port)

    v = attack(VULN_PORT)
    print("8.5.11 worker after two-request sequence:", "DEAD" if v is None else "alive")
    f = attack(FIXED_PORT)
    print("8.5.12 worker after two-request sequence:", "DEAD" if f is None else "alive")

    if v is None and f is not None:
        print("FLAG-3:", flag("flag3.txt"))
        print("  (8.5.11 used the freed PS(id); 8.5.12 reset session globals at MULTIPART_EVENT_START)")
        return True
    print("expected: vulnerable worker dies, patched worker survives")
    return False


def main():
    router_sh()
    results = []
    try:
        results.append(level1())
        results.append(level2())
        results.append(level3())
    finally:
        subprocess.run([os.path.join(LAB, "stop.sh")], check=False)

    print("\n== summary ==")
    for i, ok in enumerate(results, 1):
        print("level %d: %s" % (i, "PASS" if ok else "FAIL"))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
