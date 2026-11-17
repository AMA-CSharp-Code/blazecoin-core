#!/usr/bin/env python3
"""
Smoke-run the post-quantum fuzz targets (src/test/fuzz/pq_script.cpp) over a generated seed corpus, using the fuzz
binary's file-input runner (no libFuzzer needed: works with the MSVC build and a plain gcc --enable-fuzz build).

    python test/pqsig/run_pq_fuzz_seeds.py [--fuzz-bin PATH] [--seeds N] [--out DIR] [--target NAME ...]

Every seed is a file; the runner executes the target once per file and must exit 0 (an assertion in a target is
an abort, which this script reports as a failure with the seed path kept for reproduction). Seeds mix random
bytes of varied length with structured prefixes (a fixed key seed followed by random bytes), so the valid-spend
path and each scripted mutation case in pq_spend are reached. For coverage-guided fuzzing use a libFuzzer build
(clang, ./configure --enable-fuzz --with-sanitizers=fuzzer) and point it at the --out directory as its corpus.
"""
import argparse
import os
import random
import subprocess
import sys
import time

TARGETS = ("mldsa44", "pq_sighash", "pq_spend")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def default_fuzz_bin():
    for p in (os.path.join(ROOT, "build_msvc", "fuzz", "x64", "Release", "fuzz.exe"),
              os.path.join(ROOT, "build_msvc", "x64", "Release", "fuzz.exe"),
              os.path.join(ROOT, "src", "test", "fuzz", "fuzz")):
        if os.path.exists(p):
            return p
    return None


def make_seeds(out, target, n, rng):
    d = os.path.join(out, target)
    os.makedirs(d, exist_ok=True)
    paths = []
    for i in range(n):
        kind = i % 4
        if kind == 0:
            data = rng.randbytes(rng.choice((0, 1, 7, 31, 32, 33, 64)))
        elif kind == 1:
            data = rng.randbytes(rng.randint(40, 400))
        elif kind == 2:
            data = bytes([i & 0xff]) * 32 + rng.randbytes(rng.randint(0, 200))    # fixed key seed, random rest
        else:
            data = rng.randbytes(rng.randint(400, 7000))
        p = os.path.join(d, f"seed-{i:04d}.bin")
        with open(p, "wb") as f:
            f.write(data)
        paths.append(p)
    return paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fuzz-bin", default=default_fuzz_bin())
    ap.add_argument("--seeds", type=int, default=64)
    ap.add_argument("--out", default=os.path.join(ROOT, "build_msvc", "fuzz", "pq-corpus"))
    ap.add_argument("--target", action="append", choices=TARGETS)
    ap.add_argument("--rng-seed", type=int, default=413)
    a = ap.parse_args()
    if not a.fuzz_bin or not os.path.exists(a.fuzz_bin):
        sys.exit("fuzz binary not found; build build_msvc/fuzz (MSVC) or ./configure --enable-fuzz, or pass --fuzz-bin")
    rng = random.Random(a.rng_seed)
    failures = 0
    for target in a.target or TARGETS:
        paths = make_seeds(a.out, target, a.seeds, rng)
        env = dict(os.environ, FUZZ=target)
        t0 = time.time()
        r = subprocess.run([a.fuzz_bin, *paths], env=env, capture_output=True, text=True)
        dt = time.time() - t0
        if r.returncode == 0:
            print(f"{target:12} {len(paths)} seeds OK in {dt:.1f} s")
            continue
        failures += 1
        print(f"{target:12} FAILED (exit {r.returncode}) after {dt:.1f} s; bisecting to the first failing seed...")
        for p in paths:
            rr = subprocess.run([a.fuzz_bin, p], env=env, capture_output=True, text=True)
            if rr.returncode != 0:
                print(f"   first failing seed: {p}")
                print("   " + (rr.stderr or rr.stdout).strip().replace("\n", "\n   ")[-1500:])
                break
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
