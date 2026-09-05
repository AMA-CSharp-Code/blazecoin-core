#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run the full Blazecoin test gate: the C++ Boost unit suite, then the functional tests.

Thin wrapper so a single-argument "default" launch target in Visual Studio
(.vs/launch.vs.json) can run the whole Blazecoin suite. Set BITCOIND to point at
src/blazecoind.exe before running (the launch target does this for you).

Unit suite: runs test_blazecoin.exe (the MSVC Boost binary) with NO --run_test filter —
as of 2026-07-06 the whole binary is green with zero exclusions (see
BLAZECOIN_DESIGN_AUDIT.md D4), and running it here is what keeps it from rotting again.
Override the binary location with the TEST_BLAZECOIN env var; if the binary is missing
the unit stage FAILS (build build_msvc/test_bitcoin first) rather than silently skipping.

Wrapper-only flags (not forwarded to test_runner.py):
  --functional-only   skip the Boost unit suite
  --unit-only         skip the functional tests
Anything else (e.g. --jobs=2) is forwarded to test_runner.py."""

import os
import runpy
import subprocess
import sys

# On Windows the default cp1252 stdout raises UnicodeEncodeError on non-Latin-1 glyphs *after*
# the tests have already passed, which test_runner.py then miscounts as a FAILURE. Two sources:
#   1) test_runner.py builds a tmpdir with unicode in its name (…_₿_🏃_…) that each child test
#      logs on shutdown ("Cleaning up <tmpdir>") — the crash happens in the CHILD process, so the
#      env var must propagate to subprocesses, not just this wrapper.
#   2) the results table prints ✓/✖ glyphs in THIS process.
# Force UTF-8 for both: reconfigure our own streams, and export PYTHONIOENCODING so every child
# test subprocess test_runner.py spawns inherits it. Without this the VS play-button target reports
# green tests as failed.
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

BLAZECOIN_TESTS = [
    "feature_blazecoin_subsidy.py",
    "feature_blazecoin_maturity.py",
    "feature_blazecoin_maturity_boundary.py",
    "feature_blazecoin_highs_policy.py",
    "feature_blazecoin_send_receive.py",
    "feature_blazecoin_backup_restore.py",
    "feature_blazecoin_chainparams.py",
    "feature_blazecoin_policy_defaults.py",
    "feature_blazecoin_phoenix413.py",
]


def find_unit_test_binary(repo_root):
    """Locate test_blazecoin — TEST_BLAZECOIN env var first, then known build outputs."""
    env = os.environ.get("TEST_BLAZECOIN")
    if env:
        return env if os.path.isfile(env) else None
    candidates = [
        os.path.join(repo_root, "build_msvc", "test_bitcoin", "x64", "Release", "test_blazecoin.exe"),
        os.path.join(repo_root, "build_msvc", "test_bitcoin", "x64", "Debug", "test_blazecoin.exe"),
        os.path.join(repo_root, "src", "test", "test_blazecoin"),  # autotools builds
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def run_unit_suite(repo_root):
    """Run the whole Boost binary (no --run_test filter). Returns process exit code."""
    binary = find_unit_test_binary(repo_root)
    if binary is None:
        print("run_blazecoin_tests: FAIL — test_blazecoin binary not found "
              "(build build_msvc/test_bitcoin, or set TEST_BLAZECOIN). "
              "The unit stage is a required part of the gate; use --functional-only to bypass deliberately.")
        return 1
    print(f"run_blazecoin_tests: running Boost unit suite: {binary}")
    # --catch_system_errors=yes turns crashes into named failures instead of killing the
    # process with its buffered output (which presents as an empty log + exit 127).
    result = subprocess.run([
        binary,
        "--catch_system_errors=yes",
        "--log_level=error",
        "--report_level=short",
    ])
    print(f"run_blazecoin_tests: Boost unit suite {'PASSED' if result.returncode == 0 else 'FAILED'} "
          f"(exit {result.returncode})")
    return result.returncode


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))

    args = sys.argv[1:]
    unit_only = "--unit-only" in args
    functional_only = "--functional-only" in args
    forwarded = [a for a in args if a not in ("--unit-only", "--functional-only")]

    unit_rc = 0
    if not functional_only:
        unit_rc = run_unit_suite(repo_root)
        if unit_only:
            sys.exit(unit_rc)

    functional_rc = 0
    if not unit_only:
        sys.argv = ["test_runner.py", *BLAZECOIN_TESTS, *forwarded]
        try:
            runpy.run_path(os.path.join(here, "test_runner.py"), run_name="__main__")
        except SystemExit as e:
            functional_rc = int(e.code or 0)

    sys.exit(unit_rc or functional_rc)
