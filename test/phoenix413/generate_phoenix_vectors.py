#!/usr/bin/env python3
"""Phoenix-413 canonical reference implementation + test-vector generator.

This file is the AUTHORITY for Phoenix-413 semantics (spec: PHOENIX_413.md in
Blazecoin_Wallet_V2_Core). Every consensus implementation (V1.5 C++ CBigNum/BN,
V2 C++ arith_uint256, lite-wallet C#) must reproduce these vectors bit-exactly.

Algorithm: aserti3-2d fixed-point form (BCH mainnet since Nov 2020, MIT),
with Blazecoin constants:
    T   = 30 s        (target spacing)
    tau = 12,390 s    (half-life = 413 blocks - the chain's signature number)
    powLimit = 2^236 - 1   (== ~uint256(0) >> 20, bnProofOfWorkLimit)

Semantics pinned here (implementations MUST match):
  * exponent = C-style TRUNCATING division of
        (timeDiff - T*(heightDiff+1)) * 65536  by  tau
    (truncation toward zero - matches the aserti3-2d reference)
  * shifts = exponent >> 16 with ARITHMETIC shift (floor) on the signed value
  * frac = low 16 bits of exponent, two's-complement
  * cubic 2^frac approximation with the aserti3-2d constants, uint64 domain
  * target = (refTarget * factor) then net-shift by (shifts - 16);
    right shifts floor; zero -> 1; clamp to powLimit
  * compact encode/decode: Bitcoin compact for positive targets
    (identical to V1.5 CBigNum::SetCompact/GetCompact and Core arith_uint256)

Anchor convention (spec section 2.1): refTarget = nBits OF block H_A (the last
old-rule target); anchorParentTime = timestamp of block H_A - 1;
heightDiff = (evalHeight - 1) - H_A. The rule computes the target FOR block
evalHeight (> H_A) from the timestamp of its parent (evalHeight - 1).

Outputs (deterministic - no RNG seeded from time):
    phoenix413_vectors.json      canonical vector file
    ../../src/phoenix413_vectors.h  C++ header for the standalone harness
"""

import json
import os

T = 30
TAU = 12390
POW_LIMIT = (1 << 236) - 1


def set_compact(c):
    """Compact -> integer target (positive targets only)."""
    size = c >> 24
    word = c & 0x007FFFFF
    if size <= 3:
        return word >> (8 * (3 - size))
    return word << (8 * (size - 3))


def get_compact(n):
    """Integer target -> compact (positive targets only)."""
    size = (n.bit_length() + 7) // 8
    if size <= 3:
        compact = n << (8 * (3 - size))
    else:
        compact = n >> (8 * (size - 3))
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return compact | (size << 24)


def trunc_div(a, b):
    """C-style integer division: truncation toward zero. b > 0."""
    q = abs(a) // b
    return -q if a < 0 else q


def phoenix_next_bits(anchor_bits, anchor_parent_time, anchor_height,
                      eval_height, parent_time):
    """Target (compact) for the block at eval_height (> anchor_height)."""
    assert eval_height > anchor_height
    ref = set_compact(anchor_bits)
    time_diff = parent_time - anchor_parent_time
    height_diff = (eval_height - 1) - anchor_height
    num = (time_diff - T * (height_diff + 1)) * 65536
    exponent = trunc_div(num, TAU)
    shifts = exponent >> 16          # Python >> floors: matches C arithmetic shift
    frac = exponent & 0xFFFF         # low 16 bits, two's complement: matches C
    factor = 65536 + ((195766423245049 * frac
                       + 971821376 * frac * frac
                       + 5127 * frac * frac * frac
                       + (1 << 47)) >> 48)
    target = ref * factor
    net = shifts - 16
    target = (target >> -net) if net < 0 else (target << net)
    if target == 0:
        target = 1
    if target > POW_LIMIT:
        target = POW_LIMIT
    return get_compact(target)


def main():
    vectors = []

    def add(name, ab, apt, ah, eh, pt):
        vectors.append({
            "name": name,
            "anchor_bits": ab, "anchor_parent_time": apt, "anchor_height": ah,
            "eval_height": eh, "parent_time": pt,
            "expect_bits": phoenix_next_bits(ab, apt, ah, eh, pt),
        })

    A_BITS = 0x1D00FFFF          # mid-range anchor
    A_TIME = 1600000000
    A_H = 4500000

    # -- steady state: exactly on schedule at several depths -----------------
    for dh in (0, 1, 412, 413, 9999):
        eh = A_H + 1 + dh
        pt = A_TIME + T * dh     # parent (eh-1) exactly on schedule
        add("steady_dh%d" % dh, A_BITS, A_TIME, A_H, eh, pt)

    # -- single-block jitter around schedule ---------------------------------
    for off in (-29, -1, 1, 29, 300, -300):
        add("jitter_%+d" % off, A_BITS, A_TIME, A_H, A_H + 2, A_TIME + T + off)

    # -- exact half-life boundaries: +/- k * tau of schedule deficit ---------
    for k in (1, 2, 3, 4, 5):
        add("stall_%dhalflife" % k, A_BITS, A_TIME, A_H, A_H + 1,
            A_TIME + T + k * TAU)
        add("surge_%dhalflife" % k, A_BITS, A_TIME, A_H, A_H + 1,
            A_TIME + T - k * TAU)

    # -- strand-and-recover: farm left at 23x / 100x (elapsed = R * ideal) ---
    for r in (13, 23, 100):
        dh = 1000
        ideal = T * (dh + 1)
        add("strand_%dx" % r, A_BITS, A_TIME, A_H, A_H + 1 + dh,
            A_TIME + r * ideal)

    # -- 2h future-time abuse (max transient ~1.5x) ---------------------------
    add("future_abuse_7200", A_BITS, A_TIME, A_H, A_H + 2, A_TIME + T + 7200)

    # -- deep stall -> powLimit clamp (start from an easy anchor) ------------
    add("clamp_powlimit", 0x1E0FFFFF, A_TIME, A_H, A_H + 1,
        A_TIME + 400 * TAU)

    # -- absurd surge -> target floors at 1 (hard anchor, huge negative exp) -
    add("clamp_one", 0x03000001, A_TIME, A_H, A_H + 1, A_TIME - 3000 * TAU)

    # -- different anchors ----------------------------------------------------
    for ab, tag in ((0x1E0FFFFF, "easy"), (0x1B04864C, "hard"),
                    (0x1C05A3F4, "mid")):
        add("anchor_%s_steady" % tag, ab, A_TIME, A_H, A_H + 3, A_TIME + 2 * T)
        add("anchor_%s_stall" % tag, ab, A_TIME, A_H, A_H + 3,
            A_TIME + 2 * T + TAU)

    # -- deterministic 120-block sequential walk (LCG solve times) ----------
    # Each block's target is computed from the SAME anchor (absolute rule);
    # solve times wander 5..90 s.  Verifies no drift accumulates.
    lcg = 0x413
    pt = A_TIME
    for i in range(120):
        lcg = (1103515245 * lcg + 12345) % (1 << 31)
        pt += 5 + (lcg % 86)
        eh = A_H + 2 + i          # parent height A_H+1+i has timestamp pt
        if i % 10 == 0:           # keep the file readable: every 10th block
            add("walk_%03d" % i, A_BITS, A_TIME, A_H, eh, pt)

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "phoenix413_vectors.json"), "w") as f:
        json.dump({"T": T, "tau": TAU, "pow_limit_bits": get_compact(POW_LIMIT),
                   "vectors": vectors}, f, indent=1)

    hpath = os.path.normpath(os.path.join(here, "..", "..", "src",
                                          "phoenix413_vectors.h"))
    with open(hpath, "w") as f:
        f.write("// Generated by contrib/phoenix413/generate_phoenix_vectors.py"
                " - DO NOT EDIT.\n")
        f.write("// Canonical Phoenix-413 test vectors; see PHOENIX_413.md"
                " (Blazecoin_Wallet_V2_Core).\n")
        f.write("#ifndef PHOENIX413_VECTORS_H\n#define PHOENIX413_VECTORS_H\n\n")
        f.write("struct Phoenix413Vector {\n"
                "    const char* name;\n"
                "    unsigned int anchor_bits;\n"
                "    long long anchor_parent_time;\n"
                "    long long anchor_height;\n"
                "    long long eval_height;\n"
                "    long long parent_time;\n"
                "    unsigned int expect_bits;\n};\n\n")
        f.write("static const Phoenix413Vector PHOENIX413_VECTORS[] = {\n")
        for v in vectors:
            f.write('    { "%s", 0x%08xu, %dLL, %dLL, %dLL, %dLL, 0x%08xu },\n'
                    % (v["name"], v["anchor_bits"], v["anchor_parent_time"],
                       v["anchor_height"], v["eval_height"], v["parent_time"],
                       v["expect_bits"]))
        f.write("};\n\nstatic const unsigned int PHOENIX413_VECTOR_COUNT = "
                "sizeof(PHOENIX413_VECTORS)/sizeof(PHOENIX413_VECTORS[0]);\n\n"
                "#endif // PHOENIX413_VECTORS_H\n")

    print("wrote %d vectors" % len(vectors))
    # quick sanity prints
    print("steady keeps anchor bits:",
          hex(phoenix_next_bits(A_BITS, A_TIME, A_H, A_H + 1, A_TIME)))
    one_hl = phoenix_next_bits(A_BITS, A_TIME, A_H, A_H + 1, A_TIME + T + TAU)
    print("one half-life stall doubles target:", hex(one_hl),
          "(ratio %.4f)" % (set_compact(one_hl) / set_compact(A_BITS)))


if __name__ == "__main__":
    main()
