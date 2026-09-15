#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin Era 3 — Phoenix-413 per-block ASERT retarget (PHOENIX_413.md).

Activates Phoenix on regtest via -testactivationheight=phoenix413@H_A and
asserts, against an in-test Python mirror of the canonical reference
(test/phoenix413/generate_phoenix_vectors.py), that the LIVE daemon's
GetNextWorkRequired produces bit-exact targets:
  * blocks at height <= H_A keep the old rule (powLimit bits on regtest),
  * every block above H_A matches the mirror fed with the real anchor
    (block H_A's nBits + block H_A-1's timestamp) and real parent timestamps,
  * a multi-half-life stall clamps back to powLimit,
  * a reorg across the post-fork region recomputes correctly on the new branch
    (GetAncestor makes the anchor branch-correct).

Regtest runs the upstream Bitcoin cadence (spacing 600 s — deliberately NOT
Blazecoin-tuned, see DESIGN_AUDIT D1), so the mirror uses T=600 and
tau = 413*T: the half-life is 413 BLOCKS on every network.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

H_A = 210
T = 600                    # regtest nPowTargetSpacing (upstream cadence, per D1)
TAU = 413 * T              # half-life: 413 blocks on every network
POW_LIMIT_BITS = 0x207fffff
T0 = 1600000000


def set_compact(c):
    size = c >> 24
    word = c & 0x007FFFFF
    if size <= 3:
        return word >> (8 * (3 - size))
    return word << (8 * (size - 3))


def get_compact(n):
    size = (n.bit_length() + 7) // 8
    if size <= 3:
        compact = n << (8 * (3 - size))
    else:
        compact = n >> (8 * (size - 3))
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return compact | (size << 24)


POW_LIMIT = set_compact(POW_LIMIT_BITS)


def trunc_div(a, b):
    q = abs(a) // b
    return -q if a < 0 else q


def phoenix_next_bits(anchor_bits, anchor_parent_time, anchor_height,
                      eval_height, parent_time):
    ref = set_compact(anchor_bits)
    time_diff = parent_time - anchor_parent_time
    height_diff = (eval_height - 1) - anchor_height
    num = (time_diff - T * (height_diff + 1)) * 65536
    exponent = trunc_div(num, TAU)
    shifts = exponent >> 16
    frac = exponent & 0xFFFF
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


class BlazecoinPhoenix413Test(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=phoenix413@{H_A}"]]

    def setup_nodes(self):
        # Skip the framework's Bitcoin-WIF coinbase-key import (Blazecoin rejects it).
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def bits_at(self, node, height):
        return int(node.getblockheader(node.getblockhash(height))["bits"], 16)

    def time_at(self, node, height):
        return node.getblockheader(node.getblockhash(height))["time"]

    def assert_phoenix_bits(self, node, heights, anchor_parent_time):
        """Every block in `heights` must match the mirror, fed real timestamps."""
        for h in heights:
            expected = phoenix_next_bits(POW_LIMIT_BITS, anchor_parent_time,
                                         H_A, h, self.time_at(node, h - 1))
            assert_equal(self.bits_at(node, h), expected)

    def run_test(self):
        node = self.nodes[0]
        node.setmocktime(T0)
        node.createwallet(wallet_name="miner")
        addr = node.getnewaddress()

        self.log.info(f"Mine to the activation height H_A={H_A}; old rule holds")
        self.generatetoaddress(node, H_A, addr)
        assert_equal(node.getblockcount(), H_A)
        for h in (1, 100, H_A):
            assert_equal(self.bits_at(node, h), POW_LIMIT_BITS)
        anchor_parent_time = self.time_at(node, H_A - 1)

        self.log.info("Post-H_A: every block's nBits matches the Phoenix mirror")
        self.generatetoaddress(node, 20, addr)
        self.assert_phoenix_bits(node, range(H_A + 1, H_A + 21), anchor_parent_time)
        # Mining fast (frozen mocktime) runs AHEAD of schedule: difficulty rose.
        assert set_compact(self.bits_at(node, H_A + 20)) < POW_LIMIT

        self.log.info("A multi-half-life stall decays difficulty back to the powLimit clamp")
        node.setmocktime(T0 + 8 * TAU)
        self.generatetoaddress(node, 2, addr)
        tip = node.getblockcount()
        self.assert_phoenix_bits(node, [tip - 1, tip], anchor_parent_time)
        # The second block's parent carries the post-stall timestamp -> clamped.
        assert_equal(self.bits_at(node, tip), POW_LIMIT_BITS)

        self.log.info("Reorg across the post-fork region: the new branch recomputes correctly")
        node.invalidateblock(node.getblockhash(tip - 1))
        assert_equal(node.getblockcount(), tip - 2)
        # Advance mocktime so the replacement blocks differ from the
        # invalidated ones (identical times would regenerate the same hashes,
        # which the node correctly refuses to re-accept).
        node.setmocktime(T0 + 8 * TAU + 120)
        self.generatetoaddress(node, 3, addr)
        new_tip = node.getblockcount()
        assert_equal(new_tip, tip + 1)
        self.assert_phoenix_bits(node, range(tip - 1, new_tip + 1), anchor_parent_time)

        self.log.info("Phoenix-413 regtest activation: all live targets bit-exact vs the reference mirror")


if __name__ == '__main__':
    BlazecoinPhoenix413Test(__file__).main()
