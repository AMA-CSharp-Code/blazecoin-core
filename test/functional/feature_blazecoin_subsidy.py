#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin: verify the block-reward schedule on regtest.

Premine at height 1 (20,650,000 BLZ), early tier 13 BLZ (heights 2..99), base tier
413 BLZ (heights >= 100). Uses getblockstats()['subsidy'] (block subsidy in sat).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

COIN = 100_000_000


class BlazecoinSubsidyTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)  # enable the wallet (default: descriptor) so createwallet works

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True  # start from genesis (height 0)

    def setup_nodes(self):
        # Blazecoin: skip the framework's import_deterministic_coinbase_privkeys() —
        # it imports a Bitcoin-prefixed WIF that Blazecoin's wallet rejects. We make
        # our own wallet + legacy address in run_test instead.
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="subsidy")
        # Legacy P2PKH address — Blazecoin has SegWit disabled, so never mine to blz1...
        addr = node.getnewaddress("", "legacy")

        self.generatetoaddress(node, 100, addr)
        assert_equal(node.getblockcount(), 100)

        assert_equal(node.getblockstats(1)["subsidy"], 20_650_000 * COIN)  # premine
        assert_equal(node.getblockstats(2)["subsidy"], 13 * COIN)          # early (first after premine)
        assert_equal(node.getblockstats(99)["subsidy"], 13 * COIN)         # early (last)
        assert_equal(node.getblockstats(100)["subsidy"], 413 * COIN)       # base (first)
        self.log.info("Blazecoin subsidy schedule verified on regtest (premine/13/413).")


if __name__ == '__main__':
    BlazecoinSubsidyTest(__file__).main()
