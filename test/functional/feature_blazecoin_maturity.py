#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin: coinbase maturity is enforced (COINBASE_MATURITY = 30).

A freshly mined coinbase is immature and unspendable; after enough confirmations it
matures and can be spent. (The exact constant is pinned by the unit test
validation_tests/blazecoin_coinbase_maturity; this checks the behaviour end-to-end.)
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BlazecoinMaturityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        # Skip import_deterministic_coinbase_privkeys() (Bitcoin-prefixed WIF).
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="mat")
        addr = node.getnewaddress("", "legacy")

        # One coinbase (height 1, the premine) — immature, nothing spendable yet.
        self.generatetoaddress(node, 1, addr)
        mine = node.getbalances()["mine"]
        assert_equal(mine["trusted"], 0)
        assert mine["immature"] > 0
        assert_raises_rpc_error(-6, "Insufficient funds",
                                node.sendtoaddress, node.getnewaddress("", "legacy"), 1)

        # Mine well past maturity; the coinbase becomes spendable.
        self.generatetoaddress(node, 101, addr)
        assert node.getbalances()["mine"]["trusted"] > 0
        node.sendtoaddress(node.getnewaddress("", "legacy"), 1)  # now succeeds
        self.log.info("Blazecoin coinbase maturity behaviour verified on regtest.")


if __name__ == '__main__':
    BlazecoinMaturityTest(__file__).main()
