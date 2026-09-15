#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin: cross-check the running daemon's regtest chain params against the source.

The C++ ChainParams_*_sanity unit tests validate the params structs in-process; this asserts
the LIVE daemon agrees — most importantly that the regtest genesis block hash the node builds
matches the constant pinned (and asserted) in kernel/chainparams.cpp. A regression here means the
genesis params (time/bits/nonce/merkle) were changed, which would fork every regtest chain.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# kernel/chainparams.cpp regtest: CreateGenesisBlock(1296688602, 0, 0x207fffff, 1, 50*COIN),
# assert(hashGenesisBlock == d062f37...0062).
REGTEST_GENESIS = "d062f3721f1261bf3542870d0399e67432554efb448bb6046a576128467a0062"


class BlazecoinChainParamsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True  # start at genesis (height 0)

    def setup_nodes(self):
        # Skip the framework's Bitcoin-WIF coinbase-key import (Blazecoin rejects it).
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]

        # Chain identity + clean start.
        assert_equal(node.getblockchaininfo()["chain"], "regtest")
        assert_equal(node.getblockcount(), 0)

        # Genesis hash the daemon built must equal the source-pinned constant.
        assert_equal(node.getblockhash(0), REGTEST_GENESIS)
        assert_equal(node.getbestblockhash(), REGTEST_GENESIS)

        # Genesis block shape: version 1, exactly the coinbase tx, no parent.
        genesis = node.getblock(REGTEST_GENESIS)
        assert_equal(genesis["height"], 0)
        assert_equal(genesis["version"], 1)
        assert_equal(genesis["nTx"], 1)
        assert "previousblockhash" not in genesis  # genesis has no parent

        self.log.info("Blazecoin regtest genesis + chain identity match kernel/chainparams.cpp.")


if __name__ == '__main__':
    BlazecoinChainParamsTest(__file__).main()
