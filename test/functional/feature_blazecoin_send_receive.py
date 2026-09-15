#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin: end-to-end send/receive between two wallets on one regtest node."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlazecoinSendReceiveTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="sender")
        node.createwallet(wallet_name="receiver")
        ws = node.get_wallet_rpc("sender")
        wr = node.get_wallet_rpc("receiver")

        a_send = ws.getnewaddress("", "legacy")
        self.generatetoaddress(node, 101, a_send)  # fund sender + mature the premine coinbase
        assert ws.getbalance() > 0

        a_recv = wr.getnewaddress("", "legacy")
        ws.sendtoaddress(a_recv, 1000)
        assert_equal(wr.getbalances()["mine"]["untrusted_pending"], 1000)  # seen, unconfirmed
        self.generatetoaddress(node, 1, a_send)

        assert_equal(wr.getbalance(), 1000)
        assert_equal(wr.getreceivedbyaddress(a_recv), 1000)
        self.log.info("Blazecoin send/receive verified on regtest.")


if __name__ == '__main__':
    BlazecoinSendReceiveTest(__file__).main()
