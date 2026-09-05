#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin: backupwallet -> restorewallet round-trip preserves the balance."""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlazecoinBackupRestoreTest(BitcoinTestFramework):
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
        node.createwallet(wallet_name="orig")
        w = node.get_wallet_rpc("orig")
        addr = w.getnewaddress("", "legacy")
        self.generatetoaddress(node, 101, addr)  # give the wallet a spendable balance
        bal = w.getbalance()
        assert bal > 0

        backup = os.path.join(self.options.tmpdir, "blz_wallet.bak")
        w.backupwallet(backup)

        node.restorewallet("restored", backup)
        wr = node.get_wallet_rpc("restored")
        assert_equal(wr.getbalance(), bal)
        self.log.info("Blazecoin backup/restore round-trip verified on regtest.")


if __name__ == '__main__':
    BlazecoinBackupRestoreTest(__file__).main()
