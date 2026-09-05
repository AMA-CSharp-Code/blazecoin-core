#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin: the fee + address policy defaults baked into the binary — free-send works out of the box.

Blazecoin zeroes the fee floors so the V1.5 free-send history relays and mines
(DEFAULT_MIN_RELAY_TX_FEE / DEFAULT_BLOCK_MIN_TX_FEE = 0, policy.h) and defaults new addresses
to LEGACY (DEFAULT_ADDRESS_TYPE, wallet.h) because SegWit is consensus-disabled and a blz1...
address would lock funds.

Finding D3 (now FIXED at the binary level): DEFAULT_MIN_RELAY_TX_FEE=0 used to be silently
overridden at startup — node/mempool_args.cpp bumps min_relay_feerate up to incremental_relay_feerate
when -minrelaytxfee is unset, and DEFAULT_INCREMENTAL_RELAY_FEE was Bitcoin's stock 1000, so a
default node re-floored the relay fee to 0.00001 and rejected 0-fee relay. policy.h now also sets
DEFAULT_INCREMENTAL_RELAY_FEE=0, so nothing bumps the relay fee and the 0 default stands with NO conf.

This pins that a DEFAULT-configured node (no -minrelaytxfee, no conf) already:
  - reports incrementalrelayfee = 0, minrelaytxfee = 0, relayfee = 0,
  - yields a non-witness (legacy) address from getnewaddress with no type, and
  - accepts a genuinely 0-fee transaction into the mempool.
If a future rebuild reverts DEFAULT_INCREMENTAL_RELAY_FEE to a non-zero value, the first assertion
fails — the signal that the D3 regression is back.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class BlazecoinPolicyDefaultsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        # Skip the framework's Bitcoin-WIF coinbase-key import (Blazecoin rejects it).
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]

        # 1) DEFAULT config (no -minrelaytxfee, no conf): all three fee floors are 0. The key one is
        #    incrementalrelayfee — if it is non-zero, mempool_args.cpp re-floors minrelaytxfee and the
        #    D3 free-send regression is back.
        info = node.getmempoolinfo()
        assert_equal(info["incrementalrelayfee"], Decimal(0))
        assert_equal(info["minrelaytxfee"], Decimal(0))
        assert_equal(node.getnetworkinfo()["relayfee"], Decimal(0))

        # 2) Default address type is LEGACY — getnewaddress WITHOUT a type must be non-witness.
        node.createwallet(wallet_name="policy")
        default_addr = node.getnewaddress()  # no type arg -> exercises DEFAULT_ADDRESS_TYPE
        assert_equal(node.getaddressinfo(default_addr)["iswitness"], False)
        assert not default_addr.startswith("bcrt1"), f"default address is bech32: {default_addr}"

        # 3) A genuinely 0-fee tx is accepted by relay policy with NO special startup flags. Mine past
        #    coinbase maturity (30), spend a mature coinbase in full (output == input -> fee 0), relay it.
        addr = node.getnewaddress("", "legacy")
        self.generatetoaddress(node, 35, addr)
        assert_greater_than(node.getblockcount(), 30)

        utxo = node.listunspent(1)[0]  # only mature/spendable coinbases are listed
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            {node.getnewaddress("", "legacy"): utxo["amount"]},  # send it ALL -> zero fee
        )
        signed = node.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)

        result = node.testmempoolaccept([signed["hex"]])[0]
        assert_equal(result["allowed"], True)
        assert_equal(result["fees"]["base"], Decimal(0))  # exactly zero fee, still relayable

        self.log.info("Blazecoin policy defaults verified: incrementalrelayfee/minrelaytxfee/relayfee all 0, "
                      "legacy default address, 0-fee relay accepted with no conf (D3 fixed in-binary).")


if __name__ == '__main__':
    BlazecoinPolicyDefaultsTest(__file__).main()
