#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin: coinbase maturity boundary is exactly COINBASE_MATURITY = 30.

A coinbase output becomes spendable only once it is 30 confirmations deep: a
spend of it is rejected with bad-txns-premature-spend-of-coinbase at 29
confirmations and accepted at 30. This pins the exact off-by-one at the
consensus layer via testmempoolaccept (which evaluates against spend height
tip+1), complementing the unit test validation_tests/blazecoin_coinbase_maturity
that pins the constant and feature_blazecoin_maturity.py that checks the general
behaviour.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.address import key_to_p2pkh
from test_framework.key import ECKey
from test_framework.messages import COIN, CTransaction, CTxIn, CTxOut, COutPoint
from test_framework.script import CScript, sign_input_legacy
from test_framework.script_util import key_to_p2pkh_script
from test_framework.util import assert_equal


class BlazecoinMaturityBoundaryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        # Skip import_deterministic_coinbase_privkeys() (Bitcoin-prefixed WIF);
        # this test crafts its own key/tx and uses no wallet.
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]
        key = ECKey()
        key.generate()
        pub = key.get_pubkey().get_bytes()
        addr = key_to_p2pkh(pub)
        spk = key_to_p2pkh_script(pub)

        sink_key = ECKey()
        sink_key.generate()
        sink = key_to_p2pkh(sink_key.get_pubkey().get_bytes())

        # Target coinbase at height 2 (height 1 premine goes to the sink).
        self.generatetoaddress(node, 1, sink)
        self.generatetoaddress(node, 1, addr)
        cb = node.getblock(node.getblockhash(2), 2)['tx'][0]
        cb_txid, cb_value = cb['txid'], cb['vout'][0]['value']

        # Build the spend once; its validity now hinges only on coinbase maturity.
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(cb_txid, 16), 0)))
        tx.vout.append(CTxOut(int(cb_value * COIN) - 10000, spk))  # 0.0001 BLZ fee
        tx.vin[0].scriptSig = CScript([pub])
        sign_input_legacy(tx, 0, spk, key)
        raw = tx.serialize_without_witness().hex()

        # Advance to tip 30 -> the height-2 coinbase has 29 confirmations.
        self.generatetoaddress(node, 28, sink)
        assert_equal(node.getblockcount(), 30)
        res = node.testmempoolaccept([raw])[0]
        assert_equal(res['allowed'], False)
        assert 'premature-spend-of-coinbase' in res['reject-reason'], res['reject-reason']

        # One more block -> 30 confirmations -> spendable.
        self.generatetoaddress(node, 1, sink)
        assert_equal(node.getblockcount(), 31)
        res = node.testmempoolaccept([raw])[0]
        assert_equal(res['allowed'], True)

        self.log.info("Blazecoin coinbase maturity boundary (spendable at 30 confs) verified on regtest.")


if __name__ == '__main__':
    BlazecoinMaturityBoundaryTest(__file__).main()
