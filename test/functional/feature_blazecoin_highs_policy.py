#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin: high-S (non-canonical) signatures relay.

Blazecoin removed SCRIPT_VERIFY_LOW_S from the standard (mempool/relay) script
verify flags so that legacy 0.8.x sends — roughly half of which carry a high-S
ECDSA signature — relay and get mined on V2 Core. Stock Bitcoin Core rejects
such a transaction from the mempool ("non-mandatory-script-verify-flag,
Non-canonical signature: S value is unnecessarily high"); this test pins that
Blazecoin accepts it. A low-S spend is checked alongside as a control.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.address import key_to_p2pkh
from test_framework.key import ECKey, ORDER
from test_framework.messages import COIN, CTransaction, CTxIn, CTxOut, COutPoint
from test_framework.script import CScript, LegacySignatureHash, SIGHASH_ALL, sign_input_legacy
from test_framework.script_util import key_to_p2pkh_script
from test_framework.util import assert_equal


def parse_der_s(der):
    """Return the S integer from a DER-encoded ECDSA signature
    (SEQUENCE: 30 len 02 rlen <r> 02 slen <s>)."""
    rlen = der[3]
    slen = der[5 + rlen]
    return int.from_bytes(der[6 + rlen:6 + rlen + slen], 'big')


def high_s_der(privkey, sighash):
    """A DER ECDSA signature with S in the upper half of the curve order
    (s > n/2) — the non-canonical form that LOW_S rejects. (r, s) and (r, n-s)
    are both valid signatures; sign with a random nonce until S lands high."""
    while True:
        der = privkey.sign_ecdsa(sighash, low_s=False)
        if parse_der_s(der) > ORDER // 2:
            return der


class BlazecoinHighSPolicyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        # Skip import_deterministic_coinbase_privkeys() (Bitcoin-prefixed WIF);
        # this test crafts its own keys/txs and uses no wallet.
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def build_spend(self, cb_txid, cb_value, spk, pub):
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(cb_txid, 16), 0)))
        tx.vout.append(CTxOut(int(cb_value * COIN) - 10000, spk))  # 0.0001 BLZ fee
        tx.vin[0].scriptSig = CScript([pub])  # P2PKH: pubkey push; sig prepended next
        return tx

    def run_test(self):
        node = self.nodes[0]
        key = ECKey()
        key.generate()
        pub = key.get_pubkey().get_bytes()
        addr = key_to_p2pkh(pub)
        spk = key_to_p2pkh_script(pub)

        # Throwaway sink so the premine (block 1) and filler blocks don't land on
        # our key; our spendable coinbase is the single one at height 2.
        sink_key = ECKey()
        sink_key.generate()
        sink = key_to_p2pkh(sink_key.get_pubkey().get_bytes())

        self.generatetoaddress(node, 1, sink)    # height 1 (premine) -> sink
        self.generatetoaddress(node, 1, addr)    # height 2 -> our target coinbase
        cb = node.getblock(node.getblockhash(2), 2)['tx'][0]
        cb_txid, cb_value = cb['txid'], cb['vout'][0]['value']
        self.generatetoaddress(node, 100, sink)  # mature the target coinbase

        # Control: a normal low-S spend relays.
        tx_low = self.build_spend(cb_txid, cb_value, spk, pub)
        sign_input_legacy(tx_low, 0, spk, key)   # prepends a canonical low-S sig
        res_low = node.testmempoolaccept([tx_low.serialize_without_witness().hex()])[0]
        assert_equal(res_low['allowed'], True)

        # The fix: the same spend with a high-S signature also relays on Blazecoin
        # (stock Bitcoin would reject it as a non-canonical S value).
        tx_high = self.build_spend(cb_txid, cb_value, spk, pub)
        sighash, err = LegacySignatureHash(spk, tx_high, 0, SIGHASH_ALL)
        assert err is None
        der = high_s_der(key, sighash)
        assert parse_der_s(der) > ORDER // 2, "signature is not high-S"
        tx_high.vin[0].scriptSig = (bytes(CScript([der + bytes([SIGHASH_ALL])]))
                                    + bytes(tx_high.vin[0].scriptSig))
        tx_high.rehash()
        res_high = node.testmempoolaccept([tx_high.serialize_without_witness().hex()])[0]
        assert_equal(res_high['allowed'], True)

        self.log.info("Blazecoin high-S (non-canonical) signature relay verified on regtest.")


if __name__ == '__main__':
    BlazecoinHighSPolicyTest(__file__).main()
