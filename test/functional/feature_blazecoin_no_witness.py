#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin: nothing to do with SegWit is admitted while SegWit is not active (bug-bounty reports 2026-11-06).

SegWit is never active on mainnet (SegwitHeight = BLAZECOIN_BIP_NEVER_ACTIVE), so a block may carry no witness
data and a witness output can never be spent. Two reports:
  * a standard witness spend was admitted to the mempool, picked by the block assembler, and every block template then
    failed TestBlockValidity ("unexpected-witness") - no block could be built while it was there;
  * the node wallet made bech32 / bech32m addresses on request and paid them (and -changetype=bech32 sent every send's
    change to one), losing the coins for good.

This test runs a node with SegWit pushed far out of reach (the mainnet state) and checks that
  * a v0 (P2WPKH) and a v1 (Taproot key-path) spend are both refused at admission with "no-witness-yet";
  * a transaction that would CREATE a witness output is refused with "no-witness-outputs-yet";
  * the wallet refuses to make a witness address, to pay one, to use one for change, or to spend a witness coin;
  * blocks keep being produced, before and after, by getblocktemplate and generate alike.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

SEGWIT_NEVER = 1_000_000


class BlazecoinNoWitnessTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=segwit@{SEGWIT_NEVER}", "-acceptnonstdtxn=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        # Skip the framework's Bitcoin-WIF coinbase-key import (Blazecoin rejects it).
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def mines_a_block(self, to):
        node = self.nodes[0]
        before = node.getblockcount()
        node.getblocktemplate({"rules": ["segwit"]})        # used to throw "unexpected-witness"
        self.generatetoaddress(node, 1, to)
        assert_equal(node.getblockcount(), before + 1)

    def own_witness_address(self, wallet, descriptor_prefix):
        """An address of the wallet's own witness descriptor - obtained without the RPCs that now refuse to make one."""
        desc = next(d["desc"] for d in wallet.listdescriptors(True)["descriptors"] if d["desc"].startswith(descriptor_prefix) and not d["internal"])
        return self.nodes[0].deriveaddresses(desc, [0, 0])[0]

    def witness_coin(self, wallet, addr, back_to):
        """Puts 1 BLZ on a witness address by mining a hand-built block (consensus allows the OUTPUT; the mempool no
        longer does), and returns the wallet's signed spend of it - which carries witness data."""
        node = self.nodes[0]
        coin = wallet.listunspent()[0]
        raw = wallet.createrawtransaction([{"txid": coin["txid"], "vout": coin["vout"]}], {addr: 1, back_to: coin["amount"] - 1})
        funding = wallet.signrawtransactionwithwallet(raw)["hex"]
        assert_equal(node.testmempoolaccept([funding])[0]["reject-reason"], "no-witness-outputs-yet")   # the mempool will not help
        self.generateblock(node, back_to, [funding])
        funding_txid = node.decoderawtransaction(funding)["txid"]
        vout = next(o["n"] for o in node.decoderawtransaction(funding)["vout"] if o["scriptPubKey"].get("address") == addr)
        spend = wallet.createrawtransaction([{"txid": funding_txid, "vout": vout}], {back_to: Decimal("0.999")})
        signed = wallet.signrawtransactionwithwallet(spend)
        assert_equal(signed["complete"], True)
        assert node.decoderawtransaction(signed["hex"])["vin"][0].get("txinwitness"), "the spend carries witness data"
        return (funding_txid, vout), signed["hex"]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", descriptors=True)
        w = node.get_wallet_rpc("w")
        legacy = w.getnewaddress("", "legacy")
        self.generatetoaddress(node, 110, legacy)
        assert_equal(node.getdeploymentinfo()["deployments"]["segwit"]["active"], False)

        self.log.info("The wallet will not make a witness address, pay one, or send change to one")
        for address_type in ("bech32", "bech32m"):
            assert_raises_rpc_error(None, "SegWit is not active", w.getnewaddress, "", address_type)
            assert_raises_rpc_error(None, "SegWit is not active", w.getrawchangeaddress, address_type)
        # A P2WPKH and a P2TR address for a key this wallet does not treat as its own (the legacy key's pubkey under
        # descriptors the wallet does not hold) - valid regtest bech32 / bech32m strings.
        pubkey = w.getaddressinfo(legacy)["pubkey"]
        strangers = [node.deriveaddresses(node.getdescriptorinfo(d)["descriptor"])[0] for d in (f"wpkh({pubkey})", f"tr({pubkey})")]
        assert strangers[0].startswith("bcrt1q") and strangers[1].startswith("bcrt1p"), strangers
        for stranger in strangers:
            assert_equal(node.validateaddress(stranger)["isvalid"], True)        # a valid shape - and still refused
            assert_raises_rpc_error(-6, "SegWit is not active", w.sendtoaddress, stranger, 1)
            assert_raises_rpc_error(-4, "SegWit is not active", w.send, {stranger: 1})
        assert_raises_rpc_error(-4, "SegWit is not active", w.send, {legacy: 1}, None, "unset", None, {"change_type": "bech32"})
        assert_equal(node.getrawmempool(), [])

        for address_type, prefix in (("bech32", "wpkh("), ("bech32m", "tr(")):
            self.log.info(f"A {address_type} spend is refused at admission while SegWit is not active")
            addr = self.own_witness_address(w, prefix)
            outpoint, spend = self.witness_coin(w, addr, legacy)
            res = node.testmempoolaccept([spend])[0]
            assert_equal(res["allowed"], False)
            assert_equal(res["reject-reason"], "no-witness-yet")
            assert_raises_rpc_error(-26, "no-witness-yet", node.sendrawtransaction, spend)
            assert_equal(node.getrawmempool(), [])
            self.mines_a_block(legacy)

            self.log.info(f"...and the wallet knows its {address_type} coin cannot be spent")
            coin = next(u for u in w.listunspent() if (u["txid"], u["vout"]) == outpoint)
            assert_equal(coin["spendable"], False)
            assert_raises_rpc_error(-4, "SegWit is not active", w.send, {legacy: Decimal("0.5")}, None, "unset", None,
                                    {"inputs": [{"txid": outpoint[0], "vout": outpoint[1]}], "add_inputs": False})
            assert_equal(node.getrawmempool(), [])

        self.log.info("A legacy spend is unaffected, and blocks keep coming")
        txid = w.sendtoaddress(w.getnewaddress("", "legacy"), 1)
        assert txid in node.getrawmempool()
        self.mines_a_block(legacy)
        assert_equal(node.getrawmempool(), [])


if __name__ == '__main__':
    BlazecoinNoWitnessTest(__file__).main()
