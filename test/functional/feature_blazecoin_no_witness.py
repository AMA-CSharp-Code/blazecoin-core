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
A third (2026-11-09): that fix left out the P2SH-WRAPPED witness type. "p2sh-segwit" still got an address (and worked
as a change type); the address looks like any other P2SH address, a payment to it confirms, the wallet lists the coin
as spendable and signs a spend - which carries witness data and is refused everywhere.

This test runs a node with SegWit pushed far out of reach (the mainnet state) and checks that
  * a v0 (P2WPKH) and a v1 (Taproot key-path) spend are both refused at admission with "no-witness-yet";
  * a transaction that would CREATE a witness output is refused with "no-witness-outputs-yet";
  * the wallet refuses to make a witness address, to pay one, to use one for change, or to spend a witness coin;
  * all of that holds for p2sh-segwit too: no such address or change, no payment to one of the wallet's own, a coin
    already sitting on one is listed as not spendable and never offered as an input; createmultisig makes legacy only;
  * blocks keep being produced, before and after, by getblocktemplate and generate alike.

More of the same report family (2026-11-09), each a way round the checks above:
  * sendall looked at neither its recipients nor an input named outright: it returned a txid for a transaction the
    mempool then refused, and the balance read zero until the transaction was abandoned by hand;
  * a change ADDRESS (change_address / changeAddress) was used as given, where a change TYPE was checked;
  * with a witness type as the default address type, the automatic change type was a witness type - the payment was
    refused over its own change (or, on 2.1.2, the change went to a p2sh-segwit address). It is legacy now;
  * importing a witness descriptor says that its coins cannot be spent here.

Audit 2026-11-09: createmultisig was guarded and its wallet twin was not - addmultisigaddress (a legacy-wallet RPC)
still made and stored a p2sh-segwit or bech32 multisig address, asked for by name or through a witness default
address type. Checked here on a legacy wallet of its own, where the build has BDB.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

SEGWIT_NEVER = 1_000_000
H_Q = 200   # post-quantum outputs become standard here; the sendall check is made before it, the change check after


class BlazecoinNoWitnessTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=segwit@{SEGWIT_NEVER}", f"-testactivationheight=pqsig@{H_Q}", "-acceptnonstdtxn=0"]]

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
        for address_type in ("bech32", "bech32m", "p2sh-segwit"):
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
        assert_raises_rpc_error(-4, "SegWit is not active", w.send, {legacy: 1}, None, "unset", None, {"change_type": "p2sh-segwit"})
        assert_equal(node.getrawmempool(), [])

        self.log.info("createmultisig makes legacy addresses only")
        keys = [w.getaddressinfo(w.getnewaddress("", "legacy"))["pubkey"] for _ in range(2)]
        for address_type in ("p2sh-segwit", "bech32"):
            assert_raises_rpc_error(-5, "SegWit is not active", node.createmultisig, 2, keys, address_type)
        assert "address" in node.createmultisig(2, keys, "legacy")

        if self.is_bdb_compiled():
            self.log.info("...and so does addmultisigaddress, its legacy-wallet twin (audit 2026-11-09)")
            node.createwallet(wallet_name="old", descriptors=False)
            old = node.get_wallet_rpc("old")
            for address_type in ("p2sh-segwit", "bech32"):
                assert_raises_rpc_error(-5, "SegWit is not active", old.addmultisigaddress, 2, keys, "", address_type)
            assert "address" in old.addmultisigaddress(2, keys, "", "legacy")
            node.unloadwallet("old")

        self.log.info("A P2SH-wrapped witness address (p2sh-segwit) is the same trap behind an ordinary-looking address")
        wrapped = self.own_witness_address(w, "sh(wpkh(")
        assert_equal(w.getaddressinfo(wrapped)["ismine"], True)
        assert_equal(w.getaddressinfo(wrapped)["isscript"], True)
        # Nothing on the wire tells it from any other P2SH address, so the network cannot refuse a payment to it -
        # but the wallet knows its own, and will not pay it.
        assert_raises_rpc_error(-6, "SegWit is not active", w.sendtoaddress, wrapped, 1)
        assert_raises_rpc_error(-4, "SegWit is not active", w.send, {wrapped: 1})
        assert_equal(node.getrawmempool(), [])

        self.log.info("...and a coin already sitting on one (paid by an older version, or by someone else) is known to be stuck")
        coin = next(u for u in w.listunspent() if u["spendable"] and u["desc"].startswith("pkh("))
        raw = w.createrawtransaction([{"txid": coin["txid"], "vout": coin["vout"]}], {wrapped: 1, legacy: coin["amount"] - 1})
        funding = w.signrawtransactionwithwallet(raw)["hex"]
        funding_txid = node.sendrawtransaction(funding)          # an ordinary P2SH output: admitted and mined
        self.mines_a_block(legacy)
        vout = next(o["n"] for o in node.decoderawtransaction(funding)["vout"] if o["scriptPubKey"].get("address") == wrapped)
        stuck = next(u for u in w.listunspent() if (u["txid"], u["vout"]) == (funding_txid, vout))
        stuck_outpoint = {"txid": funding_txid, "vout": vout}
        assert_equal(stuck["spendable"], False)                  # was True: the wallet offered it as money it could send
        assert_raises_rpc_error(-4, "SegWit is not active", w.send, {legacy: Decimal("0.5")}, None, "unset", None,
                                {"inputs": [{"txid": funding_txid, "vout": vout}], "add_inputs": False})
        # Its spend needs witness data, which is why: refused at admission like any other.
        spend = w.createrawtransaction([{"txid": funding_txid, "vout": vout}], {legacy: Decimal("0.999")})
        signed = w.signrawtransactionwithwallet(spend)
        assert node.decoderawtransaction(signed["hex"])["vin"][0].get("txinwitness"), "the spend carries witness data"
        assert_equal(node.testmempoolaccept([signed["hex"]])[0]["reject-reason"], "no-witness-yet")
        # Automatic coin selection leaves it alone: sending everything spendable does not touch it.
        w.sendall([legacy])
        assert (funding_txid, vout) in [(u["txid"], u["vout"]) for u in w.listunspent()]
        self.mines_a_block(legacy)
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

        self.log.info("sendall checks where the money goes, and what it spends, like every other send")
        balance = w.getbalances()["mine"]["trusted"]
        assert balance > 100
        pq = w.getnewaddress("", "pq")
        assert node.getblockcount() < H_Q - 1
        refused = ((strangers[0], "SegWit is not active"), (strangers[1], "SegWit is not active"),
                   (wrapped, "SegWit is not active"), (pq, "post-quantum outputs are not standard"))
        for bad, why in refused:
            assert_raises_rpc_error(None, why, w.sendall, [bad])                     # was: a txid, and nothing sent
            assert_raises_rpc_error(None, why, w.sendall, [{bad: 1}, legacy])
        # A coin that needs witness data is no more spendable for being named outright.
        assert_raises_rpc_error(None, "SegWit is not active", w.sendall, [legacy], None, "unset", None, {"inputs": [stuck_outpoint]})
        assert_equal(node.getrawmempool(), [])
        assert_equal(w.getbalances()["mine"]["trusted"], balance)                    # was: zero until abandontransaction

        self.log.info("A change ADDRESS is checked like a change type")
        raw = w.createrawtransaction([], {legacy: 1})
        for bad, why in refused:
            assert_raises_rpc_error(-4, why, w.send, {legacy: 1}, None, "unset", None, {"change_address": bad})
            assert_raises_rpc_error(-4, why, w.fundrawtransaction, raw, {"changeAddress": bad})
            assert_raises_rpc_error(-4, why, w.walletcreatefundedpsbt, [], [{legacy: 1}], 0, {"changeAddress": bad})
        assert_equal(node.getrawmempool(), [])
        assert_equal(w.getbalances()["mine"]["trusted"], balance)

        self.log.info("Importing a witness descriptor says what it is worth here")
        node.createwallet(wallet_name="other", descriptors=True, blank=True)
        other = node.get_wallet_rpc("other")
        for prefix in ("sh(wpkh(", "wpkh(", "tr("):
            desc = next(d["desc"] for d in w.listdescriptors(True)["descriptors"] if d["desc"].startswith(prefix) and not d["internal"])
            res = other.importdescriptors([{"desc": desc, "timestamp": "now", "active": True, "range": [0, 5]}])[0]
            assert_equal(res["success"], True)
            assert any("SegWit is not active" in warning for warning in res.get("warnings", [])), res
        desc = next(d["desc"] for d in w.listdescriptors(True)["descriptors"] if d["desc"].startswith("pkh(") and not d["internal"])
        res = other.importdescriptors([{"desc": desc, "timestamp": "now", "active": True, "range": [0, 5]}])[0]
        assert_equal(res["success"], True)
        assert not any("SegWit" in warning for warning in res.get("warnings", [])), res      # a legacy one: nothing to say
        node.unloadwallet("other")

        self.log.info("A legacy spend is unaffected, and blocks keep coming")
        txid = w.sendtoaddress(w.getnewaddress("", "legacy"), 1)
        assert txid in node.getrawmempool()
        self.mines_a_block(legacy)
        assert_equal(node.getrawmempool(), [])

        self.log.info("With a witness type as the default address type, change is legacy - not refused, and not lost")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-addresstype=p2sh-segwit"])
        if "w" not in node.listwallets():
            node.loadwallet("w")
        w = node.get_wallet_rpc("w")

        def change_types(txid, paid):
            outs = node.decoderawtransaction(w.gettransaction(txid)["hex"])["vout"]
            return [o["scriptPubKey"]["type"] for o in outs if o["scriptPubKey"].get("address") != paid]

        # To a P2SH address: 2.1.2 answered in kind with p2sh-segwit change, which nothing can spend.
        p2sh = node.createmultisig(2, keys, "legacy")["address"]
        txid = w.sendtoaddress(p2sh, 1)
        assert txid in node.getrawmempool()
        assert_equal(change_types(txid, p2sh), ["pubkeyhash"])
        self.mines_a_block(legacy)
        # To a post-quantum address, once those are standard: the fall-through picked bech32m change and the wallet
        # refused its own payment ("change type bech32m ... use a BQ address" - which is what was being paid).
        self.generatetoaddress(node, H_Q - node.getblockcount(), legacy)
        assert_equal(node.getdeploymentinfo()["deployments"]["pqsig"]["active"], True)
        txid = w.sendtoaddress(pq, 1)
        assert txid in node.getrawmempool()
        assert_equal(change_types(txid, pq), ["pubkeyhash"])
        self.mines_a_block(legacy)
        assert_equal(node.getrawmempool(), [])

        if self.is_bdb_compiled():
            self.log.info("addmultisigaddress does not take a witness type from the default address type either")
            node.loadwallet("old")
            old = node.get_wallet_rpc("old")
            assert_raises_rpc_error(-5, "SegWit is not active", old.addmultisigaddress, 2, keys)
            assert "address" in old.addmultisigaddress(2, keys, "", "legacy")
            node.unloadwallet("old")


if __name__ == '__main__':
    BlazecoinNoWitnessTest(__file__).main()
