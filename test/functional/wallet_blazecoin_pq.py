#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin wallet support for P2PQH, the post-quantum output type (PQ_SIGNATURES.md s6).

Runs a descriptor wallet against a regtest node with DEPLOYMENT_PQSIG buried at H_Q and checks:
  * getnewaddress "" pq  -> a 52-char TQ address before activation (the operator needs them for
    the coinbase list ahead of the fork); getaddressinfo reports ismine/solvable/desc/pqkh/algorithm;
  * pre-activation the wallet refuses to pay a BQ/TQ address (sendtoaddress, sendmany,
    fundrawtransaction, walletcreatefundedpsbt) with "post-quantum outputs are not standard until
    block N", and a P2PQH coin it already owns is listed with spendable=false and never selected;
  * from the block at H_Q the wallet pays PQ addresses and spends PQ coins three ways: sendtoaddress
    (ML-DSA-44 signing inside the wallet), createrawtransaction + signrawtransactionwithwallet, and
    walletcreatefundedpsbt -> walletprocesspsbt -> finalizepsbt -> sendrawtransaction (both the
    unfinalized "blz" proprietary-field path and the one-shot path); fee estimation prices a PQ input
    at 3,782 vbytes;
  * signmessage / verifymessage with a TQ address (and that tampering fails);
  * encryptwallet / walletpassphrase: the PQ seed rides the encrypted-key path, a restart reloads
    the cached ML-DSA public keys, a locked wallet cannot sign;
  * dumpprivkey refuses a TQ address; importdescriptors accepts both the public single-key form and
    the private ranged form (which reproduces the same addresses).
"""

import base64
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

H_Q = 150
NOT_STANDARD = f"post-quantum outputs are not standard until block {H_Q}"
PQ_SCRIPTSIG_HEX_LEN = 2 * 3739
PQ_PUBKEY_HEX_LEN = 2 * 1312


class BlazecoinPQWalletTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=pqsig@{H_Q}", "-acceptnonstdtxn=0", "-keypool=50"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def setup_nodes(self):
        # Skip the framework's Bitcoin-WIF coinbase-key import (Blazecoin rejects it).
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    # ------------------------------------------------------------------ helpers
    def pq_utxos(self, wallet):
        return sorted([u for u in wallet.listunspent() if u["desc"].startswith("pqkh(")], key=lambda u: u["amount"])

    def assert_pq_scriptsig(self, tx_hex):
        dec = self.nodes[0].decoderawtransaction(tx_hex)
        for vin in dec["vin"]:
            assert_equal(len(vin["scriptSig"]["hex"]), PQ_SCRIPTSIG_HEX_LEN)
        return dec

    # ------------------------------------------------------------------ test
    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="miner", descriptors=True)
        node.createwallet(wallet_name="pq", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        pq = node.get_wallet_rpc("pq")
        mine_addr = miner.getnewaddress("", "legacy")
        self.generatetoaddress(node, 110, mine_addr)
        assert_greater_than(miner.getbalance(), 100)

        self.log.info("PQ addresses can be generated before activation")
        addr = pq.getnewaddress("", "pq")
        assert_equal(len(addr), 52)
        assert addr.startswith("TQ")
        info = pq.getaddressinfo(addr)
        assert_equal(info["ismine"], True)
        assert_equal(info["iswatchonly"], False)
        assert_equal(info["solvable"], True)
        assert info["desc"].startswith("pqkh(mldsa44pub:")
        assert info["parent_desc"].startswith("pqkh(mldsa44:")
        assert_equal(info["type"], "pqkh")
        assert_equal(info["algorithm"], "ML-DSA-44")
        assert_equal(len(info["pqkh"]), 64)
        assert_equal(len(info["pqpubkey"]), PQ_PUBKEY_HEX_LEN)
        assert_equal(info["isscript"], False)
        assert_equal(info["iswitness"], False)
        assert_equal(info["ischange"], False)
        assert_equal(node.validateaddress(addr)["isvalid"], True)
        assert pq.getnewaddress("", "pq") != addr
        change = pq.getrawchangeaddress("pq")
        assert change.startswith("TQ")
        assert_equal(pq.getaddressinfo(change)["ismine"], True)
        # A stranger's TQ address: valid, not ours, not solvable.
        stranger = miner.getnewaddress("", "pq")
        assert_equal(pq.getaddressinfo(stranger)["ismine"], False)
        assert_equal(pq.getaddressinfo(stranger)["solvable"], False)

        self.log.info("listdescriptors: public form shows the seed id, private form the 32-byte seed")
        pub_descs = [d for d in pq.listdescriptors()["descriptors"] if d["desc"].startswith("pqkh(")]
        assert_equal(len(pub_descs), 2)
        assert_equal(sorted(d["internal"] for d in pub_descs), [False, True])
        for d in pub_descs:
            assert_equal(d["active"], True)
            assert_equal(d["desc"].index("/*)#"), len("pqkh(mldsa44:") + 40)
        priv_descs = [d for d in pq.listdescriptors(True)["descriptors"] if d["desc"].startswith("pqkh(")]
        assert_equal(len(priv_descs), 2)
        for d in priv_descs:
            assert_equal(d["desc"].index("/*)#"), len("pqkh(mldsa44:") + 64)
        priv_external = [d["desc"] for d in priv_descs if not d["internal"]][0]

        self.log.info("Legacy-only and script paths refuse pq")
        assert_raises_rpc_error(-5, "Post-quantum (BQ) addresses have no exportable private key", pq.dumpprivkey, addr)
        legacy_pubkey = miner.getaddressinfo(mine_addr)["pubkey"]
        assert_raises_rpc_error(-5, "createmultisig cannot create pq", node.createmultisig, 1, [legacy_pubkey], "pq")

        self.log.info("Pre-activation: paying a PQ address is refused by every funding path")
        # (sendtoaddress / sendmany report every CreateTransaction failure as -6, the fund paths as -4)
        assert_raises_rpc_error(-6, NOT_STANDARD, miner.sendtoaddress, addr, 10)
        assert_raises_rpc_error(-6, NOT_STANDARD, miner.sendmany, "", {addr: 10})
        assert_raises_rpc_error(-4, NOT_STANDARD, miner.fundrawtransaction, node.createrawtransaction([], {addr: 10}))
        assert_raises_rpc_error(-4, NOT_STANDARD, miner.walletcreatefundedpsbt, [], {addr: 10})
        assert_raises_rpc_error(-4, NOT_STANDARD, miner.send, {addr: 10})
        assert_raises_rpc_error(-4, "change type pq", miner.send, {miner.getnewaddress("", "legacy"): 1}, None, "unset", None, {"change_type": "pq"})

        self.log.info("Pre-activation: a P2PQH coin the wallet owns is visible but not spendable")
        utxo = miner.listunspent()[0]
        raw = miner.createrawtransaction([{"txid": utxo["txid"], "vout": utxo["vout"]}],
                                         {addr: 10, mine_addr: utxo["amount"] - Decimal("10.001")})
        signed = miner.signrawtransactionwithwallet(raw)["hex"]
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, signed)  # non-standard output before H_Q
        self.generateblock(node, mine_addr, [signed])  # valid in a block at any height
        unspent = pq.listunspent()
        assert_equal(len(unspent), 1)
        assert_equal(unspent[0]["address"], addr)
        assert_equal(unspent[0]["amount"], 10)
        assert_equal(unspent[0]["spendable"], False)
        assert_equal(unspent[0]["solvable"], True)
        assert unspent[0]["desc"].startswith("pqkh(mldsa44pub:")
        assert_equal(pq.getbalance(), 10)
        assert_raises_rpc_error(-6, "Insufficient funds", pq.sendtoaddress, mine_addr, 1)
        assert_raises_rpc_error(-4, "cannot be spent until block", pq.send, {mine_addr: 1}, None, "unset", None,
                                {"inputs": [{"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}], "add_inputs": False})

        self.log.info("Activate: mine to H_Q - 1 so the next block is the first PQ block")
        self.generatetoaddress(node, H_Q - 1 - node.getblockcount(), mine_addr)
        assert_equal(node.getblockcount(), H_Q - 1)
        assert_equal(pq.listunspent()[0]["spendable"], True)

        self.log.info("The wallet pays PQ addresses once the fork is active for the next block")
        addr2, addr3, addr4 = (pq.getnewaddress("", "pq") for _ in range(3))
        txid = miner.sendmany("", {addr2: 20, addr3: 30, addr4: 40})
        assert txid in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr)
        assert_equal(node.getblockcount(), H_Q)
        assert_equal(pq.getbalance(), 100)
        utxos = self.pq_utxos(pq)
        assert_equal([u["amount"] for u in utxos], [10, 20, 30, 40])
        assert all(u["spendable"] for u in utxos)

        self.log.info("Spend 1: sendtoaddress signs with ML-DSA-44 inside the wallet")
        txid1 = pq.sendtoaddress(mine_addr, 5)
        assert txid1 in node.getrawmempool()
        self.assert_pq_scriptsig(node.getrawtransaction(txid1))
        self.generatetoaddress(node, 1, mine_addr)
        assert_equal(pq.gettransaction(txid1)["confirmations"], 1)

        self.log.info("Spend 2: createrawtransaction + signrawtransactionwithwallet")
        u = self.pq_utxos(pq)[0]
        raw = pq.createrawtransaction([{"txid": u["txid"], "vout": u["vout"]}], {mine_addr: u["amount"] - Decimal("0.01")})
        res = pq.signrawtransactionwithwallet(raw)
        assert_equal(res["complete"], True)
        self.assert_pq_scriptsig(res["hex"])
        txid2 = node.sendrawtransaction(res["hex"])
        self.generatetoaddress(node, 1, mine_addr)
        assert_equal(pq.gettransaction(txid2)["confirmations"], 1)

        self.log.info("Spend 3: PSBT with the signature carried in the blz proprietary fields")
        u = self.pq_utxos(pq)[0]
        funded = pq.walletcreatefundedpsbt([{"txid": u["txid"], "vout": u["vout"]}], {mine_addr: 1}, 0,
                                           {"add_inputs": False, "fee_rate": 10})
        # fee estimation prices the PQ input at 3,782 vbytes: >= 3,782 * 10 sat/vB
        assert_greater_than(funded["fee"], Decimal("0.00037820"))
        dec = node.decodepsbt(funded["psbt"])
        assert_equal(dec["inputs"][0]["non_witness_utxo"]["txid"], u["txid"])
        proc = pq.walletprocesspsbt(funded["psbt"], True, "ALL", True, False)
        assert_equal(proc["complete"], False)  # not finalized: the fields travel unfinalized
        dec = node.decodepsbt(proc["psbt"])
        assert "final_scriptSig" not in dec["inputs"][0]
        props = sorted(dec["inputs"][0]["proprietary"], key=lambda p: p["subtype"])
        assert_equal([p["identifier"] for p in props], ["626c7a", "626c7a"])  # "blz"
        assert_equal([p["subtype"] for p in props], [1, 2])
        assert_equal([len(p["value"]) for p in props], [2 * 2420, 2 * 1313])
        fin = node.finalizepsbt(proc["psbt"])
        assert_equal(fin["complete"], True)
        self.assert_pq_scriptsig(fin["hex"])
        txid3 = node.sendrawtransaction(fin["hex"])
        # ... and the one-shot path
        u = self.pq_utxos(pq)[0]
        funded = pq.walletcreatefundedpsbt([{"txid": u["txid"], "vout": u["vout"]}], {mine_addr: 1}, 0, {"add_inputs": False})
        proc = pq.walletprocesspsbt(funded["psbt"])
        assert_equal(proc["complete"], True)
        dec = node.decodepsbt(proc["psbt"])
        assert_equal(len(dec["inputs"][0]["final_scriptSig"]["hex"]), PQ_SCRIPTSIG_HEX_LEN)
        assert "proprietary" not in dec["inputs"][0]
        txid4 = node.sendrawtransaction(node.finalizepsbt(proc["psbt"])["hex"])
        self.generatetoaddress(node, 1, mine_addr)
        for t in (txid3, txid4):
            assert_equal(pq.gettransaction(t)["confirmations"], 1)
        assert_equal(self.pq_utxos(pq), [])

        self.log.info("signmessage / verifymessage with a TQ address")
        message = "Blazecoin post-quantum ownership proof"
        sig = pq.signmessage(addr, message)
        assert_equal(len(base64.b64decode(sig)), 1313 + 2420)
        assert_equal(node.verifymessage(addr, sig, message), True)
        assert_equal(node.verifymessage(addr, sig, message + "!"), False)
        assert_equal(node.verifymessage(addr2, sig, message), False)
        tampered = bytearray(base64.b64decode(sig))
        tampered[-1] ^= 1
        assert_equal(node.verifymessage(addr, base64.b64encode(bytes(tampered)).decode(), message), False)
        assert_raises_rpc_error(-3, "Malformed base64 encoding", node.verifymessage, addr, sig[:-8], message)
        assert_raises_rpc_error(-4, "Private key not available", miner.signmessage, addr, message)
        assert_equal(pq.signmessage(addr, message), sig)  # deterministic

        self.log.info("importdescriptors: the public single-key form (watch) and the private ranged form (restore)")
        node.createwallet(wallet_name="watch", descriptors=True, disable_private_keys=True)
        watch = node.get_wallet_rpc("watch")
        res = watch.importdescriptors([{"desc": pq.getaddressinfo(addr2)["desc"], "timestamp": "now"}])
        assert_equal(res[0]["success"], True)
        assert_equal(watch.getaddressinfo(addr2)["ismine"], True)
        assert_equal(watch.getaddressinfo(addr2)["solvable"], True)
        assert_equal(watch.getaddressinfo(addr3)["ismine"], False)
        node.createwallet(wallet_name="restored", descriptors=True, blank=True)
        restored = node.get_wallet_rpc("restored")
        res = restored.importdescriptors([{"desc": priv_external, "timestamp": "now", "active": True, "range": 20}])
        assert_equal(res[0]["success"], True)
        # Same seed, same chain: the rescan (timestamp "now" still covers the 2-hour window) finds the
        # history of the original wallet's addresses and moves the keypool past the used ones.
        assert_equal(restored.getaddressinfo(addr)["ismine"], True)
        assert_equal(restored.getaddressinfo(addr2)["ismine"], True)
        assert_equal(restored.getreceivedbyaddress(addr), 10)
        assert_equal(restored.getreceivedbyaddress(addr2), 20)
        assert_equal(restored.getaddressinfo(change)["ismine"], False)  # change lives on the internal chain
        fresh = restored.getnewaddress("", "pq")
        assert fresh not in (addr, addr2, addr3, addr4)
        assert_equal(pq.getaddressinfo(fresh)["ismine"], True)  # the original wallet derives the same key
        # the public ranged form cannot be expanded (ML-DSA has no public derivation)
        pub_external = [d["desc"] for d in pub_descs if not d["internal"]][0]
        res = watch.importdescriptors([{"desc": pub_external, "timestamp": "now", "range": 20}])
        assert_equal(res[0]["success"], False)
        assert "Cannot expand descriptor" in res[0]["error"]["message"]

        self.log.info("Encryption: the PQ seed rides the encrypted-key path; a restart keeps the cached pubkeys")
        addr5 = pq.getnewaddress("", "pq")
        miner.sendtoaddress(addr5, 7)
        self.generatetoaddress(node, 1, mine_addr)
        pq.encryptwallet("pass")
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", pq.sendtoaddress, mine_addr, 1)
        u = self.pq_utxos(pq)[0]
        assert_equal(u["address"], addr5)
        self.restart_node(0, extra_args=self.extra_args[0])
        node.loadwallet("pq")
        pq = node.get_wallet_rpc("pq")
        assert_equal(pq.getaddressinfo(addr5)["ismine"], True)
        assert_equal(self.pq_utxos(pq)[0]["address"], addr5)
        funded = pq.walletcreatefundedpsbt([{"txid": u["txid"], "vout": u["vout"]}], {mine_addr: 6}, 0, {"add_inputs": False})
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", pq.walletprocesspsbt, funded["psbt"])
        pq.walletpassphrase("pass", 60)
        proc = pq.walletprocesspsbt(funded["psbt"])
        assert_equal(proc["complete"], True)
        txid5 = node.sendrawtransaction(node.finalizepsbt(proc["psbt"])["hex"])
        self.assert_pq_scriptsig(node.getrawtransaction(txid5))
        addr6 = pq.getnewaddress("", "pq")  # the post-encryption seed is a fresh, encrypted-at-birth one
        assert addr6.startswith("TQ")
        assert_equal(pq.signmessage(addr5, message) != sig, True)
        assert_equal(node.verifymessage(addr5, pq.signmessage(addr5, message), message), True)
        pq.walletlock()
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", pq.signmessage, addr5, message)
        self.generatetoaddress(node, 1, mine_addr)
        assert_equal(pq.gettransaction(txid5)["confirmations"], 1)


if __name__ == '__main__':
    BlazecoinPQWalletTest(__file__).main()
