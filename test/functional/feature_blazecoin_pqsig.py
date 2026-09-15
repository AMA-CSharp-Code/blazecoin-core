#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin P2PQH - the post-quantum output type (PQ_SIGNATURES.md).

Activates DEPLOYMENT_PQSIG on regtest via -testactivationheight=pqsig@H_Q and,
with the PQ spends built and signed in Python (test_framework/blazecoin_pq.py,
dilithium-py - independent of the daemon wallet), checks the LIVE daemon:
  * P2PQH outputs can be created at any height but are non-standard before H_Q;
  * a P2PQH spend is rejected (mempool AND block) while the next block is < H_Q,
    accepted and mined from the first block at H_Q;
  * the 5,000-byte push relaxation applies only to PQ inputs;
  * a 26-input PQ transaction is standard; a block with ~250 PQ inputs connects;
  * a reorg back across H_Q drops PQ spends from the mempool, and re-crossing
    it brings them back;
  * validateaddress / decodescript report type "pqkh" for a "TQ..." address, and
    a coinbase can pay a P2PQH address once the fork is active.
"""

from test_framework.blazecoin_pq import (
    PQKey,
    PREFIX_MAIN,
    PQ_SCRIPTSIG_LEN,
    have_dilithium,
    sign_pq_input,
)
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet, MiniWalletMode

H_Q = 160
MASTER = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
PQ_UTXO_VALUE = 1_000_000          # sat per P2PQH output created by the funding tx
N_PQ_OUTPUTS = 300
PQ_FEE = 300_000                   # sat: comfortably above minrelay (1000 sat/kvB) for a 98 KB tx


class BlazecoinPQSigTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=pqsig@{H_Q}", "-acceptnonstdtxn=0", "-txindex"]]

    def skip_test_if_missing_module(self):
        if not have_dilithium():
            raise SkipTest("dilithium-py is not installed (pip install dilithium-py)")

    def setup_nodes(self):
        # Skip the framework's Bitcoin-WIF coinbase-key import (Blazecoin rejects it).
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    # ------------------------------------------------------------------ helpers
    def pqsig_deployment(self):
        return self.nodes[0].getdeploymentinfo()["deployments"]["pqsig"]

    def make_pq_spend(self, utxos, key, to_spk, fee=PQ_FEE):
        """Spend the given P2PQH utxos [(txid, vout, value)] of `key` to one output."""
        tx = CTransaction()
        total = 0
        for txid, vout, value in utxos:
            tx.vin.append(CTxIn(COutPoint(int(txid, 16), vout)))
            total += value
        tx.vout.append(CTxOut(total - fee, to_spk))
        for n, (_, _, value) in enumerate(utxos):
            sign_pq_input(tx, n, value, key)
        return tx

    def assert_block_rejected(self, node, tx_hex, reason):
        """generateblock runs TestBlockValidity; the RPC (and the parallel script-check queue) surface only
        "block-validation-failed" - the precise script reason (`reason`) is what the mempool path reports and
        is asserted there; here only the rejection itself is checked."""
        assert_raises_rpc_error(-25, "testBlockValidity failed", node.generateblock, self.wallet.get_address(), [tx_hex], invalid_call=False)

    # ------------------------------------------------------------------ test
    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.raw_wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)  # a standard bare prevout with a real scriptSig
        self.generate(self.raw_wallet, 1)
        self.generate(self.wallet, 110)
        assert_equal(node.getblockcount(), 111)
        key = PQKey(MASTER, 0)
        spk_hex = bytes(key.spk).hex()

        self.log.info("Deployment is known, buried at H_Q, not yet active")
        dep = self.pqsig_deployment()
        assert_equal(dep["type"], "buried")
        assert_equal(dep["height"], H_Q)
        assert_equal(dep["active"], False)

        self.log.info("validateaddress / decodescript know the TQ address and the 34-byte template")
        info = node.validateaddress(key.address())
        assert_equal(info["isvalid"], True)
        assert_equal(info["scriptPubKey"], spk_hex)
        assert_equal(info["type"], "pqkh")
        assert_equal(info["algorithm"], "ML-DSA-44")
        assert_equal(info["isscript"], False)
        assert_equal(info["iswitness"], False)
        assert_equal(len(key.address()), 52)
        assert key.address().startswith("TQ")
        assert_equal(node.validateaddress(key.address(PREFIX_MAIN))["isvalid"], False)  # a BQ (mainnet) address is not a regtest one
        dec = node.decodescript(spk_hex)
        assert_equal(dec["type"], "pqkh")
        assert_equal(dec["address"], key.address())
        assert "p2sh" not in dec  # never P2SH-wrappable
        assert_equal(node.decodescript("ba")["type"], "nonstandard")  # the bare opcode is not a template

        self.log.info("Pre-activation: P2PQH outputs are valid in a block but non-standard")
        fund = self.wallet.create_self_transfer(fee_rate=0)["tx"]
        fund.vout[0].nValue -= N_PQ_OUTPUTS * PQ_UTXO_VALUE + 10_000
        for _ in range(N_PQ_OUTPUTS):
            fund.vout.append(CTxOut(PQ_UTXO_VALUE, key.spk))
        fund_hex = fund.serialize().hex()
        res = node.testmempoolaccept([fund_hex])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "scriptpubkey")
        self.generateblock(node, output=self.wallet.get_address(), transactions=[fund_hex])
        fund_txid = fund.rehash()
        self.wallet.rescan_utxos()
        assert_equal(node.gettxout(fund_txid, 1)["scriptPubKey"]["type"], "pqkh")
        assert_equal(node.gettxout(fund_txid, 1)["scriptPubKey"]["address"], key.address())
        pq_utxos = [(fund_txid, i, PQ_UTXO_VALUE) for i in range(1, N_PQ_OUTPUTS + 1)]

        self.log.info("Pre-activation: a PQ spend is rejected by the mempool and in a block")
        spend = self.make_pq_spend(pq_utxos[:1], key, self.wallet.get_scriptPubKey(), fee=10_000)
        spend_hex = spend.serialize().hex()
        assert_equal(len(spend.vin[0].scriptSig), PQ_SCRIPTSIG_LEN)
        # Policy stops it first (the 3,739-byte scriptSig is not standard before H_Q); consensus would too.
        res = node.testmempoolaccept([spend_hex])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "scriptsig-size")
        assert_raises_rpc_error(-26, "scriptsig-size", node.sendrawtransaction, spend_hex)
        self.assert_block_rejected(node, spend_hex, "Push value size limit exceeded")

        self.log.info(f"Mine to H_Q-2 = {H_Q - 2}: block H_Q-1 still cannot carry the spend")
        self.generate(self.wallet, H_Q - 2 - node.getblockcount())
        assert_equal(node.getblockcount(), H_Q - 2)
        assert_equal(self.pqsig_deployment()["active"], False)  # getdeploymentinfo reports the NEXT block (H_Q-1)
        assert_equal(node.testmempoolaccept([spend_hex])[0]["allowed"], False)
        self.assert_block_rejected(node, spend_hex, "Push value size limit exceeded")

        self.log.info(f"At tip H_Q-1 the NEXT block is H_Q: the spend is standard, relayed and mined in block {H_Q}")
        self.generate(self.wallet, 1)
        assert_equal(node.getblockcount(), H_Q - 1)
        assert_equal(self.pqsig_deployment()["active"], True)  # next block = H_Q
        res = node.testmempoolaccept([spend_hex])[0]
        assert_equal(res["allowed"], True)
        spend_txid = node.sendrawtransaction(spend_hex)
        assert spend_txid in node.getrawmempool()
        block_hq = self.generate(self.wallet, 1)[0]
        assert_equal(node.getblockcount(), H_Q)
        assert_equal(self.pqsig_deployment()["active"], True)
        assert spend_txid in node.getblock(block_hq)["tx"]
        assert_equal(node.getrawtransaction(spend_txid, True)["confirmations"], 1)

        self.log.info("Post-activation: P2PQH outputs are standard; a coinbase can pay a TQ address")
        sent = self.wallet.send_to(from_node=node, scriptPubKey=key.spk, amount=PQ_UTXO_VALUE)
        assert sent["txid"] in node.getrawmempool()
        cb_block = self.generatetoaddress(node, 1, key.address())[0]
        cb = node.getblock(cb_block, 2)["tx"][0]
        assert_equal(cb["vout"][0]["scriptPubKey"]["type"], "pqkh")
        assert_equal(cb["vout"][0]["scriptPubKey"]["address"], key.address())

        self.log.info("The 5,000-byte push relaxation applies only to PQ inputs")
        legacy = self.raw_wallet.create_self_transfer(fee_rate=0)["tx"]
        legacy.vin[0].scriptSig = CScript(bytes(CScript([b"\x00" * 600])) + bytes(legacy.vin[0].scriptSig))  # an extra 600-byte push before the P2PK signature
        legacy_hex = legacy.serialize().hex()
        res = node.testmempoolaccept([legacy_hex])[0]
        assert_equal(res["allowed"], False)
        assert "Push value size limit exceeded" in res["reject-reason"]
        self.assert_block_rejected(node, legacy_hex, "Push value size limit exceeded")
        # A PQ scriptSig with an extra push is neither standard nor valid.
        three = self.make_pq_spend(pq_utxos[1:2], key, self.wallet.get_scriptPubKey(), fee=10_000)
        three.vin[0].scriptSig = CScript(b"\x01\x01" + bytes(three.vin[0].scriptSig))
        res = node.testmempoolaccept([three.serialize().hex()])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "scriptsig-size")
        self.assert_block_rejected(node, three.serialize().hex(), "exactly two stack elements")
        # ... and a signature over the wrong amount fails.
        wrong = self.make_pq_spend([(fund_txid, 2, PQ_UTXO_VALUE + 1)], key, self.wallet.get_scriptPubKey(), fee=10_000)
        res = node.testmempoolaccept([wrong.serialize().hex()])[0]
        assert_equal(res["allowed"], False)
        assert "PQ signature is invalid" in res["reject-reason"]

        self.log.info("A 26-input PQ transaction is standard (the size maximum); ~250 PQ inputs fit one block")
        big_txids = []
        tx26 = self.make_pq_spend(pq_utxos[1:27], key, self.wallet.get_scriptPubKey())
        tx26_hex = tx26.serialize().hex()
        assert_greater_than(100_000, len(tx26_hex) // 2)
        res = node.testmempoolaccept([tx26_hex])[0]
        assert_equal(res["allowed"], True)
        big_txids.append(node.sendrawtransaction(tx26_hex))
        cursor = 27
        for _ in range(9):
            tx = self.make_pq_spend(pq_utxos[cursor:cursor + 25], key, self.wallet.get_scriptPubKey())
            cursor += 25
            big_txids.append(node.sendrawtransaction(tx.serialize().hex()))
        assert_equal(sorted(big_txids), sorted(node.getrawmempool()))
        big_block = self.generate(self.wallet, 1)[0]
        blk = node.getblock(big_block)
        for txid in big_txids:
            assert txid in blk["tx"]
        assert_greater_than(blk["size"], 900_000)
        assert_equal(node.getrawmempool(), [])
        n_pq_inputs = sum(len(node.getrawtransaction(t, True)["vin"]) for t in big_txids)
        assert_equal(n_pq_inputs, 26 + 9 * 25)

        self.log.info("Reorg back across H_Q: PQ spends leave the mempool; re-crossing brings them back")
        tip = node.getblockcount()
        hash_hq_minus_1 = node.getblockhash(H_Q - 1)
        node.invalidateblock(node.getblockhash(H_Q))
        assert_equal(node.getblockcount(), H_Q - 1)
        # The next block is H_Q again, so every disconnected PQ spend is still valid for it.
        mempool = node.getrawmempool()
        assert spend_txid in mempool
        for txid in big_txids:
            assert txid in mempool
        node.invalidateblock(hash_hq_minus_1)
        assert_equal(node.getblockcount(), H_Q - 2)
        mempool = node.getrawmempool()
        assert spend_txid not in mempool
        for txid in big_txids:
            assert txid not in mempool
        assert_equal(node.testmempoolaccept([spend_hex])[0]["allowed"], False)
        node.reconsiderblock(hash_hq_minus_1)
        assert_equal(node.getblockcount(), tip)
        assert_equal(node.getrawmempool(), [])
        assert_equal(node.getrawtransaction(spend_txid, True)["blockhash"], block_hq)
        assert_equal(node.getrawtransaction(big_txids[0], True)["blockhash"], big_block)

        self.log.info("Spending the coinbase-paid and wallet-paid P2PQH outputs works too")
        cb_txid = cb["txid"]
        self.generate(self.wallet, 30)  # Blazecoin COINBASE_MATURITY
        cb_value = int(round(cb["vout"][0]["value"] * COIN))
        tx = self.make_pq_spend([(cb_txid, 0, cb_value), (sent["txid"], sent["sent_vout"], PQ_UTXO_VALUE)], key,
                                self.wallet.get_scriptPubKey(), fee=20_000)
        txid = node.sendrawtransaction(tx.serialize().hex())
        last_block = self.generate(self.wallet, 1)[0]
        assert txid in node.getblock(last_block)["tx"]


if __name__ == "__main__":
    BlazecoinPQSigTest(__file__).main()
