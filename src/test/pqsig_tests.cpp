// Copyright (c) 2026 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/** Blazecoin P2PQH / OP_CHECKPQSIG / PQSigHash - bit-exactness against the shared vectors.
 *
 *  Authority: test/pqsig/generate_pqsig_vectors.py (pure-Python dilithium-py) -> pqsig_vectors.json
 *  -> src/test/pqsig_vector_data.h (test/pqsig/gen_pqsig_header.py). Spec: PQ_SIGNATURES.md.
 *  Every constant, key, digest, signature, script and address here is compared byte-for-byte;
 *  if a vector and the spec disagree, the vector wins (and the disagreement gets reported). */

#include <addresstype.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/mldsa44.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key_io.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pq.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/solver.h>
#include <streams.h>
#include <test/pqsig_vector_data.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

namespace V = pqsig_vectors;

namespace {

std::vector<unsigned char> H(const char* hex) { return ParseHex(hex); }
uint256 H256(const char* hex)
{
    const auto v = ParseHex(hex);
    BOOST_REQUIRE_EQUAL(v.size(), 32U);
    return uint256(v);
}
Span<const unsigned char> CtxSpan(const std::string& s) { return {reinterpret_cast<const unsigned char*>(s.data()), s.size()}; }
uint256 Sha256(Span<const unsigned char> data)
{
    uint256 out;
    CSHA256().Write(data.data(), data.size()).Finalize(out.begin());
    return out;
}
CMutableTransaction DecodeTx(const unsigned char* data, size_t len)
{
    DataStream ss{Span<const unsigned char>{data, len}};
    CMutableTransaction mtx;
    ss >> TX_WITH_WITNESS(mtx);
    BOOST_REQUIRE(ss.empty());
    return mtx;
}
/** Key `index` of the vectors' fixed master seed (all PQ keys in the vectors come from it). */
struct VectorKey {
    std::vector<unsigned char> pk, sk, blob;
    uint256 pqkh;
    CScript spk;
};
VectorKey KeyAt(uint32_t index)
{
    VectorKey k;
    const auto master = H(V::DERIVATION[0].master_seed);
    const uint256 xi = pq::PQSeedForIndex(master, index);
    BOOST_REQUIRE(mldsa44::KeyGenFromSeed(xi, k.pk, k.sk));
    k.blob = pq::PQKeyBlob(k.pk);
    k.pqkh = pq::PQKeyHash(k.blob);
    k.spk = pq::GetScriptForPQKeyHash(k.pqkh);
    return k;
}
ScriptError ExpectedError(const std::string& expect)
{
    if (expect == "OK") return SCRIPT_ERR_OK;
    if (expect == "PQ_KEYHASH_MISMATCH") return SCRIPT_ERR_PQ_KEYHASH_MISMATCH;
    if (expect == "PQ_ALGO_INACTIVE") return SCRIPT_ERR_PQ_ALGO_INACTIVE;
    if (expect == "PQ_PUBKEY_LENGTH") return SCRIPT_ERR_PQ_PUBKEY_LENGTH;
    if (expect == "PQ_SIG_INVALID") return SCRIPT_ERR_PQ_SIG_INVALID;
    if (expect == "PQ_STACK_SIZE") return SCRIPT_ERR_PQ_STACK_SIZE;
    if (expect == "SIG_PUSHONLY") return SCRIPT_ERR_SIG_PUSHONLY;
    BOOST_FAIL("unknown expectation " + expect);
    return SCRIPT_ERR_UNKNOWN_ERROR;
}
constexpr unsigned int CONSENSUS_PQ_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_PQSIG;
constexpr unsigned int STANDARD_PQ_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQSIG;

} // namespace

BOOST_FIXTURE_TEST_SUITE(pqsig_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pqsig_constants)
{
    BOOST_CHECK_EQUAL(pq::PQ_ALGO_MLDSA44, V::ALGO_ID_MLDSA44);
    BOOST_CHECK_EQUAL(mldsa44::PUBKEY_SIZE, V::PUBKEY_LEN);
    BOOST_CHECK_EQUAL(mldsa44::SECKEY_SIZE, V::SECKEY_LEN);
    BOOST_CHECK_EQUAL(mldsa44::SIG_SIZE, V::SIG_LEN);
    BOOST_CHECK_EQUAL(mldsa44::SEED_SIZE, V::SEED_LEN);
    BOOST_CHECK_EQUAL(pq::PQ_MLDSA44_PUBKEY_SIZE, V::PUBKEY_LEN);
    BOOST_CHECK_EQUAL(pq::PQ_MLDSA44_SIG_SIZE, V::SIG_LEN);
    BOOST_CHECK_EQUAL(static_cast<uint32_t>(OP_CHECKPQSIG), V::OP_CHECKPQSIG);
    BOOST_CHECK_EQUAL(static_cast<uint32_t>(OP_CHECKPQSIG), static_cast<uint32_t>(OP_CHECKSIGADD));
    BOOST_CHECK_EQUAL(pq::PQ_SIGHASH_ALL, V::SIGHASH_ALL);
    BOOST_CHECK_EQUAL(pq::MAX_PQ_SCRIPT_ELEMENT_SIZE, V::MAX_PQ_ELEMENT_SIZE);
    BOOST_CHECK_EQUAL(pq::TAG_PQKH, V::TAG_PQKH);
    BOOST_CHECK_EQUAL(pq::TAG_SIGHASH, V::TAG_SIGHASH);
    BOOST_CHECK_EQUAL(pq::TAG_SEED, V::TAG_SEED);
    BOOST_CHECK_EQUAL(pq::CTX_TX, V::CTX_TX);
    BOOST_CHECK_EQUAL(MAX_STANDARD_PQ_SCRIPTSIG_SIZE, V::SCRIPTSIG_LEN);
    BOOST_CHECK_EQUAL(HexStr(CreateChainParams(ArgsManager{}, ChainType::MAIN)->Base58Prefix(CChainParams::PQ_ADDRESS)), V::ADDRESS_PREFIX_MAIN);
    for (const auto chain : {ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        BOOST_CHECK_EQUAL(HexStr(CreateChainParams(ArgsManager{}, chain)->Base58Prefix(CChainParams::PQ_ADDRESS)), V::ADDRESS_PREFIX_TEST);
    }
    // The flag must not collide with any upstream flag and must sit below the end marker.
    BOOST_CHECK(SCRIPT_VERIFY_PQSIG != SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS);
    BOOST_CHECK(SCRIPT_VERIFY_PQSIG != SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);
    BOOST_CHECK(SCRIPT_VERIFY_PQSIG < SCRIPT_VERIFY_END_MARKER);
    BOOST_CHECK((STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_PQSIG) == 0);
    BOOST_CHECK((MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_PQSIG) == 0);
}

BOOST_AUTO_TEST_CASE(pqsig_derivation)
{
    BOOST_REQUIRE_EQUAL(V::DERIVATION_COUNT, 3U);
    for (size_t i = 0; i < V::DERIVATION_COUNT; ++i) {
        const auto& d = V::DERIVATION[i];
        const auto master = H(d.master_seed);
        BOOST_REQUIRE_EQUAL(master.size(), 32U);
        const uint256 xi = pq::PQSeedForIndex(master, d.index);
        BOOST_CHECK_EQUAL(HexStr(xi), d.xi);

        std::vector<unsigned char> pk, sk;
        BOOST_REQUIRE(mldsa44::KeyGenFromSeed(xi, pk, sk));
        BOOST_CHECK_EQUAL(HexStr(pk), d.pubkey);
        BOOST_CHECK_EQUAL(sk.size(), mldsa44::SECKEY_SIZE);
        BOOST_CHECK_EQUAL(HexStr(Sha256(sk)), d.seckey_sha256);

        const auto blob = pq::PQKeyBlob(pk);
        BOOST_CHECK_EQUAL(blob.size(), pq::PQ_MLDSA44_KEYBLOB_SIZE);
        BOOST_CHECK_EQUAL(blob[0], pq::PQ_ALGO_MLDSA44);
        BOOST_CHECK_EQUAL(HexStr(Sha256(blob)), d.keyblob_sha256);

        const uint256 pqkh = pq::PQKeyHash(blob);
        BOOST_CHECK_EQUAL(HexStr(pqkh), d.pqkh);

        const CScript spk = pq::GetScriptForPQKeyHash(pqkh);
        BOOST_CHECK_EQUAL(HexStr(spk), d.scriptPubKey);
        BOOST_CHECK_EQUAL(spk.size(), pq::PQ_SCRIPTPUBKEY_SIZE);
        uint256 back;
        BOOST_CHECK(pq::IsPayToPQKeyHash(spk, &back));
        BOOST_CHECK(back == pqkh);

        std::vector<std::vector<unsigned char>> sols;
        BOOST_CHECK(Solver(spk, sols) == TxoutType::PQ_KEYHASH);
        BOOST_REQUIRE_EQUAL(sols.size(), 1U);
        BOOST_CHECK(uint256(sols[0]) == pqkh);
        BOOST_CHECK_EQUAL(GetTxnOutputType(TxoutType::PQ_KEYHASH), "pqkh");

        CTxDestination dest;
        BOOST_CHECK(ExtractDestination(spk, dest));
        BOOST_REQUIRE(std::holds_alternative<PQKeyHash>(dest));
        BOOST_CHECK(uint256(std::get<PQKeyHash>(dest)) == pqkh);
        BOOST_CHECK(IsValidDestination(dest));
        BOOST_CHECK(GetScriptForDestination(dest) == spk);

        // Addresses: mainnet "BQ..." and every test network "TQ..." (52 chars each).
        SelectParams(ChainType::MAIN);
        BOOST_CHECK_EQUAL(EncodeDestination(dest), d.address_main);
        BOOST_CHECK_EQUAL(std::string(d.address_main).size(), 52U);
        BOOST_CHECK_EQUAL(std::string(d.address_main).substr(0, 2), "BQ");
        BOOST_CHECK(IsValidDestinationString(d.address_main));
        BOOST_CHECK(!IsValidDestinationString(d.address_test));
        {
            const CTxDestination dec = DecodeDestination(d.address_main);
            BOOST_REQUIRE(std::holds_alternative<PQKeyHash>(dec));
            BOOST_CHECK(uint256(std::get<PQKeyHash>(dec)) == pqkh);
        }
        SelectParams(ChainType::REGTEST);
        BOOST_CHECK_EQUAL(EncodeDestination(dest), d.address_test);
        BOOST_CHECK_EQUAL(std::string(d.address_test).size(), 52U);
        BOOST_CHECK_EQUAL(std::string(d.address_test).substr(0, 2), "TQ");
        BOOST_CHECK(IsValidDestinationString(d.address_test));
        BOOST_CHECK(!IsValidDestinationString(d.address_main));
        {
            const CTxDestination dec = DecodeDestination(d.address_test);
            BOOST_REQUIRE(std::holds_alternative<PQKeyHash>(dec));
            BOOST_CHECK(uint256(std::get<PQKeyHash>(dec)) == pqkh);
        }
        SelectParams(ChainType::MAIN);
    }
}

BOOST_AUTO_TEST_CASE(pqsig_address_examples)
{
    SelectParams(ChainType::MAIN);
    const std::vector<unsigned char> ff(32, 0xff);
    BOOST_CHECK_EQUAL(EncodeDestination(PQKeyHash(uint256::ZERO)), V::ADDRESS_EXAMPLE_PQKH_00);
    BOOST_CHECK_EQUAL(EncodeDestination(PQKeyHash(uint256(ff))), V::ADDRESS_EXAMPLE_PQKH_FF);
    for (const char* a : {V::ADDRESS_EXAMPLE_PQKH_00, V::ADDRESS_EXAMPLE_PQKH_FF}) {
        BOOST_CHECK_EQUAL(std::string(a).size(), 52U);
        BOOST_CHECK_EQUAL(std::string(a).substr(0, 2), "BQ");
        BOOST_CHECK(IsValidDestinationString(a));
    }
    // A damaged address (checksum) and a truncated one are invalid.
    std::string bad{V::ADDRESS_EXAMPLE_PQKH_00};
    bad[10] = (bad[10] == 'a') ? 'b' : 'a';
    BOOST_CHECK(!IsValidDestinationString(bad));
    BOOST_CHECK(!IsValidDestinationString(std::string(V::ADDRESS_EXAMPLE_PQKH_00).substr(0, 51)));
    // Test-network encoding of the whole payload range stays 52 chars and "TQ".
    SelectParams(ChainType::REGTEST);
    for (const auto& payload : {std::vector<unsigned char>(32, 0x00), ff}) {
        const std::string a = EncodeDestination(PQKeyHash(uint256(payload)));
        BOOST_CHECK_EQUAL(a.size(), 52U);
        BOOST_CHECK_EQUAL(a.substr(0, 2), "TQ");
        BOOST_CHECK(IsValidDestinationString(a));
    }
    BOOST_CHECK(!IsValidDestinationString(V::ADDRESS_EXAMPLE_PQKH_00)); // a mainnet address is not a regtest one
    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(pqsig_sighash)
{
    BOOST_REQUIRE_EQUAL(V::SIGHASH_COUNT, 3U);
    const auto ctx = CtxSpan(pq::CTX_TX);
    for (size_t t = 0; t < V::SIGHASH_COUNT; ++t) {
        const auto& tv = V::SIGHASH[t];
        BOOST_TEST_MESSAGE("sighash tx: " << tv.label);
        const CTransaction tx{DecodeTx(tv.tx, tv.tx_len)};
        BOOST_CHECK_EQUAL(tx.GetHash().ToString(), tv.txid);
        BOOST_REQUIRE_EQUAL(tv.n_prevouts, tx.vin.size());

        std::vector<CTxOut> spent;
        for (size_t i = 0; i < tv.n_prevouts; ++i) {
            const auto s = H(tv.prevouts[i].scriptPubKey);
            spent.emplace_back(tv.prevouts[i].amount, CScript(s.begin(), s.end()));
        }
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(spent));
        // A P2PQH prevout makes Init precompute the BIP-143 hashes even without a witness.
        BOOST_CHECK(txdata.m_bip143_segwit_ready);

        for (size_t i = 0; i < tv.n_inputs; ++i) {
            const auto& in = tv.inputs[i];
            const auto sc = H(in.scriptCode);
            const CScript scriptCode(sc.begin(), sc.end());
            BOOST_CHECK(scriptCode == spent[in.input].scriptPubKey);
            BOOST_CHECK_EQUAL(in.amount, spent[in.input].nValue);

            const uint256 digest_cached = pq::PQSigHash(tx, in.input, in.amount, scriptCode, &txdata);
            const uint256 digest_plain = pq::PQSigHash(tx, in.input, in.amount, scriptCode, nullptr);
            BOOST_CHECK_EQUAL(HexStr(digest_cached), in.digest);
            BOOST_CHECK_EQUAL(HexStr(digest_plain), in.digest);
            if (in.preimage) {
                HashWriter ss{TaggedHash(pq::TAG_SIGHASH)};
                const auto pre = H(in.preimage);
                ss.write(AsBytes(Span{pre}));
                BOOST_CHECK_EQUAL(HexStr(ss.GetSHA256()), in.digest);
            }

            const VectorKey k = KeyAt(in.key_index);
            const auto sig = H(in.sig);
            BOOST_CHECK_EQUAL(sig.size(), mldsa44::SIG_SIZE);
            BOOST_CHECK(mldsa44::Verify(k.pk, digest_cached, ctx, sig));
            // Deterministic signing reproduces the authority's signature byte-for-byte.
            std::vector<unsigned char> mine;
            BOOST_REQUIRE(mldsa44::Sign(k.sk, digest_cached, ctx, mine));
            BOOST_CHECK_EQUAL(HexStr(mine), in.sig);
            // Wrong ctx: does not verify.
            BOOST_CHECK(!mldsa44::Verify(k.pk, digest_cached, CtxSpan("blazecoin-msg-v1"), sig));
            BOOST_CHECK(!mldsa44::Verify(k.pk, digest_cached, CtxSpan(""), sig));

            if (in.scriptSig) {
                BOOST_CHECK(tx.vin[in.input].scriptSig == (CScript() << sig << k.blob));
                BOOST_CHECK_EQUAL(HexStr(tx.vin[in.input].scriptSig), in.scriptSig);
                BOOST_CHECK_EQUAL(tx.vin[in.input].scriptSig.size(), V::SCRIPTSIG_LEN);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(pqsig_spend)
{
    BOOST_REQUIRE_EQUAL(V::SPEND_COUNT, 40U);
    static const CScriptWitness no_witness;
    for (size_t s = 0; s < V::SPEND_COUNT; ++s) {
        const auto& sv = V::SPEND[s];
        BOOST_TEST_MESSAGE("spend: " << sv.label);
        const CTransaction tx{sv.tx_ref >= 0 ? DecodeTx(V::SIGHASH[sv.tx_ref].tx, V::SIGHASH[sv.tx_ref].tx_len) : DecodeTx(sv.tx, sv.tx_len)};
        const auto spk_bytes = H(sv.scriptPubKey);
        const CScript spk(spk_bytes.begin(), spk_bytes.end());
        const CAmount amount{sv.amount};
        const std::string expect{sv.expect};
        ScriptError err;

        if (expect == "PRE_ACTIVATION") {
            // Without SCRIPT_VERIFY_PQSIG the template is a BASE script: the 2,420-byte push is oversized.
            BOOST_REQUIRE(sv.sigversion && std::string(sv.sigversion) == "BASE");
            const unsigned int pre_flag_sets[] = {SCRIPT_VERIFY_NONE, MANDATORY_SCRIPT_VERIFY_FLAGS, STANDARD_SCRIPT_VERIFY_FLAGS};
            for (const unsigned int flags : pre_flag_sets) {
                const TransactionSignatureChecker checker(&tx, sv.input, amount, MissingDataBehavior::FAIL);
                BOOST_CHECK(!VerifyScript(tx.vin[sv.input].scriptSig, spk, &no_witness, flags, checker, &err));
                BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_PUSH_SIZE));
            }
            // And the bare template with an EMPTY scriptSig is a bad opcode, never a NOP.
            {
                const TransactionSignatureChecker checker(&tx, sv.input, amount, MissingDataBehavior::FAIL);
                BOOST_CHECK(!VerifyScript(CScript(), spk, &no_witness, SCRIPT_VERIFY_NONE, checker, &err));
                BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_BAD_OPCODE));
            }
            continue;
        }

        const ScriptError want = ExpectedError(expect);
        // Consensus flag set (no MINIMALDATA, so the malformed-push cases report the PQ code).
        {
            const TransactionSignatureChecker checker(&tx, sv.input, amount, MissingDataBehavior::FAIL);
            const bool ok = VerifyScript(tx.vin[sv.input].scriptSig, spk, &no_witness, CONSENSUS_PQ_FLAGS, checker, &err);
            BOOST_CHECK_EQUAL(ok, want == SCRIPT_ERR_OK);
            BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(want));
        }
        if (want != SCRIPT_ERR_OK) continue;

        // Standard flag set, cached txdata (as the mempool sees it) and the signature cache (as the block does).
        {
            const TransactionSignatureChecker checker(&tx, sv.input, amount, MissingDataBehavior::FAIL);
            BOOST_CHECK(VerifyScript(tx.vin[sv.input].scriptSig, spk, &no_witness, STANDARD_PQ_FLAGS, checker, &err));
            BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_OK));
        }
        if (sv.tx_ref >= 0) {
            const auto& tv = V::SIGHASH[sv.tx_ref];
            std::vector<CTxOut> spent;
            for (size_t i = 0; i < tv.n_prevouts; ++i) {
                const auto b = H(tv.prevouts[i].scriptPubKey);
                spent.emplace_back(tv.prevouts[i].amount, CScript(b.begin(), b.end()));
            }
            PrecomputedTransactionData txdata;
            txdata.Init(tx, std::move(spent));
            const TransactionSignatureChecker cached(&tx, sv.input, amount, txdata, MissingDataBehavior::FAIL);
            BOOST_CHECK(VerifyScript(tx.vin[sv.input].scriptSig, spk, &no_witness, CONSENSUS_PQ_FLAGS, cached, &err));

            SignatureCache sigcache{1 << 20};
            for (int pass = 0; pass < 2; ++pass) { // second pass is a cache hit
                const CachingTransactionSignatureChecker caching(&tx, sv.input, amount, /*storeIn=*/true, sigcache, txdata);
                BOOST_CHECK(VerifyScript(tx.vin[sv.input].scriptSig, spk, &no_witness, CONSENSUS_PQ_FLAGS, caching, &err));
                BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_OK));
            }
            // A different amount changes the digest: the cached entry must not match.
            const CachingTransactionSignatureChecker caching(&tx, sv.input, amount + 1, /*storeIn=*/true, sigcache, txdata);
            BOOST_CHECK(!VerifyScript(tx.vin[sv.input].scriptSig, spk, &no_witness, CONSENSUS_PQ_FLAGS, caching, &err));
            BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_PQ_SIG_INVALID));
        }
        // A missing amount cannot be signed over: MissingDataBehavior::FAIL fails, never passes.
        {
            const TransactionSignatureChecker checker(&tx, sv.input, MAX_MONEY + 1, MissingDataBehavior::FAIL);
            BOOST_CHECK(!VerifyScript(tx.vin[sv.input].scriptSig, spk, &no_witness, CONSENSUS_PQ_FLAGS, checker, &err));
        }
    }
}

BOOST_AUTO_TEST_CASE(pqsig_sizes_and_sigops)
{
    const auto& tv = V::SIGHASH[2];
    const CTransaction tx26{DecodeTx(tv.tx, tv.tx_len)};
    BOOST_CHECK_EQUAL(tx26.vin.size(), 26U);
    BOOST_CHECK_EQUAL(tv.tx_len, V::TX26_SERIALIZED_LEN);
    BOOST_CHECK_EQUAL(::GetSerializeSize(TX_NO_WITNESS(tx26)), V::TX26_SERIALIZED_LEN);
    BOOST_CHECK_LE(GetTransactionWeight(tx26), MAX_STANDARD_TX_WEIGHT);
    for (const auto& in : tx26.vin) {
        BOOST_CHECK_EQUAL(in.scriptSig.size(), V::SCRIPTSIG_LEN);
        BOOST_CHECK_EQUAL(::GetSerializeSize(in), V::INPUT_LEN);
    }
    // 27 PQ inputs would not fit a standard transaction.
    BOOST_CHECK_GT(GetTransactionWeight(tx26) + WITNESS_SCALE_FACTOR * V::INPUT_LEN, MAX_STANDARD_TX_WEIGHT);

    // OP_CHECKPQSIG = 50 legacy sigops, counted where the output is created (like P2PK/P2PKH).
    const CScript spk = pq::GetScriptForPQKeyHash(uint256::ZERO);
    BOOST_CHECK_EQUAL(spk.GetSigOpCount(/*fAccurate=*/false), PQ_SIGOP_COST);
    BOOST_CHECK_EQUAL(spk.GetSigOpCount(/*fAccurate=*/true), PQ_SIGOP_COST);
    BOOST_CHECK_EQUAL(PQ_SIGOP_COST, 50U);
    CMutableTransaction creator;
    creator.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
    for (int i = 0; i < 26; ++i) creator.vout.emplace_back(1000, spk);
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(CTransaction(creator)), 26U * PQ_SIGOP_COST);
    // Spending them costs nothing extra in the legacy count (the pushes carry no sigops).
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(tx26), 1U + PQ_SIGOP_COST); // outputs: one P2PKH + one P2PQH
}

BOOST_AUTO_TEST_CASE(pqsig_policy)
{
    const CScript spk = pq::GetScriptForPQKeyHash(uint256::ZERO);
    TxoutType type;
    BOOST_CHECK(!IsStandard(spk, std::nullopt, type, /*pqsig_active=*/false));
    BOOST_CHECK(type == TxoutType::PQ_KEYHASH);
    BOOST_CHECK(IsStandard(spk, std::nullopt, type, /*pqsig_active=*/true));
    BOOST_CHECK(!IsStandard(spk, std::nullopt, type)); // default = pre-activation

    const CFeeRate dust{DUST_RELAY_TX_FEE};
    std::string reason;
    // tx1 (one PQ input, P2PKH + P2PQH outputs): non-standard before H_Q, standard after.
    const CTransaction tx1{DecodeTx(V::SIGHASH[0].tx, V::SIGHASH[0].tx_len)};
    BOOST_CHECK(!IsStandardTx(tx1, MAX_OP_RETURN_RELAY, true, dust, reason, false));
    BOOST_CHECK_EQUAL(reason, "scriptsig-size");
    BOOST_CHECK(IsStandardTx(tx1, MAX_OP_RETURN_RELAY, true, dust, reason, true));
    // tx26: the standard-size maximum.
    const CTransaction tx26{DecodeTx(V::SIGHASH[2].tx, V::SIGHASH[2].tx_len)};
    BOOST_CHECK(IsStandardTx(tx26, MAX_OP_RETURN_RELAY, true, dust, reason, true));

    // Inputs: a P2PQH prevout is non-standard before H_Q; after, the 3,739-byte scriptSig is standard
    // only against a P2PQH prevout.
    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);
    for (size_t i = 0; i < tx1.vin.size(); ++i) {
        const auto b = H(V::SIGHASH[0].prevouts[i].scriptPubKey);
        coins.AddCoin(tx1.vin[i].prevout, Coin(CTxOut(V::SIGHASH[0].prevouts[i].amount, CScript(b.begin(), b.end())), 1, false), false);
    }
    BOOST_CHECK(!AreInputsStandard(tx1, coins, false));
    BOOST_CHECK(AreInputsStandard(tx1, coins, true));

    CMutableTransaction legacy{tx1};
    const COutPoint legacy_prevout(Txid::FromUint256(uint256::ONE), 5);
    legacy.vin[0].prevout = legacy_prevout;
    coins.AddCoin(legacy_prevout, Coin(CTxOut(tx1.vin.size() * 1, CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG), 1, false), false);
    BOOST_CHECK(IsStandardTx(CTransaction(legacy), MAX_OP_RETURN_RELAY, true, dust, reason, true)); // shape passes...
    BOOST_CHECK(!AreInputsStandard(CTransaction(legacy), coins, true));                            // ...the prevout check does not

    // An over-cap scriptSig that is NOT the PQ shape stays non-standard even after H_Q.
    CMutableTransaction big{tx1};
    big.vin[0].scriptSig = CScript() << std::vector<unsigned char>(1700, 0x01) << std::vector<unsigned char>(40, 0x02);
    BOOST_CHECK_GT(big.vin[0].scriptSig.size(), MAX_STANDARD_SCRIPTSIG_SIZE);
    BOOST_CHECK(!IsStandardTx(CTransaction(big), MAX_OP_RETURN_RELAY, true, dust, reason, true));
    BOOST_CHECK_EQUAL(reason, "scriptsig-size");
}

BOOST_AUTO_TEST_CASE(pqsig_interpreter_edges)
{
    ScriptError err;
    std::vector<std::vector<unsigned char>> stack;
    const BaseSignatureChecker nochecker;

    // 5,000-byte elements are allowed only in the PQ context.
    const CScript push600 = CScript() << std::vector<unsigned char>(600, 0xab);
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, push600, SCRIPT_VERIFY_NONE, nochecker, SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_PUSH_SIZE));
    stack.clear();
    BOOST_CHECK(EvalScript(stack, push600, SCRIPT_VERIFY_NONE, nochecker, SigVersion::PQ, &err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    const CScript push5000 = CScript() << std::vector<unsigned char>(5000, 0xab);
    stack.clear();
    BOOST_CHECK(EvalScript(stack, push5000, SCRIPT_VERIFY_NONE, nochecker, SigVersion::PQ, &err));
    const CScript push5001 = CScript() << std::vector<unsigned char>(5001, 0xab);
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, push5001, SCRIPT_VERIFY_NONE, nochecker, SigVersion::PQ, &err));
    BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_PUSH_SIZE));

    // The PQ context knows pushes and OP_CHECKPQSIG only.
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, CScript() << OP_1 << OP_1 << OP_ADD, SCRIPT_VERIFY_NONE, nochecker, SigVersion::PQ, &err));
    BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_BAD_OPCODE));
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, CScript() << OP_1 << OP_1 << OP_CHECKSIG, SCRIPT_VERIFY_NONE, nochecker, SigVersion::PQ, &err));
    BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_BAD_OPCODE));
    // OP_CHECKPQSIG (0xba) in BASE / WITNESS_V0 stays a bad opcode.
    for (const SigVersion sv : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        stack.clear();
        BOOST_CHECK(!EvalScript(stack, CScript() << OP_1 << OP_1 << OP_1 << OP_CHECKPQSIG, SCRIPT_VERIFY_NONE, nochecker, sv, &err));
        BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_BAD_OPCODE));
    }
    // OP_CHECKPQSIG with too few stack elements.
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, CScript() << OP_1 << OP_CHECKPQSIG, SCRIPT_VERIFY_NONE, nochecker, SigVersion::PQ, &err));
    BOOST_CHECK_EQUAL(ScriptErrorString(err), ScriptErrorString(SCRIPT_ERR_INVALID_STACK_OPERATION));

    // Template recognition is exact.
    BOOST_CHECK(pq::IsPayToPQKeyHash(pq::GetScriptForPQKeyHash(uint256::ZERO)));
    BOOST_CHECK(!pq::IsPayToPQKeyHash(CScript() << std::vector<unsigned char>(32, 0) << OP_CHECKSIG));
    BOOST_CHECK(!pq::IsPayToPQKeyHash(CScript() << std::vector<unsigned char>(31, 0) << OP_CHECKPQSIG));
    BOOST_CHECK(!pq::IsPayToPQKeyHash(CScript() << std::vector<unsigned char>(33, 0) << OP_CHECKPQSIG));
    BOOST_CHECK(!pq::IsPayToPQKeyHash(CScript() << OP_1 << std::vector<unsigned char>(32, 0)));
    BOOST_CHECK(!pq::IsPayToPQKeyHash(CScript()));

    // ParseScript accepts the PQ name; GetOpName keeps the upstream one.
    BOOST_CHECK(ParseScript("OP_CHECKPQSIG") == (CScript() << OP_CHECKPQSIG));
    BOOST_CHECK(ParseScript("CHECKPQSIG") == (CScript() << OP_CHECKPQSIG));
    BOOST_CHECK_EQUAL(GetOpName(OP_CHECKPQSIG), "OP_CHECKSIGADD");

    // A signature under the wrong FIPS 204 ctx never verifies as a transaction signature.
    const VectorKey k = KeyAt(0);
    const uint256 msg = H256(V::SIGHASH[0].inputs[0].digest);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(mldsa44::Sign(k.sk, msg, CtxSpan("blazecoin-msg-v1"), sig));
    BOOST_CHECK(mldsa44::Verify(k.pk, msg, CtxSpan("blazecoin-msg-v1"), sig));
    BOOST_CHECK(!mldsa44::Verify(k.pk, msg, CtxSpan(pq::CTX_TX), sig));
    // Size guards in the wrapper.
    BOOST_CHECK(!mldsa44::Verify(Span{k.pk}.first(1311), msg, CtxSpan(pq::CTX_TX), sig));
    BOOST_CHECK(!mldsa44::Verify(k.pk, msg, CtxSpan(pq::CTX_TX), Span{sig}.first(2419)));
    std::vector<unsigned char> pk2, sk2;
    BOOST_CHECK(!mldsa44::KeyGenFromSeed(std::vector<unsigned char>(31, 0), pk2, sk2));
    BOOST_CHECK(!mldsa44::Sign(Span{k.sk}.first(100), msg, CtxSpan(pq::CTX_TX), sig));
    BOOST_CHECK(!mldsa44::Sign(k.sk, msg, std::vector<unsigned char>(256, 0), sig));
}

BOOST_AUTO_TEST_SUITE_END()
