// Copyright (c) 2026 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Node-side cost of the post-quantum path (PQ_SIGNATURES.md s4), next to the
// classic path measured in the same harness on the same machine:
//   MLDSA44KeyGen / MLDSA44Sign / MLDSA44Verify   the primitive alone
//   PQSigHashDigest                               the s3.5 digest alone
//   VerifyScriptP2PQH                             one full input: script, digest, key hash, signature
//   VerifyScriptP2PKH                             the same for a classic ECDSA input
//   VerifyTxP2PQH26Inputs / VerifyTxP2PKH26Inputs a 26-input transaction (the largest standard
//                                                 all-PQ transaction) with the shared-hash cache
// No signature cache is involved: every run does the full verification.

#include <bench/bench.h>
#include <crypto/mldsa44.h>
#include <hash.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/pq.h>
#include <script/script.h>
#include <span.h>
#include <test/util/transaction_utils.h>
#include <uint256.h>

#include <array>
#include <cassert>
#include <vector>

namespace {

constexpr unsigned int PQ_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_PQSIG};
constexpr unsigned int CLASSIC_FLAGS{SCRIPT_VERIFY_P2SH};
constexpr unsigned int TX_INPUTS{26};

Span<const unsigned char> TxCtx()
{
    return {reinterpret_cast<const unsigned char*>(pq::CTX_TX.data()), pq::CTX_TX.size()};
}

struct PQKey {
    std::vector<unsigned char> pk, sk, blob;
    CScript spk;
};

PQKey MakePQKey(uint32_t index)
{
    static const std::array<unsigned char, 32> master{{0x42, 0x4c, 0x5a, 0x2d, 0x62, 0x65, 0x6e, 0x63, 0x68}};
    PQKey k;
    const uint256 xi{pq::PQSeedForIndex(master, index)};
    const bool ok{mldsa44::KeyGenFromSeed(xi, k.pk, k.sk)};
    assert(ok);
    k.blob = pq::PQKeyBlob(k.pk);
    k.spk = pq::GetScriptForPQKeyHash(pq::PQKeyHash(k.blob));
    return k;
}

CKey MakeClassicKey(unsigned char n)
{
    std::array<unsigned char, 32> raw{};
    raw[31] = n;
    CKey key;
    key.Set(raw.begin(), raw.end(), /*fCompressedIn=*/true);
    return key;
}

CScript P2PKH(const CPubKey& pub)
{
    return CScript() << OP_DUP << OP_HASH160 << ToByteVector(pub.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
}

/** A transaction with `n` inputs spending `spks[i]` (1 coin each) to one output. */
CMutableTransaction MakeSpend(const std::vector<CScript>& spks, std::vector<CTxOut>& spent)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(spks.size());
    for (size_t i = 0; i < spks.size(); ++i) {
        tx.vin[i].prevout = COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(i + 1)}), 0};
        tx.vin[i].nSequence = CTxIn::SEQUENCE_FINAL;
        spent.emplace_back(CAmount{100'000'000}, spks[i]);
    }
    tx.vout.emplace_back(CAmount{100'000'000} * static_cast<CAmount>(spks.size()), spks[0]);
    return tx;
}

} // namespace

static void MLDSA44KeyGen(benchmark::Bench& bench)
{
    const std::array<unsigned char, 32> seed{{1, 2, 3}};
    std::vector<unsigned char> pk, sk;
    bench.run([&] {
        const bool ok{mldsa44::KeyGenFromSeed(seed, pk, sk)};
        assert(ok);
    });
}

static void MLDSA44Sign(benchmark::Bench& bench)
{
    const PQKey k{MakePQKey(0)};
    uint256 msg{1};
    std::vector<unsigned char> sig;
    bench.run([&] {
        // A new message every run: the number of rejection-sampling rounds depends on it.
        msg = (HashWriter{} << msg).GetSHA256();
        const bool ok{mldsa44::Sign(k.sk, msg, TxCtx(), sig)};
        assert(ok);
    });
}

static void MLDSA44Verify(benchmark::Bench& bench)
{
    const PQKey k{MakePQKey(0)};
    const uint256 msg{7};
    std::vector<unsigned char> sig;
    bool ok{mldsa44::Sign(k.sk, msg, TxCtx(), sig)};
    assert(ok);
    bench.run([&] {
        ok = mldsa44::Verify(k.pk, msg, TxCtx(), sig);
        assert(ok);
    });
}

static void PQSigHashDigest(benchmark::Bench& bench)
{
    const PQKey k{MakePQKey(0)};
    std::vector<CTxOut> spent;
    const CMutableTransaction tx{MakeSpend({k.spk}, spent)};
    bench.run([&] {
        const uint256 digest{pq::PQSigHash(tx, 0, spent[0].nValue, k.spk, nullptr)};
        ankerl::nanobench::doNotOptimizeAway(digest);
    });
}

static void VerifyScriptP2PQH(benchmark::Bench& bench)
{
    const PQKey k{MakePQKey(0)};
    std::vector<CTxOut> spent;
    CMutableTransaction tx{MakeSpend({k.spk}, spent)};
    std::vector<unsigned char> sig;
    bool ok{mldsa44::Sign(k.sk, pq::PQSigHash(tx, 0, spent[0].nValue, k.spk, nullptr), TxCtx(), sig)};
    assert(ok);
    tx.vin[0].scriptSig = CScript() << sig << k.blob;
    static const CScriptWitness no_witness;
    bench.run([&] {
        ScriptError err;
        ok = VerifyScript(tx.vin[0].scriptSig, k.spk, &no_witness, PQ_FLAGS,
                          MutableTransactionSignatureChecker(&tx, 0, spent[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err);
        assert(err == SCRIPT_ERR_OK);
        assert(ok);
    });
}

static void VerifyScriptP2PKH(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};
    const CKey key{MakeClassicKey(1)};
    const CPubKey pub{key.GetPubKey()};
    const CScript spk{P2PKH(pub)};
    std::vector<CTxOut> spent;
    CMutableTransaction tx{MakeSpend({spk}, spent)};
    std::vector<unsigned char> sig;
    bool ok{key.Sign(SignatureHash(spk, tx, 0, SIGHASH_ALL, spent[0].nValue, SigVersion::BASE), sig)};
    assert(ok);
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
    tx.vin[0].scriptSig = CScript() << sig << ToByteVector(pub);
    static const CScriptWitness no_witness;
    bench.run([&] {
        ScriptError err;
        ok = VerifyScript(tx.vin[0].scriptSig, spk, &no_witness, CLASSIC_FLAGS,
                          MutableTransactionSignatureChecker(&tx, 0, spent[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err);
        assert(err == SCRIPT_ERR_OK);
        assert(ok);
    });
}

static void VerifyTxP2PQH26Inputs(benchmark::Bench& bench)
{
    std::vector<PQKey> keys;
    std::vector<CScript> spks;
    for (unsigned int i = 0; i < TX_INPUTS; ++i) {
        keys.push_back(MakePQKey(i));
        spks.push_back(keys.back().spk);
    }
    std::vector<CTxOut> spent;
    CMutableTransaction mtx{MakeSpend(spks, spent)};
    for (unsigned int i = 0; i < TX_INPUTS; ++i) {
        std::vector<unsigned char> sig;
        const bool ok{mldsa44::Sign(keys[i].sk, pq::PQSigHash(mtx, i, spent[i].nValue, spks[i], nullptr), TxCtx(), sig)};
        assert(ok);
        mtx.vin[i].scriptSig = CScript() << sig << keys[i].blob;
    }
    const CTransaction tx{mtx};
    static const CScriptWitness no_witness;
    bench.batch(TX_INPUTS).unit("input").run([&] {
        // As in block validation: the shared hashes are computed once per transaction.
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);
        for (unsigned int i = 0; i < TX_INPUTS; ++i) {
            ScriptError err;
            const bool ok{VerifyScript(tx.vin[i].scriptSig, spks[i], &no_witness, PQ_FLAGS,
                                       TransactionSignatureChecker(&tx, i, spent[i].nValue, txdata, MissingDataBehavior::ASSERT_FAIL), &err)};
            assert(err == SCRIPT_ERR_OK);
            assert(ok);
        }
    });
}

static void VerifyTxP2PKH26Inputs(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};
    std::vector<CKey> keys;
    std::vector<CScript> spks;
    for (unsigned int i = 0; i < TX_INPUTS; ++i) {
        keys.push_back(MakeClassicKey(static_cast<unsigned char>(i + 1)));
        spks.push_back(P2PKH(keys.back().GetPubKey()));
    }
    std::vector<CTxOut> spent;
    CMutableTransaction mtx{MakeSpend(spks, spent)};
    for (unsigned int i = 0; i < TX_INPUTS; ++i) {
        std::vector<unsigned char> sig;
        const bool ok{keys[i].Sign(SignatureHash(spks[i], mtx, i, SIGHASH_ALL, spent[i].nValue, SigVersion::BASE), sig)};
        assert(ok);
        sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
        mtx.vin[i].scriptSig = CScript() << sig << ToByteVector(keys[i].GetPubKey());
    }
    const CTransaction tx{mtx};
    static const CScriptWitness no_witness;
    bench.batch(TX_INPUTS).unit("input").run([&] {
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);
        for (unsigned int i = 0; i < TX_INPUTS; ++i) {
            ScriptError err;
            const bool ok{VerifyScript(tx.vin[i].scriptSig, spks[i], &no_witness, CLASSIC_FLAGS,
                                       TransactionSignatureChecker(&tx, i, spent[i].nValue, txdata, MissingDataBehavior::ASSERT_FAIL), &err)};
            assert(err == SCRIPT_ERR_OK);
            assert(ok);
        }
    });
}

BENCHMARK(MLDSA44KeyGen, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLDSA44Sign, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLDSA44Verify, benchmark::PriorityLevel::HIGH);
BENCHMARK(PQSigHashDigest, benchmark::PriorityLevel::HIGH);
BENCHMARK(VerifyScriptP2PQH, benchmark::PriorityLevel::HIGH);
BENCHMARK(VerifyScriptP2PKH, benchmark::PriorityLevel::HIGH);
BENCHMARK(VerifyTxP2PQH26Inputs, benchmark::PriorityLevel::HIGH);
BENCHMARK(VerifyTxP2PKH26Inputs, benchmark::PriorityLevel::HIGH);
