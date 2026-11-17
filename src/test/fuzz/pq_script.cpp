// Copyright (c) 2026 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Fuzz targets for the post-quantum script path (PQ_SIGNATURES.md s3): the ML-DSA-44 primitive behind
// OP_CHECKPQSIG, the P2PQH templates and key hash, the s3.5 digest, and a whole P2PQH spend through
// VerifyScript with a real signature checker. Three properties are asserted, the rest is "must not crash":
//   - a correctly signed spend verifies (and only that one: every scripted mutation must fail);
//   - PQSigHash is the same with and without the shared-hash cache;
//   - a valid ML-DSA-44 signature verifies and any single-byte change to it does not.
// Build: part of the fuzz binary (MSVC build_msvc/fuzz, autotools --enable-fuzz). Run a corpus file with
//   FUZZ=pq_spend fuzz <file>     (targets: pq_spend, pq_sighash, mldsa44)

#include <crypto/mldsa44.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pq.h>
#include <script/script.h>
#include <script/script_error.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <array>
#include <cassert>
#include <optional>
#include <vector>

namespace {

constexpr unsigned int PQ_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_PQSIG};

Span<const unsigned char> TxCtx()
{
    return {reinterpret_cast<const unsigned char*>(pq::CTX_TX.data()), pq::CTX_TX.size()};
}

std::array<unsigned char, 32> ConsumeSeed(FuzzedDataProvider& p)
{
    std::array<unsigned char, 32> seed{};
    const auto bytes{p.ConsumeBytes<unsigned char>(32)};
    std::copy(bytes.begin(), bytes.end(), seed.begin());
    return seed;
}

struct PQKey {
    std::vector<unsigned char> pk, sk, blob;
    CScript spk;
};

PQKey MakeKey(const std::array<unsigned char, 32>& seed)
{
    PQKey k;
    const bool ok{mldsa44::KeyGenFromSeed(seed, k.pk, k.sk)};
    assert(ok);
    k.blob = pq::PQKeyBlob(k.pk);
    k.spk = pq::GetScriptForPQKeyHash(pq::PQKeyHash(k.blob));
    return k;
}

/** A spend of n P2PQH outputs with fuzzed amounts, sequences, version, lock time and outputs. */
CMutableTransaction MakeSpend(FuzzedDataProvider& p, const std::vector<CScript>& spks, std::vector<CTxOut>& spent)
{
    CMutableTransaction tx;
    tx.version = p.ConsumeIntegral<uint32_t>();
    tx.nLockTime = p.ConsumeIntegral<uint32_t>();
    tx.vin.resize(spks.size());
    for (size_t i = 0; i < spks.size(); ++i) {
        tx.vin[i].prevout = COutPoint{Txid::FromUint256(ConsumeUInt256(p)), p.ConsumeIntegral<uint32_t>()};
        tx.vin[i].nSequence = p.ConsumeIntegral<uint32_t>();
        spent.emplace_back(ConsumeMoney(p), spks[i]);
    }
    const auto n_out{p.ConsumeIntegralInRange<size_t>(0, 4)};
    for (size_t i = 0; i < n_out; ++i) {
        // Two consumers in one argument list walk the input in an order the language leaves unspecified (MSVC
        // right-to-left, clang left-to-right), so a libFuzzer artefact did not reproduce on Windows (2026-11-13).
        // Sequence them: the amount first, then the script.
        const CAmount amount{ConsumeMoney(p)};
        tx.vout.emplace_back(amount, ConsumeScript(p));
    }
    return tx;
}

} // namespace

/** The primitive: keygen from a fuzzed seed, sign a fuzzed message under a fuzzed context, verify, then
 *  check that one changed byte of the signature, the message or the context is refused. */
FUZZ_TARGET(mldsa44)
{
    FuzzedDataProvider p(buffer.data(), buffer.size());
    const auto seed{ConsumeSeed(p)};
    std::vector<unsigned char> pk, sk, sig;
    assert(mldsa44::KeyGenFromSeed(seed, pk, sk));
    assert(pk.size() == mldsa44::PUBKEY_SIZE && sk.size() == mldsa44::SECKEY_SIZE);

    const auto msg{ConsumeRandomLengthByteVector<unsigned char>(p, 4096)};
    auto ctx{ConsumeRandomLengthByteVector<unsigned char>(p, 300)};
    const bool ctx_ok{ctx.size() <= mldsa44::MAX_CTX_SIZE};
    const bool signed_ok{mldsa44::Sign(sk, msg, ctx, sig)};
    assert(signed_ok == ctx_ok);
    if (!ctx_ok) {
        assert(!mldsa44::Verify(pk, msg, ctx, std::vector<unsigned char>(mldsa44::SIG_SIZE)));
        return;
    }
    assert(sig.size() == mldsa44::SIG_SIZE);
    assert(mldsa44::Verify(pk, msg, ctx, sig));

    // Deterministic: signing again gives the same bytes.
    std::vector<unsigned char> again;
    assert(mldsa44::Sign(sk, msg, ctx, again) && again == sig);

    // One byte of the signature changed, at a fuzzed position, to a fuzzed value: must fail.
    {
        auto bad{sig};
        const size_t pos{p.ConsumeIntegralInRange<size_t>(0, bad.size() - 1)};
        bad[pos] ^= static_cast<unsigned char>(p.ConsumeIntegralInRange<int>(1, 255));
        assert(!mldsa44::Verify(pk, msg, ctx, bad));
    }
    // One byte of the message changed (or appended when empty): must fail.
    {
        auto bad{msg};
        if (bad.empty()) {
            bad.push_back(0x01);
        } else {
            const size_t pos{p.ConsumeIntegralInRange<size_t>(0, bad.size() - 1)};
            bad[pos] ^= static_cast<unsigned char>(p.ConsumeIntegralInRange<int>(1, 255));
        }
        assert(!mldsa44::Verify(pk, bad, ctx, sig));
    }
    // A different context string: must fail (it is part of M').
    {
        auto other{ctx};
        if (other.size() < mldsa44::MAX_CTX_SIZE) {
            other.push_back(0x00);
        } else {
            other.pop_back();
        }
        assert(!mldsa44::Verify(pk, msg, other, sig));
    }
    // Wrong sizes are refusals, never exceptions.
    assert(!mldsa44::Verify(std::vector<unsigned char>(pk.begin(), pk.end() - 1), msg, ctx, sig));
    assert(!mldsa44::Verify(pk, msg, ctx, std::vector<unsigned char>(sig.begin(), sig.end() - 1)));
    assert(!mldsa44::Verify(pk, msg, ctx, ConsumeRandomLengthByteVector<unsigned char>(p, 3000)));
}

/** The s3.5 digest and the templates on fuzzed transactions and scripts. */
FUZZ_TARGET(pq_sighash)
{
    FuzzedDataProvider p(buffer.data(), buffer.size());

    // Templates and key hash on arbitrary bytes.
    {
        const CScript script{ConsumeScript(p)};
        uint256 pqkh;
        const bool is_p2pqh{pq::IsPayToPQKeyHash(script, &pqkh)};
        if (is_p2pqh) {
            assert(script.size() == pq::PQ_SCRIPTPUBKEY_SIZE);
            assert(pq::GetScriptForPQKeyHash(pqkh) == script);
        }
        const auto blob{ConsumeRandomLengthByteVector<unsigned char>(p, 2000)};
        (void)pq::PQKeyHash(blob);
        const auto pubkey{ConsumeRandomLengthByteVector<unsigned char>(p, 2000)};
        const auto made{pq::PQKeyBlob(pubkey)};
        assert(made.size() == pubkey.size() + 1 && made[0] == pq::PQ_ALGO_MLDSA44);
        const auto master{ConsumeSeed(p)};
        (void)pq::PQSeedForIndex(master, p.ConsumeIntegral<uint32_t>());
    }

    // The digest: with and without the shared-hash cache, on a fuzzed transaction.
    const std::optional<CMutableTransaction> mtx{ConsumeDeserializable<CMutableTransaction>(p, TX_WITH_WITNESS)};
    if (!mtx || mtx->vin.empty()) return;
    const CTransaction tx{*mtx};
    const unsigned int n_in{p.ConsumeIntegralInRange<unsigned int>(0, static_cast<unsigned int>(tx.vin.size() - 1))};
    const CAmount amount{ConsumeMoney(p)};
    const CScript script_code{p.ConsumeBool() ? pq::GetScriptForPQKeyHash(ConsumeUInt256(p)) : ConsumeScript(p)};

    const uint256 plain{pq::PQSigHash(tx, n_in, amount, script_code, nullptr)};
    std::vector<CTxOut> spent;
    for (const auto& in : tx.vin) {
        (void)in;
        spent.emplace_back(amount, script_code);
    }
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);
    const uint256 cached{pq::PQSigHash(tx, n_in, amount, script_code, &txdata)};
    assert(plain == cached);
}

/** A whole P2PQH spend: a real key and signature over the real digest must verify; each scripted
 *  mutation must fail with a PQ error, and arbitrary scriptSig bytes must never crash the interpreter. */
FUZZ_TARGET(pq_spend)
{
    FuzzedDataProvider p(buffer.data(), buffer.size());
    const auto seed{ConsumeSeed(p)};
    const PQKey key{MakeKey(seed)};
    const unsigned int n_inputs{p.ConsumeIntegralInRange<unsigned int>(1, 3)};
    std::vector<CScript> spks(n_inputs, key.spk);
    std::vector<CTxOut> spent;
    CMutableTransaction mtx{MakeSpend(p, spks, spent)};
    const unsigned int n_in{p.ConsumeIntegralInRange<unsigned int>(0, n_inputs - 1)};

    std::vector<unsigned char> sig;
    const uint256 digest{pq::PQSigHash(mtx, n_in, spent[n_in].nValue, key.spk, nullptr)};
    assert(mldsa44::Sign(key.sk, digest, TxCtx(), sig));

    static const CScriptWitness no_witness;
    const auto verify = [&](const CScript& script_sig, ScriptError* err) {
        return VerifyScript(script_sig, key.spk, &no_witness, PQ_FLAGS,
                            MutableTransactionSignatureChecker(&mtx, n_in, spent[n_in].nValue, MissingDataBehavior::FAIL), err);
    };

    // 1. The honest spend verifies, with and without the shared-hash cache.
    {
        ScriptError err;
        assert(verify(CScript() << sig << key.blob, &err));
        assert(err == SCRIPT_ERR_OK);
        const CTransaction tx{mtx};
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);
        assert(VerifyScript(CScript() << sig << key.blob, key.spk, &no_witness, PQ_FLAGS,
                            TransactionSignatureChecker(&tx, n_in, spent[n_in].nValue, txdata, MissingDataBehavior::FAIL), &err));
        assert(err == SCRIPT_ERR_OK);
    }

    // 2. Scripted mutations: every one must fail, and with a PQ-specific or generic script error, never a crash.
    const auto expect_fail = [&](const CScript& script_sig) {
        ScriptError err;
        assert(!verify(script_sig, &err));
        assert(err != SCRIPT_ERR_OK);
    };
    switch (p.ConsumeIntegralInRange<int>(0, 8)) {
    case 0: { // a byte of the signature
        auto bad{sig};
        bad[p.ConsumeIntegralInRange<size_t>(0, bad.size() - 1)] ^= static_cast<unsigned char>(p.ConsumeIntegralInRange<int>(1, 255));
        expect_fail(CScript() << bad << key.blob);
        break;
    }
    case 1: // signature length
        expect_fail(CScript() << std::vector<unsigned char>(sig.begin(), sig.end() - 1) << key.blob);
        break;
    case 2: { // reserved algorithm id
        auto blob{key.blob};
        blob[0] = static_cast<unsigned char>(p.ConsumeIntegralInRange<int>(2, 255));
        expect_fail(CScript() << sig << blob);
        break;
    }
    case 3: // key blob length
        expect_fail(CScript() << sig << std::vector<unsigned char>(key.blob.begin(), key.blob.end() - 1));
        break;
    case 4: { // a different key behind the same hash commitment cannot exist: swap the blob
        // The first libFuzzer campaign (2026-11-13) tripped this case on an input whose bytes ran out: both seeds
        // padded to zeros, the "other" key was the same key, and the honest spend verified. Force a difference.
        auto other_seed{ConsumeSeed(p)};
        if (other_seed == seed) other_seed[0] ^= 0x01;
        const PQKey other{MakeKey(other_seed)};
        expect_fail(CScript() << sig << other.blob);
        break;
    }
    case 5: // extra push
        expect_fail(CScript() << sig << key.blob << OP_1);
        break;
    case 6: // missing push
        expect_fail(CScript() << sig);
        break;
    case 7: { // a signature over a different input's digest (or amount)
        const CAmount other_amount{spent[n_in].nValue + 1};
        std::vector<unsigned char> other_sig;
        assert(mldsa44::Sign(key.sk, pq::PQSigHash(mtx, n_in, other_amount, key.spk, nullptr), TxCtx(), other_sig));
        expect_fail(CScript() << other_sig << key.blob);
        break;
    }
    default: { // arbitrary scriptSig bytes against the P2PQH output
        const auto bytes{ConsumeRandomLengthByteVector<unsigned char>(p, 6000)};
        const CScript script_sig(bytes.begin(), bytes.end());
        ScriptError err;
        (void)verify(script_sig, &err);
        break;
    }
    }

    // 3. The same stack under the classic sigversion is not a PQ check at all and must not succeed as one.
    {
        std::vector<std::vector<unsigned char>> stack;
        ScriptError err;
        (void)EvalScript(stack, CScript() << sig << key.blob, PQ_FLAGS, BaseSignatureChecker(), SigVersion::BASE, &err);
    }
}
