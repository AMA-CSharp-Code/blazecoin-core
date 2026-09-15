// Copyright (c) 2026 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Blazecoin P2PQH wallet support (PQ_SIGNATURES.md s6): the OutputType::PQ descriptor
// SPKM, "TQ..." addresses on regtest, ML-DSA-44 signing of a P2PQH spend, wallet
// encryption, the PSBT proprietary fields, message signing, the derivation vectors
// (test/pqsig) and the pre-activation refusal to pay a BQ address.

#include <common/signmessage.h>
#include <consensus/amount.h>
#include <crypto/mldsa44.h>
#include <key_io.h>
#include <policy/policy.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/pq.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/solver.h>
#include <streams.h>
#include <test/pqsig_vector_data.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

namespace V = pqsig_vectors;

namespace wallet {
namespace {

struct PQWalletTestingSetup : public WalletTestingSetup {
    PQWalletTestingSetup() : WalletTestingSetup(ChainType::REGTEST) {}

    /** A descriptor wallet with the full OUTPUT_TYPES set of SPKMs, PQ included. */
    void SetupDescriptorWallet() EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet)
    {
        m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_wallet.SetupDescriptorScriptPubKeyMans();
    }

    CTxDestination NewPQDestination()
    {
        auto dest = m_wallet.GetNewDestination(OutputType::PQ, "");
        BOOST_REQUIRE_MESSAGE(dest, util::ErrorString(dest).original);
        BOOST_REQUIRE(std::holds_alternative<PQKeyHash>(*dest));
        return *dest;
    }

    /** A funding output paying `dest` and a one-input spend of it (unsigned). */
    struct Spend {
        CMutableTransaction prev;
        CMutableTransaction tx;
        std::map<COutPoint, Coin> coins;
        CScript spk;
        CAmount amount{COIN};
    };

    Spend MakeSpend(const CTxDestination& dest)
    {
        Spend s;
        s.spk = GetScriptForDestination(dest);
        s.prev.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0)); // a zero-input tx would deserialize as segwit-marked
        s.prev.vout.emplace_back(s.amount, s.spk);
        const COutPoint outpoint{s.prev.GetHash(), 0};
        s.tx.vin.emplace_back(outpoint);
        s.tx.vout.emplace_back(s.amount - 10000, GetScriptForDestination(PKHash(uint160{})));
        s.coins.emplace(outpoint, Coin(s.prev.vout[0], 1, false));
        return s;
    }

    static bool VerifySpend(const Spend& s, unsigned int flags, ScriptError* err = nullptr)
    {
        const CTransaction tx{s.tx};
        PrecomputedTransactionData txdata;
        txdata.Init(tx, {s.prev.vout[0]});
        return VerifyScript(tx.vin[0].scriptSig, s.spk, &tx.vin[0].scriptWitness, flags,
                            TransactionSignatureChecker(&tx, 0, s.amount, txdata, MissingDataBehavior::FAIL), err);
    }
};

constexpr unsigned int PQ_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQSIG};
constexpr int64_t PQ_SCRIPTSIG_SIZE{3739};
constexpr int PQ_INPUT_VSIZE{3782};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_wallet_tests, PQWalletTestingSetup)

BOOST_AUTO_TEST_CASE(pq_wallet_addresses_and_descriptors)
{
    LOCK(m_wallet.cs_wallet);
    SetupDescriptorWallet();

    auto* ext = dynamic_cast<DescriptorScriptPubKeyMan*>(m_wallet.GetScriptPubKeyMan(OutputType::PQ, /*internal=*/false));
    auto* chg = dynamic_cast<DescriptorScriptPubKeyMan*>(m_wallet.GetScriptPubKeyMan(OutputType::PQ, /*internal=*/true));
    BOOST_REQUIRE(ext && chg);
    BOOST_CHECK(ext->GetID() != chg->GetID());

    // External and internal chains have distinct seeds; public form carries a 20-byte seed id, private the 32-byte seed.
    std::string ext_pub, chg_pub, ext_prv, chg_prv;
    BOOST_REQUIRE(ext->GetDescriptorString(ext_pub, /*priv=*/false));
    BOOST_REQUIRE(chg->GetDescriptorString(chg_pub, /*priv=*/false));
    BOOST_REQUIRE(ext->GetDescriptorString(ext_prv, /*priv=*/true));
    BOOST_REQUIRE(chg->GetDescriptorString(chg_prv, /*priv=*/true));
    BOOST_CHECK_EQUAL(ext_pub.substr(0, 13), "pqkh(mldsa44:");
    BOOST_CHECK_EQUAL(ext_pub.find("/*)#"), 13 + 40);
    BOOST_CHECK_EQUAL(ext_prv.find("/*)#"), 13 + 64);
    BOOST_CHECK(ext_pub != chg_pub);
    BOOST_CHECK(ext_prv != chg_prv);
    BOOST_CHECK(ext_prv.find(ext_pub.substr(13, 40)) == std::string::npos); // the seed id is not the seed

    const CTxDestination dest = NewPQDestination();
    const std::string addr = EncodeDestination(dest);
    BOOST_CHECK_EQUAL(addr.size(), 52U);
    BOOST_CHECK_EQUAL(addr.substr(0, 2), "TQ");
    BOOST_CHECK(m_wallet.IsMine(dest) == ISMINE_SPENDABLE);
    BOOST_CHECK(EncodeDestination(NewPQDestination()) != addr);

    auto change = m_wallet.GetNewChangeDestination(OutputType::PQ);
    BOOST_REQUIRE(change);
    BOOST_CHECK(std::holds_alternative<PQKeyHash>(*change));
    BOOST_CHECK(EncodeDestination(*change) != addr);
    BOOST_CHECK(m_wallet.IsMine(*change) == ISMINE_SPENDABLE);

    // The solving provider knows the public key (never the secret), so InferDescriptor yields the single form.
    const CScript spk = GetScriptForDestination(dest);
    BOOST_CHECK(pq::IsPayToPQKeyHash(spk));
    std::unique_ptr<SigningProvider> provider = m_wallet.GetSolvingProvider(spk);
    BOOST_REQUIRE(provider);
    PQKeyPair key;
    BOOST_REQUIRE(provider->GetPQKey(uint256(std::get<PQKeyHash>(dest)), key));
    BOOST_CHECK_EQUAL(key.pubkey.size(), mldsa44::PUBKEY_SIZE);
    BOOST_CHECK(key.seckey.empty());
    BOOST_CHECK(pq::PQKeyHash(pq::PQKeyBlob(key.pubkey)) == uint256(std::get<PQKeyHash>(dest)));

    auto inferred = InferDescriptor(spk, *provider);
    BOOST_REQUIRE(inferred);
    BOOST_CHECK(inferred->IsSolvable());
    BOOST_CHECK(!inferred->IsRange());
    BOOST_CHECK_EQUAL(inferred->ToString().substr(0, 16), "pqkh(mldsa44pub:");
    BOOST_CHECK(inferred->GetOutputType() == OutputType::PQ);
    BOOST_CHECK_EQUAL(*inferred->MaxSatisfactionWeight(true), PQ_SCRIPTSIG_SIZE * WITNESS_SCALE_FACTOR);
    BOOST_CHECK_EQUAL(*inferred->MaxSatisfactionElems(), 2);

    // Fee estimation sees the full 3,782-vbyte input (PQ_SIGNATURES.md s4) - plus the one weight unit the
    // estimator always reserves for a witness stack count, which here tips the rounding up by one vbyte.
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(CTxOut(COIN, spk), &m_wallet, /*coin_control=*/nullptr), PQ_INPUT_VSIZE + 1);

    // A stranger's TQ address is neither ours nor solvable.
    const CTxDestination other{PQKeyHash(uint256::ONE)};
    BOOST_CHECK(m_wallet.IsMine(other) == ISMINE_NO);
    BOOST_CHECK(!m_wallet.GetSolvingProvider(GetScriptForDestination(other)));
}

BOOST_AUTO_TEST_CASE(pq_wallet_sign_spend_and_encrypt)
{
    LOCK(m_wallet.cs_wallet);
    SetupDescriptorWallet();
    const CTxDestination dest = NewPQDestination();

    Spend s = MakeSpend(dest);
    std::map<int, bilingual_str> errors;
    BOOST_REQUIRE(m_wallet.SignTransaction(s.tx, s.coins, SIGHASH_ALL, errors));
    BOOST_CHECK(errors.empty());
    BOOST_CHECK_EQUAL(s.tx.vin[0].scriptSig.size(), PQ_SCRIPTSIG_SIZE);
    BOOST_CHECK(s.tx.vin[0].scriptWitness.IsNull());
    {
        // <sig:2420> <keyblob:1313>, keyblob hashes to the pqkh in the scriptPubKey
        CScript::const_iterator pc = s.tx.vin[0].scriptSig.begin();
        opcodetype op;
        std::vector<unsigned char> sig, keyblob;
        BOOST_REQUIRE(s.tx.vin[0].scriptSig.GetOp(pc, op, sig));
        BOOST_REQUIRE(s.tx.vin[0].scriptSig.GetOp(pc, op, keyblob));
        BOOST_CHECK(pc == s.tx.vin[0].scriptSig.end());
        BOOST_CHECK_EQUAL(sig.size(), pq::PQ_MLDSA44_SIG_SIZE);
        BOOST_CHECK_EQUAL(keyblob.size(), pq::PQ_MLDSA44_KEYBLOB_SIZE);
        BOOST_CHECK(pq::PQKeyHash(keyblob) == uint256(std::get<PQKeyHash>(dest)));
    }
    ScriptError err;
    BOOST_CHECK(VerifySpend(s, PQ_FLAGS, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK(!VerifySpend(s, STANDARD_SCRIPT_VERIFY_FLAGS)); // without the fork flag the template is not spendable

    // Signing is deterministic (FIPS 204 deterministic variant): the same input signs identically.
    Spend again = MakeSpend(dest);
    BOOST_REQUIRE(m_wallet.SignTransaction(again.tx, again.coins, SIGHASH_ALL, errors));
    BOOST_CHECK(again.tx.vin[0].scriptSig == s.tx.vin[0].scriptSig);

    // Tampering with one signature byte fails with the PQ-specific error.
    Spend bad = s;
    bad.tx.vin[0].scriptSig[10] ^= 0x01;
    BOOST_CHECK(!VerifySpend(bad, PQ_FLAGS, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_SIG_INVALID);

    // Only SIGHASH_ALL exists in v1.
    Spend other_type = MakeSpend(dest);
    BOOST_CHECK(!m_wallet.SignTransaction(other_type.tx, other_type.coins, SIGHASH_NONE, errors));

    // Encryption: the seed rides the crypted-key path; locked = cannot sign, unlocked = signs again.
    BOOST_REQUIRE(m_wallet.EncryptWallet("pass"));
    BOOST_CHECK(m_wallet.IsCrypted());
    BOOST_CHECK(m_wallet.IsLocked());
    // EncryptWallet re-seeds a descriptor wallet: the new PQ SPKM is encrypted from birth.
    BOOST_REQUIRE(m_wallet.Unlock("pass"));
    const CTxDestination dest2 = NewPQDestination();
    BOOST_CHECK(EncodeDestination(dest2) != EncodeDestination(dest));
    BOOST_REQUIRE(m_wallet.Lock());
    Spend locked = MakeSpend(dest2);
    errors.clear();
    BOOST_CHECK(!m_wallet.SignTransaction(locked.tx, locked.coins, SIGHASH_ALL, errors));
    BOOST_CHECK(m_wallet.IsMine(dest2) == ISMINE_SPENDABLE); // still recognised while locked (cached pubkey)
    BOOST_REQUIRE(m_wallet.Unlock("pass"));
    Spend unlocked = MakeSpend(dest2);
    errors.clear();
    BOOST_REQUIRE(m_wallet.SignTransaction(unlocked.tx, unlocked.coins, SIGHASH_ALL, errors));
    BOOST_CHECK(VerifySpend(unlocked, PQ_FLAGS));
    // The pre-encryption address is still spendable too (its SPKM was encrypted in place).
    Spend old = MakeSpend(dest);
    BOOST_REQUIRE(m_wallet.SignTransaction(old.tx, old.coins, SIGHASH_ALL, errors));
    BOOST_CHECK(VerifySpend(old, PQ_FLAGS));
}

BOOST_AUTO_TEST_CASE(pq_wallet_derivation_vectors)
{
    // The wallet's addresses from the vectors' master seed are the vectors' addresses (test/pqsig, s6).
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    const std::string desc_str = std::string("pqkh(mldsa44:") + V::DERIVATION[0].master_seed + "/*)";
    FlatSigningProvider keys;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(desc, error);
    BOOST_REQUIRE_EQUAL(keys.keys.size(), 1U);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 10, 0);
    auto* spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(m_wallet.AddWalletDescriptor(w_desc, keys, "", /*internal=*/false));
    BOOST_REQUIRE(spkm);
    m_wallet.AddActiveScriptPubKeyMan(spkm->GetID(), OutputType::PQ, /*internal=*/false);

    for (size_t i = 0; i < V::DERIVATION_COUNT; ++i) {
        const auto dest = m_wallet.GetNewDestination(OutputType::PQ, "");
        BOOST_REQUIRE(dest);
        BOOST_CHECK_EQUAL(EncodeDestination(*dest), V::DERIVATION[i].address_test);
        BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(*dest)), V::DERIVATION[i].scriptPubKey);
        // and the wallet can sign for it
        Spend s = MakeSpend(*dest);
        std::map<int, bilingual_str> errors;
        BOOST_REQUIRE(m_wallet.SignTransaction(s.tx, s.coins, SIGHASH_ALL, errors));
        BOOST_CHECK(VerifySpend(s, PQ_FLAGS));
    }
    std::string prv;
    BOOST_REQUIRE(spkm->GetDescriptorString(prv, /*priv=*/true));
    BOOST_CHECK_EQUAL(prv.substr(0, prv.find('#')), desc_str);
}

BOOST_AUTO_TEST_CASE(pq_wallet_psbt)
{
    LOCK(m_wallet.cs_wallet);
    SetupDescriptorWallet();
    const CTxDestination dest = NewPQDestination();
    Spend s = MakeSpend(dest);

    auto make_psbt = [&]() {
        PartiallySignedTransaction psbtx{s.tx};
        psbtx.inputs[0].non_witness_utxo = MakeTransactionRef(s.prev);
        return psbtx;
    };

    // Unfinalized: the ML-DSA-44 signature and key blob travel in the "blz" proprietary fields.
    PartiallySignedTransaction psbtx = make_psbt();
    bool complete{false};
    BOOST_REQUIRE(!m_wallet.FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false));
    BOOST_CHECK(psbtx.inputs[0].final_script_sig.empty());
    BOOST_REQUIRE_EQUAL(psbtx.inputs[0].m_proprietary.size(), 2U);
    for (const auto& prop : psbtx.inputs[0].m_proprietary) {
        BOOST_CHECK(prop.identifier == PSBT_BLZ_IDENTIFIER);
        if (prop.subtype == PSBT_BLZ_PQ_SIG) BOOST_CHECK_EQUAL(prop.value.size(), pq::PQ_MLDSA44_SIG_SIZE);
        else if (prop.subtype == PSBT_BLZ_PQ_KEYBLOB) BOOST_CHECK_EQUAL(prop.value.size(), pq::PQ_MLDSA44_KEYBLOB_SIZE);
        else BOOST_FAIL("unexpected proprietary subtype");
    }
    // Serialization round trip keeps them (and they survive Merge).
    DataStream ss;
    ss << psbtx;
    PartiallySignedTransaction back;
    ss >> back;
    BOOST_CHECK(back.inputs[0].m_proprietary == psbtx.inputs[0].m_proprietary);
    PartiallySignedTransaction merged = make_psbt();
    BOOST_REQUIRE(merged.Merge(back));
    BOOST_CHECK_EQUAL(merged.inputs[0].m_proprietary.size(), 2U);

    // A key-less finalizer assembles the scriptSig from the fields.
    BOOST_REQUIRE(FinalizePSBT(merged));
    BOOST_CHECK(merged.inputs[0].m_proprietary.empty());
    BOOST_CHECK_EQUAL(merged.inputs[0].final_script_sig.size(), PQ_SCRIPTSIG_SIZE);
    CMutableTransaction extracted;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(merged, extracted));
    Spend done = s;
    done.tx = extracted;
    BOOST_CHECK(VerifySpend(done, PQ_FLAGS));

    // Finalized in one go by the wallet.
    PartiallySignedTransaction direct = make_psbt();
    BOOST_REQUIRE(!m_wallet.FillPSBT(direct, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/true));
    BOOST_CHECK(complete);
    BOOST_CHECK_EQUAL(direct.inputs[0].final_script_sig.size(), PQ_SCRIPTSIG_SIZE);
    BOOST_CHECK(direct.inputs[0].m_proprietary.empty());

    // sign=false leaves the input untouched (no secret, nothing to carry) but reports it as signable.
    PartiallySignedTransaction dry = make_psbt();
    BOOST_REQUIRE(!m_wallet.FillPSBT(dry, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/true));
    BOOST_CHECK(dry.inputs[0].final_script_sig.empty());
    BOOST_CHECK(dry.inputs[0].m_proprietary.empty());
}

BOOST_AUTO_TEST_CASE(pq_wallet_message_signing)
{
    LOCK(m_wallet.cs_wallet);
    SetupDescriptorWallet();
    const CTxDestination dest = NewPQDestination();
    const CTxDestination other = NewPQDestination();
    const std::string addr = EncodeDestination(dest);
    const std::string message = "Blazecoin post-quantum message";

    std::string sig;
    BOOST_REQUIRE(m_wallet.SignMessagePQ(message, std::get<PQKeyHash>(dest), sig) == SigningResult::OK);
    const auto bytes = DecodeBase64(sig);
    BOOST_REQUIRE(bytes);
    BOOST_CHECK_EQUAL(bytes->size(), pq::PQ_MLDSA44_KEYBLOB_SIZE + pq::PQ_MLDSA44_SIG_SIZE);
    BOOST_CHECK(MessageVerify(addr, sig, message) == MessageVerificationResult::OK);
    BOOST_CHECK(MessageVerify(addr, sig, message + "!") == MessageVerificationResult::ERR_NOT_SIGNED);
    BOOST_CHECK(MessageVerify(EncodeDestination(other), sig, message) == MessageVerificationResult::ERR_NOT_SIGNED);
    BOOST_CHECK(MessageVerify(addr, sig.substr(0, sig.size() - 8), message) == MessageVerificationResult::ERR_MALFORMED_SIGNATURE);

    // An address the wallet does not own cannot be signed for.
    BOOST_CHECK(m_wallet.SignMessagePQ(message, PQKeyHash(uint256::ONE), sig) == SigningResult::PRIVATE_KEY_NOT_AVAILABLE);
}

BOOST_AUTO_TEST_CASE(pq_wallet_refuses_pq_outputs_before_activation)
{
    // Regtest never activates DEPLOYMENT_PQSIG unless -testactivationheight says so (PQ_SIGNATURES.md s7).
    LOCK(m_wallet.cs_wallet);
    SetupDescriptorWallet();
    BOOST_CHECK(!m_wallet.IsPQSigActiveForNextBlock());
    const CTxDestination dest = NewPQDestination();

    CCoinControl coin_control;
    const auto res = CreateTransaction(m_wallet, {CRecipient{dest, COIN, false}}, std::nullopt, coin_control);
    BOOST_REQUIRE(!res);
    const std::string err = util::ErrorString(res).original;
    BOOST_CHECK_MESSAGE(err.find("post-quantum outputs are not standard until block") != std::string::npos, err);

    // ... and pq change is refused the same way.
    coin_control.m_change_type = OutputType::PQ;
    const auto res2 = CreateTransaction(m_wallet, {CRecipient{PKHash(uint160{}), COIN, false}}, std::nullopt, coin_control);
    BOOST_REQUIRE(!res2);
    BOOST_CHECK_MESSAGE(util::ErrorString(res2).original.find("change type pq") != std::string::npos, util::ErrorString(res2).original);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
