// Copyright (c) 2026 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/** ML-DSA-44 against NIST's FIPS 204 known-answer vectors (ACVP-Server gen-val, parameter set ML-DSA-44).
 *
 *  Authority: test/pqsig/mldsa44_acvp_vectors.json (selected from NIST's files by test/pqsig/import_acvp_mldsa44.py)
 *  -> src/test/mldsa44_acvp_data.h (test/pqsig/gen_mldsa44_acvp_header.py). This pins the vendored reference code
 *  AND the mldsa44:: wrapper to the standard: key generation from a seed, deterministic and hedged signing under the
 *  external (pure, with context) and internal interfaces, and verification including NIST's "modified" cases, each
 *  of which must fail for the stated reason. pqsig_tests.cpp covers the chain's use of the primitive; this file
 *  covers the primitive itself. */

#include <crypto/mldsa44.h>
#include <test/mldsa44_acvp_data.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include <crypto/mldsa/params.h>
#include <crypto/mldsa/sign.h>
}

namespace V = mldsa44_acvp;

namespace {

std::vector<unsigned char> H(const char* hex) { return ParseHex(hex); }

/** FIPS 204 s5.2 step 10 / s5.3 step 5: M' = 0x00 || len(ctx) || ctx || M. The external interface's prefix. */
std::vector<unsigned char> ExternalPrefix(const std::vector<unsigned char>& ctx)
{
    std::vector<unsigned char> pre;
    pre.push_back(0x00);
    pre.push_back(static_cast<unsigned char>(ctx.size()));
    pre.insert(pre.end(), ctx.begin(), ctx.end());
    return pre;
}

std::string Where(uint32_t tgId, uint32_t tcId) { return "tgId " + std::to_string(tgId) + " tcId " + std::to_string(tcId); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(mldsa44_kat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mldsa44_kat_keygen)
{
    BOOST_REQUIRE(V::KEYGEN_COUNT > 0);
    for (size_t i = 0; i < V::KEYGEN_COUNT; ++i) {
        const auto& t = V::KEYGEN[i];
        std::vector<unsigned char> pk, sk;
        BOOST_REQUIRE_MESSAGE(mldsa44::KeyGenFromSeed(H(t.seed), pk, sk), Where(t.tgId, t.tcId));
        BOOST_CHECK_MESSAGE(pk == H(t.pk), "pk mismatch at " << Where(t.tgId, t.tcId));
        BOOST_CHECK_MESSAGE(sk == H(t.sk), "sk mismatch at " << Where(t.tgId, t.tcId));
    }
}

BOOST_AUTO_TEST_CASE(mldsa44_kat_siggen)
{
    BOOST_REQUIRE(V::SIGGEN_COUNT > 0);
    size_t external_det{0}, external_hedged{0}, internal_cases{0};
    for (size_t i = 0; i < V::SIGGEN_COUNT; ++i) {
        const auto& t = V::SIGGEN[i];
        const auto msg{H(t.message)}, ctx{H(t.context)}, sk{H(t.sk)}, pk{H(t.pk)}, expected{H(t.signature)};
        const std::string where{Where(t.tgId, t.tcId)};
        BOOST_REQUIRE_EQUAL(expected.size(), mldsa44::SIG_SIZE);

        if (!t.internal && t.deterministic) {
            // The wrapper the chain uses: deterministic, external interface, with context.
            std::vector<unsigned char> sig;
            BOOST_REQUIRE_MESSAGE(mldsa44::Sign(sk, msg, ctx, sig), where);
            BOOST_CHECK_MESSAGE(sig == expected, "deterministic signature mismatch at " << where);
            BOOST_CHECK_MESSAGE(mldsa44::Verify(pk, msg, ctx, sig), "own signature does not verify at " << where);
            ++external_det;
            continue;
        }

        // Hedged cases carry NIST's rnd; the internal interface has no prefix at all. Both go through the
        // reference code's internal entry point, the only place rnd can be supplied.
        unsigned char rnd[RNDBYTES]{};
        if (t.rnd != nullptr) {
            const auto r{H(t.rnd)};
            BOOST_REQUIRE_EQUAL(r.size(), sizeof(rnd));
            std::memcpy(rnd, r.data(), sizeof(rnd));
        }
        const std::vector<unsigned char> pre{t.internal ? std::vector<unsigned char>{} : ExternalPrefix(ctx)};
        std::vector<unsigned char> sig(mldsa44::SIG_SIZE);
        size_t siglen{0};
        BOOST_REQUIRE_EQUAL(crypto_sign_signature_internal(sig.data(), &siglen, msg.data(), msg.size(),
                                                           pre.empty() ? nullptr : pre.data(), pre.size(), rnd, sk.data()), 0);
        BOOST_REQUIRE_EQUAL(siglen, mldsa44::SIG_SIZE);
        BOOST_CHECK_MESSAGE(sig == expected, (t.internal ? "internal" : "hedged external") << " signature mismatch at " << where);
        if (t.internal) {
            BOOST_CHECK_EQUAL(crypto_sign_verify_internal(sig.data(), sig.size(), msg.data(), msg.size(), nullptr, 0, pk.data()), 0);
            ++internal_cases;
        } else {
            BOOST_CHECK_MESSAGE(mldsa44::Verify(pk, msg, ctx, sig), "hedged signature does not verify at " << where);
            ++external_hedged;
        }
    }
    // The import keeps every kind; a selection that silently dropped one would weaken the claim.
    BOOST_CHECK(external_det > 0);
    BOOST_CHECK(external_hedged > 0);
    BOOST_CHECK(internal_cases > 0);
}

BOOST_AUTO_TEST_CASE(mldsa44_kat_sigver)
{
    BOOST_REQUIRE(V::SIGVER_COUNT > 0);
    size_t should_pass{0}, should_fail{0};
    for (size_t i = 0; i < V::SIGVER_COUNT; ++i) {
        const auto& t = V::SIGVER[i];
        const auto msg{H(t.message)}, ctx{H(t.context)}, pk{H(t.pk)}, sig{H(t.signature)};
        const std::string where{Where(t.tgId, t.tcId) + " (" + t.reason + ")"};
        bool ok;
        if (t.internal) {
            ok = crypto_sign_verify_internal(sig.data(), sig.size(), msg.data(), msg.size(), nullptr, 0, pk.data()) == 0;
        } else {
            ok = mldsa44::Verify(pk, msg, ctx, sig);
        }
        BOOST_CHECK_MESSAGE(ok == t.testPassed, "verify returned " << ok << ", NIST says " << t.testPassed << " at " << where);
        (t.testPassed ? should_pass : should_fail)++;
    }
    BOOST_CHECK(should_pass > 0);
    BOOST_CHECK(should_fail > 0);
}

BOOST_AUTO_TEST_CASE(mldsa44_wrapper_rejects_bad_sizes_without_throwing)
{
    const auto& t = V::KEYGEN[0];
    std::vector<unsigned char> pk, sk, sig;
    BOOST_REQUIRE(mldsa44::KeyGenFromSeed(H(t.seed), pk, sk));
    const std::vector<unsigned char> msg{1, 2, 3};
    const std::vector<unsigned char> ctx{'x'};
    BOOST_REQUIRE(mldsa44::Sign(sk, msg, ctx, sig));

    std::vector<unsigned char> short_seed(31, 0), long_ctx(mldsa44::MAX_CTX_SIZE + 1, 0);
    std::vector<unsigned char> pk2, sk2, sig2;
    BOOST_CHECK(!mldsa44::KeyGenFromSeed(short_seed, pk2, sk2));
    BOOST_CHECK(!mldsa44::Sign(sk, msg, long_ctx, sig2));
    BOOST_CHECK(!mldsa44::Sign(std::vector<unsigned char>(sk.begin(), sk.end() - 1), msg, ctx, sig2));
    BOOST_CHECK(!mldsa44::Verify(pk, msg, long_ctx, sig));
    BOOST_CHECK(!mldsa44::Verify(std::vector<unsigned char>(pk.begin(), pk.end() - 1), msg, ctx, sig));
    BOOST_CHECK(!mldsa44::Verify(pk, msg, ctx, std::vector<unsigned char>(sig.begin(), sig.end() - 1)));
    BOOST_CHECK(!mldsa44::Verify(pk, msg, std::vector<unsigned char>{'y'}, sig));   // another context: different M'
    BOOST_CHECK(mldsa44::Verify(pk, msg, ctx, sig));
}

BOOST_AUTO_TEST_SUITE_END()
