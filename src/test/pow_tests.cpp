// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Blazecoin: the four get_next_work* cases below are DISABLED — they use upstream
 * Bitcoin block values and params (nBits 0x1d00ffff, 14-day/10-min timespan) that
 * don't match Blazecoin (nPowTargetTimespan=3600s, spacing 30s, two-era retarget).
 * Replaced by blazecoin_diff_two_era_switch + blazecoin_permitted_transition_matches_calc. */
BOOST_AUTO_TEST_CASE(get_next_work, *boost::unit_test::disabled())
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    unsigned int expected_nbits = 0x1d00d86aU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit, *boost::unit_test::disabled()) // Blazecoin: Bitcoin-valued, see note above
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1d00ffff;
    unsigned int expected_nbits = 0x1d00ffffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual, *boost::unit_test::disabled()) // Blazecoin: Bitcoin-valued, see note above
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits-1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual, *boost::unit_test::disabled()) // Blazecoin: Bitcoin-valued, see note above
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits+1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max{UintToArith256(uint256{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"})};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

/* Blazecoin: pin the Scrypt PoW hash vs SHA256d identity-hash distinction.
 * Every PoW call site passes CBlockHeader::GetPoWHash() (Scrypt), never GetHash()
 * (identity); the two are different functions and must not be conflated (see the
 * CONTRACT note on CheckProofOfWork). If GetPoWHash() were ever made to alias
 * GetHash(), or the genesis Scrypt PoW changed, this test fails. */
BOOST_AUTO_TEST_CASE(scrypt_pow_distinct_from_identity)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const CBlock& genesis = chainParams->GenesisBlock();
    const auto consensus = chainParams->GetConsensus();

    // Exact Scrypt PoW hash of the mainnet genesis header — pins the PoW output
    // byte-for-byte so any change to the Scrypt implementation (e.g. the HMAC /
    // PBKDF2 internals) that alters the result is caught immediately. This value
    // is consensus-critical and must never change.
    BOOST_CHECK_EQUAL(genesis.GetPoWHash().GetHex(),
                      "00000d7fde6d8163e09be89f8502a4ebf3603aedd83b2cbf5ac4aef640bf1f5f");

    // Scrypt PoW hash and SHA256d identity hash are different algorithms.
    BOOST_CHECK(genesis.GetPoWHash() != genesis.GetHash());

    // Mainnet genesis satisfies its own target under the Scrypt PoW hash — the
    // real consensus contract CheckProofOfWork enforces (and would fail if the
    // identity hash were substituted).
    BOOST_CHECK(CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, consensus));
}

/* Blazecoin two-era difficulty: an over-long actual timespan lets difficulty drop, but
 * Era 2 (height >= nDiffChangeTarget) clamps the drop to +-10% vs Era 1's +-400%. The same
 * too-slow scenario therefore yields a TIGHTER (smaller) new target in Era 2 than Era 1.
 * Capture-free: compares the two outputs rather than pinning an exact nBits. */
BOOST_AUTO_TEST_CASE(blazecoin_diff_two_era_switch)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const uint32_t startBits = 0x1c00ffffU; // well below powLimit so the *4 upper clamp doesn't cap

    auto resultAt = [&](int height) {
        CBlockIndex last;
        last.nHeight = height - 1;          // CalculateNextWorkRequired derives the era from nHeight+1
        last.nTime   = 2000000;
        last.nBits   = startBits;
        int64_t firstBlockTime = last.nTime - consensus.nPowTargetTimespan * 10; // far over target -> upper clamp
        return CalculateNextWorkRequired(&last, firstBlockTime, consensus);
    };

    const unsigned int era1 = resultAt(consensus.nDiffChangeTarget - 1); // nHeight+1 < target -> Era 1
    const unsigned int era2 = resultAt(consensus.nDiffChangeTarget + 1); // nHeight+1 > target -> Era 2

    arith_uint256 t0; t0.SetCompact(startBits);
    arith_uint256 t1; t1.SetCompact(era1);
    arith_uint256 t2; t2.SetCompact(era2);
    BOOST_CHECK(t2 < t1);   // Era 2's +-10% cap keeps the target far below Era 1's +-400% growth
    BOOST_CHECK(t1 >= t0);  // difficulty dropped (target grew) in both eras
    BOOST_CHECK(t2 >= t0);
}

/* Blazecoin: PermittedDifficultyTransition must accept exactly what CalculateNextWorkRequired
 * produces, in BOTH eras — this guards the shared GetRetargetTimespanBounds helper the two
 * functions use (SOLID audit #2). An obviously-too-easy target (powLimit) is rejected. */
BOOST_AUTO_TEST_CASE(blazecoin_permitted_transition_matches_calc)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const int interval = (int)consensus.DifficultyAdjustmentInterval();
    const unsigned int tooEasy = UintToArith256(consensus.powLimit).GetCompact();

    auto checkEra = [&](int height) {
        BOOST_REQUIRE_EQUAL(height % interval, 0); // transition bounds are only checked on a boundary
        CBlockIndex last;
        last.nHeight = height - 1;
        last.nTime   = 2000000;
        last.nBits   = 0x1c00ffffU;
        int64_t firstBlockTime = last.nTime - consensus.nPowTargetTimespan * 10; // upper clamp
        unsigned int newBits = CalculateNextWorkRequired(&last, firstBlockTime, consensus);
        BOOST_CHECK(PermittedDifficultyTransition(consensus, height, last.nBits, newBits));
        BOOST_CHECK(!PermittedDifficultyTransition(consensus, height, last.nBits, tooEasy));
    };

    checkEra(((consensus.nDiffChangeTarget / interval) - 1) * interval); // Era 1 boundary (< target)
    checkEra(( consensus.nDiffChangeTarget / interval)      * interval); // Era 2 boundary (>= target)
}

/* Blazecoin Era 3 — Phoenix-413 (PHOENIX_413.md). The pure target function must
 * be bit-exact against every canonical vector generated by
 * test/phoenix413/generate_phoenix_vectors.py (the same file pins the V1.5.2
 * client and the lite-wallet C# verifier). */
#include <test/phoenix413_vector_data.h>
#include <tinyformat.h>
BOOST_AUTO_TEST_CASE(phoenix413_canonical_vectors)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_REQUIRE_EQUAL(consensus.nPowTargetSpacing, 30); // vectors assume T=30
    for (unsigned int i = 0; i < PHOENIX413_VECTOR_COUNT; i++) {
        const Phoenix413Vector& v = PHOENIX413_VECTORS[i];
        const unsigned int got = CalculatePhoenix413Target(
            v.anchor_bits, v.anchor_parent_time, v.anchor_height,
            v.eval_height, v.parent_time, consensus.nPowTargetSpacing,
            consensus.powLimit);
        BOOST_CHECK_MESSAGE(got == v.expect_bits,
            strprintf("vector %s: expected %08x got %08x", v.name, v.expect_bits, got));
    }
}

/* Blazecoin Era 3 — the GetNextWorkRequired dispatch: below/at H_A the old rule
 * answers, above it the Phoenix anchor (block H_A + its parent's time) drives
 * the per-block target, and PermittedDifficultyTransition stops constraining. */
BOOST_AUTO_TEST_CASE(phoenix413_dispatch)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const int H_A = 1200; // one full old-rule retarget interval past genesis
    consensus.phoenix413Height = H_A;

    std::vector<CBlockIndex> blocks(H_A + 3);
    for (int i = 0; i < (int)blocks.size(); i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1600000000 + i * consensus.nPowTargetSpacing;
        blocks[i].nBits = 0x1d00ffffU;
    }

    CBlockHeader header;

    // At height H_A (nHeight+1 == H_A) the old rule still answers: not on a
    // retarget boundary, so the target is simply carried forward.
    header.nTime = blocks[H_A - 1].nTime + consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[H_A - 1], &header, consensus), 0x1d00ffffU);

    // Above H_A, Phoenix answers, and matches the pure function fed with the
    // anchor exactly as specified (block H_A's nBits, its parent's timestamp).
    for (int eval = H_A + 1; eval <= H_A + 2; eval++) {
        const CBlockIndex* last = &blocks[eval - 1];
        header.nTime = last->nTime + consensus.nPowTargetSpacing;
        const unsigned int expect = CalculatePhoenix413Target(
            blocks[H_A].nBits, blocks[H_A - 1].GetBlockTime(), H_A,
            eval, last->GetBlockTime(), consensus.nPowTargetSpacing, consensus.powLimit);
        BOOST_CHECK_EQUAL(GetNextWorkRequired(last, &header, consensus), expect);
    }

    // The anti-DoS transition pre-check accepts any per-block movement post-H_A...
    BOOST_CHECK(PermittedDifficultyTransition(consensus, H_A + 1, 0x1d00ffffU, 0x1c80ff7fU));
    // ...while at/below H_A the old off-boundary rule (bits must not change) holds.
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, H_A - 1, 0x1d00ffffU, 0x1c80ff7fU));
}

BOOST_AUTO_TEST_SUITE_END()
