// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <vector>

#include <boost/test/unit_test.hpp>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Search for a nonce to meet (regtest) proof of work */
    void FindProofOfWork(CBlockHeader& starting_header);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, const int nVersion, int prev_time,
            const uint256& merkle_root, const uint32_t nBits);
};

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header)
{
    while (!CheckProofOfWork(starting_header.GetPoWHash(), starting_header.nBits, Params().GetConsensus())) {
        ++(starting_header.nNonce);
    }
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        FindProofOfWork(next_header);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    const int target_blocks = 15000;
    arith_uint256 chain_work = target_blocks*2;

    // Generate headers for two different chains (using differing merkle roots
    // to ensure the headers are different).
    GenerateHeaders(first_chain, target_blocks-1, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(1), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the proof-of-work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success); // foiled!
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK(result.pow_validated_headers.size() == first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

// Blazecoin: above the Phoenix-413 activation height the target of every header
// is fixed by the anchor, the height and the previous header's time, and both
// phases check it exactly (bug-bounty round 17: PermittedDifficultyTransition
// passes everything there, so the presync had no difficulty bound at all).
// HeadersSyncState does not check proof of work itself (its caller does), so
// the headers here are not mined.
BOOST_AUTO_TEST_CASE(headers_sync_phoenix413_target)
{
    Consensus::Params consensus = Params().GetConsensus();
    const int H_A = 5;
    consensus.phoenix413Height = H_A;

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    const CBlockHeader genesis = Params().GenesisBlock().GetBlockHeader();

    // Blocks arrive one second apart (faster than the target spacing), so the
    // Phoenix target moves away from the anchor's.
    const int count = 60;
    std::vector<CBlockHeader> chain;
    uint256 prev_hash = genesis.GetHash();
    int64_t prev_time = genesis.GetBlockTime();
    int64_t anchor_parent_time = 0;
    for (int height = 1; height <= count; height++) {
        CBlockHeader h;
        h.nVersion = genesis.nVersion;
        h.hashPrevBlock = prev_hash;
        h.hashMerkleRoot = ArithToUint256(height);
        h.nTime = prev_time + 1;
        if (height == H_A) anchor_parent_time = prev_time;
        h.nBits = height <= H_A ? genesis.nBits :
            CalculatePhoenix413Target(genesis.nBits, anchor_parent_time, H_A, height, prev_time,
                                      consensus.nPowTargetSpacing, consensus.powLimit);
        chain.push_back(h);
        prev_hash = h.GetHash();
        prev_time = h.GetBlockTime();
    }
    // The rule really asks for something else than the anchor's target up here.
    BOOST_REQUIRE(chain.back().nBits != genesis.nBits);

    // The same chain with one header above H_A kept at the easy anchor target
    // (later headers no longer connect, which does not matter: it fails first).
    const int bad_index = 40;
    std::vector<CBlockHeader> bad_chain = chain;
    BOOST_REQUIRE(bad_chain[bad_index].nBits != genesis.nBits);
    bad_chain[bad_index].nBits = genesis.nBits;

    const arith_uint256 unreachable_work = chain_start->nChainWork + arith_uint256{1} * 1000000;
    arith_uint256 reachable_work = chain_start->nChainWork;
    for (int i = 0; i < count - 5; i++) reachable_work += GetBlockProof(CBlockIndex(chain[i]));

    // PRESYNC: the right chain is accepted...
    HeadersSyncState good_presync(0, consensus, chain_start, unreachable_work);
    auto result = good_presync.ProcessNextHeaders(chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(good_presync.GetState() == HeadersSyncState::State::PRESYNC);
    BOOST_CHECK_EQUAL(good_presync.GetPresyncHeight(), count);

    // ...and the wrong target ends the sync at that header.
    HeadersSyncState bad_presync(0, consensus, chain_start, unreachable_work);
    result = bad_presync.ProcessNextHeaders(bad_chain, true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(bad_presync.GetState() == HeadersSyncState::State::FINAL);

    // The header AT the activation height is the anchor: the old rule, not Phoenix.
    HeadersSyncState anchor_only(0, consensus, chain_start, unreachable_work);
    result = anchor_only.ProcessNextHeaders({chain.begin(), chain.begin() + H_A}, true);
    BOOST_CHECK(result.success);

    // REDOWNLOAD: the right chain twice is released in full...
    HeadersSyncState good_redownload(0, consensus, chain_start, reachable_work);
    result = good_redownload.ProcessNextHeaders(chain, true);
    BOOST_CHECK(result.success);
    BOOST_REQUIRE(good_redownload.GetState() == HeadersSyncState::State::REDOWNLOAD);
    result = good_redownload.ProcessNextHeaders(chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK_EQUAL(result.pow_validated_headers.size(), chain.size());

    // ...and a wrong target in the second pass is refused there too.
    HeadersSyncState bad_redownload(0, consensus, chain_start, reachable_work);
    result = bad_redownload.ProcessNextHeaders(chain, true);
    BOOST_REQUIRE(bad_redownload.GetState() == HeadersSyncState::State::REDOWNLOAD);
    result = bad_redownload.ProcessNextHeaders(bad_chain, true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(bad_redownload.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_SUITE_END()
