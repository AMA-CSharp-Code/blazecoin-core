// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// A fix may be on the way:
// https://developercommunity.visualstudio.com/t/consteval-conversion-function-fails/1579014
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=5d871c1b6ea5, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=76dac1, nTime=1400442576, nBits=1e0ffff0, nNonce=595109, vtx=1)
 *   CTransaction(hash=76dac1, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c55486177616969616e2053757266696e67204d6f64656c2043686172676564205769746820417474656d70746564204d757264657220696e20416c6c6567656420526f616420526167652048697420616e642052756e)
 *     CTxOut(nValue=50.00000000, scriptPubKey=040184710fa689ad502369)
 *   vMerkleTree: 76dac1
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Hawaiian Surfing Model Charged With Attempted Murder in Alleged Road Rage Hit and Run";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 1051200; // Blazecoin: ~1 year at 30s blocks
        consensus.nDiffChangeTarget = 600000; // Blazecoin: height at which difficulty adjustment changed to ±10%
        consensus.script_flag_exceptions.clear();
        // Buried deployments below the Blazecoin chain start (height 0, 2014)
        // predate every BIP listed here, and the network never adopted them.
        // BLAZECOIN_BIP_NEVER_ACTIVE marks them as permanently inactive — this
        // is legacy-consensus compatibility, not a pending activation.
        consensus.BIP34Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.BIP66Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.CSVHeight = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.SegwitHeight = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}; // Blazecoin: ~uint256(0) >> 20
        // Phoenix-413 H_A — CHOSEN 2026-08-26 by the operator (PHOENIX_413.md).
        // Tip was 4,193,990 with mining deliberately stopped; 4,194,000 is the
        // next Era-2 retarget boundary (divisible by 120) and becomes the
        // anchor block. Blocks > H_A use the per-block ASERT rule. Mining
        // resumes only after every implementation (V2, V1.5.2, lite heads)
        // ships this height.
        consensus.phoenix413Height = 4194000;
        // P2PQH (post-quantum output type) hard fork: H_Q chosen by the operator 2026-09-15
        // (PQ_SIGNATURES.md s7, s15). Blocks at height >= 4,250,000 validate with SCRIPT_VERIFY_PQSIG.
        consensus.pqsigHeight = 4250000;
        consensus.nPowTargetTimespan = 60 * 60; // Blazecoin: 1 hour
        consensus.nPowTargetSpacing = 30; // Blazecoin: 30 seconds
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 90; // 75% of 120
        consensus.nMinerConfirmationWindow = 120; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342) - Not active yet, old chain doesn't have it
        // TODO: Activate via soft fork at a future block height (Phase 2)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // ~50% of approximate cumulative chain work at block 3,500,000.
        // Derived from BlazeIndexer: SUM(Difficulty) over heights 0..3,500,000 = 26,749,779.86;
        // work_per_block ≈ 2^256/(max_target+1) ≈ 2^20 × difficulty for Blazecoin's powLimit.
        // Chains weaker than this floor are rejected during header sync.
        // Exact chainwork of the assumeValid anchor below (getblockheader .chainwork,
        // harvested 2026-08-10 from the production Indexer node) — any valid chain a
        // peer offers must carry at least this much work.
        consensus.nMinimumChainWork = uint256{"00000000000000000000000000000000000000000000000001a0938b90463890"};
        // Block 4,168,925 — tip-200 on the production chain, harvested 2026-08-10 from
        // the operator's synced Indexer node (refresh cadence: every daemon release).
        // Descends from the hardcoded 4M checkpoint. Skips signature verification for
        // blocks deemed valid up to this point; PoW is still checked.
        consensus.defaultAssumeValid = uint256{"eb32b2064b7343dd12bcd1151f3a89d0be4dc78a53358f6a60a7bfe5ac3b8164"};

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfb; // Blazecoin magic bytes
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        nDefaultPort = 55414; // Blazecoin P2P port
        nPruneAfterHeight = 100000;
        // Measured 2026-05-04 against fully-synced V1.5 datadir at chain tip ~4.1M:
        // blocks/ = 2.52 GB, chainstate/ = 128 MB. Sized with a small forward margin.
        // Chainstate is much smaller in Core 28 than the V1.5/0.8.6 era (~12 MB
        // measured at tip 4.1M on 2026-05-10), so the GB-rounded hint is 0.
        m_assumed_blockchain_size = 3;  // GB
        m_assumed_chain_state_size = 0; // GB (actual ~12 MB; rounds to 0)

        genesis = CreateGenesisBlock(1400442576, 595109, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"5d871c1b6ea542c2bb8a3b3ac70028a591bbf81369e90c2446c1a2bbfb89459b"});
        assert(genesis.hashMerkleRoot == uint256{"76dac14606eb13388518e7581062b3d4aec84feb58d015a83c532bc5349618b8"});

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        // Blazecoin seed nodes — DNS hostname first so the DNS-seed thread can return
        // a fresh peer list. The raw IPs are operator-known fallbacks if DNS is unreachable:
        // the two 2014 foundation nodes plus the two operator relay VPSes (Strasbourg + Beauharnois),
        // added after the July 2026 outage took both foundation nodes down together.
        vSeeds.emplace_back("blazecoin.co.uk");
        vSeeds.emplace_back("85.15.179.171");
        vSeeds.emplace_back("91.206.16.214");
        vSeeds.emplace_back("51.210.47.141");
        vSeeds.emplace_back("54.39.23.245");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,26); // Blazecoin: addresses start with 'B'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,154); // 128 + 26
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        base58Prefixes[PQ_ADDRESS] =     {0x46, 0x50}; // Blazecoin P2PQH: "BQ..." (52 chars), PQ_SIGNATURES.md s5

        bech32_hrp = "blz"; // Blazecoin bech32 prefix

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // Production-validated against V1.5 sync to chain tip; matches the
        // running 0.8.6.2 mainnet at every height listed. Source:
        // Blazecoin_Core_V1.5/Blazecoin_V1.5_Checkpoints.txt (2026-04-23).
        checkpointData = {
            {
                {      0, uint256{"5d871c1b6ea542c2bb8a3b3ac70028a591bbf81369e90c2446c1a2bbfb89459b"}},
                {      1, uint256{"50f5ef3a2b2637c92907e9d444e6a58f925cb61eaac7b23f46263f2e7d9245c0"}},
                {  18500, uint256{"6cfc4decf7c26c037c621190681f9b3f12912f8330b06c652e0c193340a23347"}},
                {  33000, uint256{"cfd0eb628a7fee82accc4e2f183cdd1abd08afeedf2b1b030230836a4e74629e"}},
                {  60413, uint256{"99ea9310aac366b03161254d77ada05c9eb1392ca8ca370885b013f80d41f56e"}},
                { 124650, uint256{"0d8aa2452b7f2702a9a07a4cb36ad1edd12503014ba46da46992c9dba898dec2"}},
                { 215000, uint256{"7e960cd973982501d2339906c3c7bf81c2e0c0a0a02192198263ae51f024e991"}},
                { 363120, uint256{"40c6d6d81494d53781af0fc9d7aff91a2f3a13e38100b20c3ac819f944ecf9f4"}},
                { 500000, uint256{"9b6f14f13f0ee345eb03aa2742630480d7e2f7c3ce46e4c34ecbb23d2d871f6c"}},
                {1000000, uint256{"2f1c4d32c87f0e77a63fc4cb902223307cf3b3c867818fa45f1bc7fef60d2686"}},
                {1500000, uint256{"44a971426d30eb1446086b1319979edcf73536897efb04505782da3760be4809"}},
                {2000000, uint256{"4ceca77d22d672d391670224ca2f9457209bc1ecf5f5eaf5e9d652b81656995b"}},
                {2500000, uint256{"a6c937fcf01c04eb3aa7a8e06c80acb80e6843acd268fb6d520c5dad6194e7db"}},
                {3000000, uint256{"1af43523e055656cae5e3b6894d4484b968c25ddf7adbd758e5908e45e38fdf0"}},
                {3500000, uint256{"f637143b959c511cd0e4d3df7859181f1e5633ca2460f270eb02d4903846e04f"}},
                {4000000, uint256{"959ec2a6d7d67cf4272bcb6508c68daa69a7c280123f26d001c47387186fc1fd"}},
                // Phoenix-413 anchor (H_A, last Era-2 block, 2026-08-26) — pins the fork
                // crossing itself; also makes the anchor lookup reorg-proof everywhere.
                {4194000, uint256{"add35fb660b3424e73ffccddee2ac84933b92b75e99f0fe874605b716f8a96a0"}},
            }
        };

        m_assumeutxo_data = {
            {}
        };

        chainTxData = ChainTxData{
            // Stats at the defaultAssumeValid anchor (block 4,168,925), harvested
            // 2026-08-10 via getchaintxstats on the production Indexer node
            // (1-year window for the rate). Refresh together with the anchor.
            .nTime    = 1786376563,    // 2026-08-10
            .tx_count = 4688313,
            .dTxRate  = 0.00637,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 1051200;
        consensus.nDiffChangeTarget = 600000;
        consensus.script_flag_exceptions.clear();
        // Buried deployments are permanently inactive on Blazecoin testnet for
        // the same reason as mainnet — see CMainParams. See params.h for the
        // BLAZECOIN_BIP_NEVER_ACTIVE rationale.
        consensus.BIP34Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.BIP66Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.CSVHeight = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.SegwitHeight = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.phoenix413Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE; // Phoenix-413 H_A not yet scheduled
        consensus.pqsigHeight = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE; // P2PQH H_Q not yet chosen (PQ_SIGNATURES.md s7)
        consensus.nPowTargetTimespan = 60 * 60; // Blazecoin: 1 hour
        consensus.nPowTargetSpacing = 30; // Blazecoin: 30 seconds
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 90; // 75% of 120
        consensus.nMinerConfirmationWindow = 120;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xed; // Blazecoin testnet magic bytes
        pchMessageStart[1] = 0xb2;
        pchMessageStart[2] = 0xa8;
        pchMessageStart[3] = 0xcd;
        nDefaultPort = 55424; // Blazecoin testnet port (55414 + 10)
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 0;

        // Genesis re-mined for scrypt PoW 2026-06-14. The original nonce 1292958 was a
        // SHA256d solution that does NOT satisfy Blazecoin's scrypt PoW, so -testnet failed
        // at genesis ("Errors in block header"). 2213444 is the lowest scrypt-valid nonce
        // ABOVE mainnet's 595109 — chosen >595109 so testnet's genesis stays distinct from
        // mainnet (which shares this header's timestamp/nBits/merkle root).
        genesis = CreateGenesisBlock(1400442576, 2213444, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"50397422820f31f87846edb3779e1f13023ced9bd322ce962102070a2a23ed06"});
        assert(genesis.hashMerkleRoot == uint256{"76dac14606eb13388518e7581062b3d4aec84feb58d015a83c532bc5349618b8"});

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[PQ_ADDRESS] =     {0xb2, 0x73}; // Blazecoin P2PQH: "TQ..." (52 chars), test networks

        bech32_hrp = "tblz"; // Blazecoin testnet bech32

        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {}
        };

        m_assumeutxo_data = {
            {}
        };

        chainTxData = ChainTxData{
            .nTime    = 1400442576,
            .tx_count = 0,
            .dTxRate  = 0,
        };
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 1051200; // Blazecoin: aligned to mainnet 2026-08-10 (was Bitcoin's 210000; D1 — never launched, consistency only)
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}; // Blazecoin scrypt diff-1, aligned to mainnet/testnet 2026-06-14 (was Bitcoin's SHA256d 0x1d00ffff limit)
        consensus.phoenix413Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE; // Phoenix-413 H_A not yet scheduled
        consensus.pqsigHeight = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE; // P2PQH H_Q not yet chosen (PQ_SIGNATURES.md s7)
        // Blazecoin: timespan/spacing aligned to mainnet/testnet (1h/30s) 2026-07-06. The
        // 2026-06-14 powLimit alignment above had left Bitcoin's two-week timespan in place,
        // which is UNSAFE with this powLimit: CalculateNextWorkRequired computes
        // target * nActualTimespan, and 2^236-ish powLimit * 4*(14 days) needs 259 bits —
        // a 256-bit overflow (caught by pow_tests/ChainParams_TESTNET4_sanity). The safe
        // bound for this powLimit is ~3 days; 1 hour matches every other Blazecoin chain.
        // No Blazecoin testnet4 network was ever launched, so nothing live is affected.
        consensus.nPowTargetTimespan = 60 * 60; // Blazecoin: 1 hour
        consensus.nPowTargetSpacing = 30; // Blazecoin: 30 seconds
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 90; // 75% of 120
        consensus.nMinerConfirmationWindow = 120; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{}; // reset 2026-06-14: testnet4 re-mined as a fresh Blazecoin scrypt chain (stale Bitcoin value would pin IBD on a chain that no longer exists)
        consensus.defaultAssumeValid = uint256{}; // reset 2026-06-14: no assumevalid checkpoint on the fresh scrypt chain

        pchMessageStart[0] = 0x1c;
        pchMessageStart[1] = 0x16;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x28;
        nDefaultPort = 48333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 0;

        const char* testnet4_genesis_msg = "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";
        const CScript testnet4_genesis_script = CScript() << ParseHex("000000000000000000000000000000000000000000000000000000000000000000") << OP_CHECKSIG;
        // Genesis re-mined for scrypt PoW 2026-06-14: testnet4 was inherited from Bitcoin
        // Core at SHA256d diff-1 (0x1d00ffff) and its genesis fails Blazecoin's scrypt PoW.
        // Re-targeted to Blazecoin's scrypt diff-1 (0x1e0ffff0, see powLimit above) and the
        // nonce re-mined. Timestamp / coinbase message / merkle root kept; hash pinned below.
        genesis = CreateGenesisBlock(testnet4_genesis_msg,
                testnet4_genesis_script,
                1714777860,
                2089102,
                0x1e0ffff0,
                1,
                50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"ebfa31ef324309ebc8f281eaa9f9af8cbf0a956f85a35b8630a500a54019c0d1"});
        assert(genesis.hashMerkleRoot == uint256S("0x7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // Blazecoin does not use testnet4 - no seeds configured

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[PQ_ADDRESS] =     {0xb2, 0x73}; // Blazecoin P2PQH: "TQ..." (52 chars), test networks

        bech32_hrp = "tb";

        vFixedSeeds.clear(); // Blazecoin does not use testnet4

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {},
            }
        };

        m_assumeutxo_data = {
            {}
        };

        chainTxData = ChainTxData{
            // Reset 2026-06-14: testnet4 re-mined as a fresh Blazecoin scrypt chain, so the
            // upstream Bitcoin testnet4 tx statistics no longer apply.
            .nTime    = 0,
            .tx_count = 0,
            .dTxRate  = 0,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!options.challenge) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            // Blazecoin does not use Bitcoin's signet - no default seeds

            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        // Blazecoin: economics/timing aligned to the other Blazecoin chains 2026-08-10
        // (D1 — was Bitcoin's 210000-halving / two-week / 10-min set; no Blazecoin
        // signet has ever launched, so this is consistency, not a live change. The
        // testnet4 overflow incident showed half-converted params eventually bite.)
        consensus.nSubsidyHalvingInterval = 1051200;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 3600; // 1 hour, matching every other Blazecoin chain
        consensus.nPowTargetSpacing = 30;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 90; // 75% of 120 (matches mainnet)
        consensus.nMinerConfirmationWindow = 120; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000377ae000000000000000000000000000000000000000000000000000000"};
        consensus.phoenix413Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE; // Phoenix-413 H_A not yet scheduled
        consensus.pqsigHeight = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE; // P2PQH H_Q not yet chosen (PQ_SIGNATURES.md s7)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 38333;
        nPruneAfterHeight = 1000;

        // Genesis re-mined for scrypt PoW 2026-06-14. The original nonce 52613770 was a
        // SHA256d solution that does NOT satisfy Blazecoin's scrypt PoW, so -signet failed
        // at genesis. 735441 is the lowest scrypt-valid nonce for this header (nBits
        // 0x1e0377ae); hash pinned below (distinct from mainnet).
        genesis = CreateGenesisBlock(1598918400, 735441, 0x1e0377ae, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"7391f5322e6d583cc9ddfa77ec27984abe56c8f3c95d9118cd8f0556cbd7b7bf"});
        assert(genesis.hashMerkleRoot == uint256{"76dac14606eb13388518e7581062b3d4aec84feb58d015a83c532bc5349618b8"});

        vFixedSeeds.clear();

        m_assumeutxo_data = {
            // Blazecoin does not use signet - no assumeutxo data
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[PQ_ADDRESS] =     {0xb2, 0x73}; // Blazecoin P2PQH: "TQ..." (52 chars), test networks

        bech32_hrp = "tb";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.phoenix413Height = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE; // Phoenix-413 H_A not yet scheduled (activate in tests via -testactivationheight=phoenix413@N)
        consensus.pqsigHeight = Consensus::BLAZECOIN_BIP_NEVER_ACTIVE; // P2PQH H_Q not yet chosen (activate in tests via -testactivationheight=pqsig@N)
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_PHOENIX413:
                consensus.phoenix413Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_PQSIG:
                consensus.pqsigHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        // Blazecoin: nonce re-mined for scrypt PoW. The original nonce=2 did NOT satisfy
        // the regtest scrypt target, so `-regtest` fatally failed at the genesis block
        // ("ReadBlockFromDisk: Errors in block header" -> "Failed to connect best block").
        // nonce=0 yields a scrypt hash within the regtest powLimit. Mainnet/testnet
        // genesis are unaffected (this is the REGTEST genesis only).
        genesis = CreateGenesisBlock(1296688602, 0, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"d062f3721f1261bf3542870d0399e67432554efb448bb6046a576128467a0062"});

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                // Regtest genesis hash differs from Bitcoin — checkpoint removed
            }
        };

        // Blazecoin: the Bitcoin-derived assumeUTXO snapshot triplets were removed (the
        // fork's different genesis means none of those serialized-UTXO hashes can match a
        // Blazecoin regtest chain) and REGENERATED 2026-07-06 for the Blazecoin chain.
        // This is the regtest anchor for the unit tests: upstream had entries at heights
        // 110/200 for its 100-block TestChain100Setup; this fork's fixture mines
        // COINBASE_MATURITY = 30 blocks and the snapshot tests mine +10, so the anchor is
        // height 40. Values come from the deterministic unit-test chain (dumptxoutset at
        // height 40) — see validation_chainstatemanager_tests. Test-only: regtest has no
        // real network, so nothing live depends on these. (feature_assumeutxo / fuzz
        // utxo_snapshot would still need their own heights generated from a live regtest
        // run if ever re-enabled.)
        m_assumeutxo_data = {
            {
                .height = 40,
                .hash_serialized = AssumeutxoHash{uint256{"cc203f0665156694692d5d0263729f8061663f7af561ecfc2dcaa8aae24ac68d"}},
                .m_chain_tx_count = 41,
                .blockhash = consteval_ctor(uint256{"0fc95a6a5b6f1bc232d615d7c30017eca5e9da7cd625028c43193ef7e13918b7"}),
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[PQ_ADDRESS] =     {0xb2, 0x73}; // Blazecoin P2PQH: "TQ..." (52 chars), test networks

        bech32_hrp = "bcrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::equal(message.begin(), message.end(), mainnet_msg.data())) {
        return ChainType::MAIN;
    } else if (std::equal(message.begin(), message.end(), testnet_msg.data())) {
        return ChainType::TESTNET;
    } else if (std::equal(message.begin(), message.end(), testnet4_msg.data())) {
        return ChainType::TESTNET4;
    } else if (std::equal(message.begin(), message.end(), regtest_msg.data())) {
        return ChainType::REGTEST;
    } else if (std::equal(message.begin(), message.end(), signet_msg.data())) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}

