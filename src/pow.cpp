// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

namespace {
/** Blazecoin: the min/max permitted "actual timespan" for the difficulty
 *  retarget at block `height`. Shared by CalculateNextWorkRequired (to clamp
 *  the retarget) and PermittedDifficultyTransition (to bound the transition) so
 *  the two-era rule lives in ONE place and the two consensus-critical call sites
 *  can't drift. The arithmetic byte-matches the formerly-inlined bounds:
 *    Era 1 (height < nDiffChangeTarget): ±400% (timespan/4 .. timespan*4)
 *    Era 2 (height >= nDiffChangeTarget): ±10%  (timespan - t/10 .. timespan + t/10)
 *  `lower`/`upper` avoid the Windows min/max macros. */
struct RetargetTimespanBounds { int64_t lower; int64_t upper; };

RetargetTimespanBounds GetRetargetTimespanBounds(int64_t height, const Consensus::Params& params)
{
    const int64_t timespan = params.nPowTargetTimespan;
    if (height >= params.nDiffChangeTarget) {
        // Era 2: ±10%
        return {timespan - (timespan / 10), timespan + (timespan / 10)};
    }
    // Era 1: ±400%
    return {timespan / 4, timespan * 4};
}
} // namespace

// Blazecoin: Two-era difficulty adjustment algorithm
// Era 1 (height < nDiffChangeTarget): ±400% bounds, retarget every nPowTargetTimespan/nPowTargetSpacing blocks
// Era 2 (height >= nDiffChangeTarget): ±10% bounds, same interval
// Blazecoin Era 3 — Phoenix-413 per-block ASERT (spec: PHOENIX_413.md, RATIFIED
// 2026-08-26; aserti3-2d fixed-point form with half-life 413 blocks). The pure
// function below must stay bit-exact with the canonical vectors in
// test/phoenix413/ — do not "clean up" the arithmetic: truncating division and
// arithmetic shifts are pinned semantics shared with the V1.5.2 client and the
// lite-wallet C# verifier.
unsigned int CalculatePhoenix413Target(unsigned int nAnchorBits, int64_t nAnchorParentTime,
                                       int64_t nAnchorHeight, int64_t nEvalHeight,
                                       int64_t nParentTime, int64_t nPowTargetSpacing,
                                       const uint256& pow_limit)
{
    const arith_uint256 bnPowLimit = UintToArith256(pow_limit);
    const int64_t nHalfLife = 413 * nPowTargetSpacing; // mainnet: 12,390 s

    const int64_t nTimeDiff = nParentTime - nAnchorParentTime;
    const int64_t nHeightDiff = (nEvalHeight - 1) - nAnchorHeight;

    // Exponent in 1/65536 units of half-lives behind (+) / ahead (-) schedule.
    // C-style truncating division — pinned by the vectors.
    const int64_t nNum = (nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536;
    const int64_t nExponent = nNum / nHalfLife;

    const int64_t nShifts = nExponent >> 16; // arithmetic shift: floor
    const uint64_t nFrac = (uint64_t)nExponent & 0xffff;

    // Cubic approximation of 2^(frac/65536) in 16-bit fixed point (aserti3-2d
    // constants; the sum stays inside uint64 by construction).
    const uint64_t nFactor = 65536ULL
        + ((195766423245049ULL * nFrac
            + 971821376ULL * nFrac * nFrac
            + 5127ULL * nFrac * nFrac * nFrac
            + (1ULL << 47)) >> 48);

    // The result is floor(refTarget * factor * 2^(shifts-16)), clamped. On
    // regtest powLimit is ~2^255, so refTarget * factor can OVERFLOW 256 bits
    // (found by feature_blazecoin_phoenix413.py — silent wrap made targets
    // ~2^16 harder). Evaluate exactly without ever overflowing, using
    //   floor((q*2^s + r) * f / 2^s) = q*f + floor(r*f / 2^s)
    // and floor(floor(x/2^a)/2^b) = floor(x/2^(a+b)). Any branch that proves
    // the true value >= 2^255 clamps to powLimit — identical to
    // compute-then-clamp on every network (all powLimits are < 2^255 + 1).
    arith_uint256 bnRef;
    bnRef.SetCompact(nAnchorBits);
    arith_uint256 bnTarget;

    const int64_t nNet = nShifts - 16;
    if (nNet >= 0) {
        // ref * f * 2^net: overflow iff bits(ref) + 17 + net > 256, and then
        // the true value is >= 2^255 >= every powLimit.
        if (bnRef.bits() + 17 + nNet > 256) return bnPowLimit.GetCompact();
        bnTarget = bnRef;
        bnTarget *= (uint32_t)nFactor; // nFactor < 2^17
        bnTarget <<= (unsigned int)nNet;
    } else {
        const int64_t k = -nNet; // divide by 2^k, flooring
        if (k > 272) {
            bnTarget = 0; // ref*f < 2^273, so the quotient is zero
        } else {
            const unsigned int s = (unsigned int)(k < 239 ? k : 239);
            arith_uint256 q = bnRef >> s;
            const arith_uint256 r = bnRef - (q << s);
            if (q.bits() + 17 > 256) return bnPowLimit.GetCompact(); // true value >= 2^255
            q *= (uint32_t)nFactor;          // fits: bits(q) + 17 <= 256
            arith_uint256 low = r;           // fits: r < 2^s <= 2^239, f < 2^17
            low *= (uint32_t)nFactor;
            low >>= s;
            bnTarget = q + low;              // exact floor(ref*f / 2^s)
            if ((unsigned int)k > s) bnTarget >>= (unsigned int)k - s; // floors compose
        }
    }

    if (bnTarget == 0) bnTarget = 1;
    if (bnTarget > bnPowLimit) bnTarget = bnPowLimit;
    return bnTarget.GetCompact();
}

unsigned int Phoenix413NextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    assert(pindexLast->nHeight + 1 > params.phoenix413Height);
    const CBlockIndex* pAnchor = pindexLast->GetAncestor(params.phoenix413Height);
    assert(pAnchor != nullptr && pAnchor->pprev != nullptr);
    return CalculatePhoenix413Target(pAnchor->nBits, pAnchor->pprev->GetBlockTime(),
                                     pAnchor->nHeight, pindexLast->nHeight + 1,
                                     pindexLast->GetBlockTime(), params.nPowTargetSpacing,
                                     params.powLimit);
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    // Blazecoin Era 3 — Phoenix-413 (inert while phoenix413Height is
    // BLAZECOIN_BIP_NEVER_ACTIVE; regtest activates it via
    // -testactivationheight=phoenix413@N). Deliberately checked before the
    // min-difficulty / no-retargeting shortcuts: a chain that explicitly
    // activates Phoenix wants it computed.
    if (pindexLast->nHeight + 1 > params.phoenix413Height)
        return Phoenix413NextWorkRequired(pindexLast, params);

    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    int64_t retargetInterval = params.DifficultyAdjustmentInterval();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight + 1) % retargetInterval != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* target spacing
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % retargetInterval != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Blazecoin: Go back the full period unless it's the first retarget after genesis
    // This fixes an issue where a 51% attack can change difficulty at will (Art Forz fix)
    int64_t blockstogoback = retargetInterval - 1;
    if ((pindexLast->nHeight + 1) != retargetInterval)
        blockstogoback = retargetInterval;

    const CBlockIndex* pindexFirst = pindexLast;
    for (int64_t i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    int nHeight = pindexLast->nHeight + 1;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    // Blazecoin two-era bounds (shared with PermittedDifficultyTransition)
    const RetargetTimespanBounds bounds = GetRetargetTimespanBounds(nHeight, params);
    if (nActualTimespan < bounds.lower)
        nActualTimespan = bounds.lower;
    if (nActualTimespan > bounds.upper)
        nActualTimespan = bounds.upper;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    // Blazecoin Era 3: post-Phoenix the target legitimately moves every block as
    // a function of timestamps this signature cannot see. Exact validation still
    // happens in ContextualCheckBlockHeader via GetNextWorkRequired; this
    // anti-DoS pre-check simply stops rejecting.
    if (height > params.phoenix413Height) return true;

    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        // Blazecoin two-era bounds (shared with CalculateNextWorkRequired)
        const RetargetTimespanBounds bounds = GetRetargetTimespanBounds(height, params);
        const int64_t smallest_timespan = bounds.lower;
        const int64_t largest_timespan = bounds.upper;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

/** Blazecoin: check proof of work using the Scrypt hash.
 *
 *  CONTRACT: `hash` MUST be CBlockHeader::GetPoWHash() (Scrypt), NOT GetHash()
 *  (the SHA256d block identity). They are different functions and are not
 *  interchangeable — passing the identity hash here compares the wrong value
 *  against the target and would split consensus. This distinction is by
 *  convention (the arg is a plain uint256), so every PoW call site is expected
 *  to pass GetPoWHash(); the `scrypt_pow_distinct_from_identity` pow test pins it.
 */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
