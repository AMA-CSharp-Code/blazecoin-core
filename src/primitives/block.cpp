// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <crypto/scrypt.h>
#include <hash.h>
#include <streams.h>
#include <tinyformat.h>

#include <cassert>

uint256 CBlockHeader::GetHash() const
{
    return (HashWriter{} << *this).GetHash();
}

// Blazecoin: the proof-of-work hash (Scrypt) — distinct from GetHash() above,
// which is the SHA256d block IDENTITY hash. The two are NOT interchangeable:
// only this hash may be passed to CheckProofOfWork; GetHash() identifies the
// block everywhere else. See the contract note on CheckProofOfWork in pow.cpp.
uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    // Serialize the block header — exactly 80 bytes — as the Scrypt input.
    // scrypt_1024_1_1_256 reads a FIXED 80-byte buffer with no length argument,
    // so the serialized size is a hard contract. Assert it (asserts are on in
    // release for this codebase) so any future header-format change fails loudly
    // here instead of causing a silent out-of-bounds read / wrong PoW hash.
    DataStream ss{};
    ss << *this;
    assert(ss.size() == 80);
    scrypt_1024_1_1_256((const char*)ss.data(), (char*)thash.data());
    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
