// Copyright (c) 2026 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/pq.h>

#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>

#include <vector>

namespace pq {

uint256 PQKeyHash(Span<const unsigned char> keyblob)
{
    HashWriter ss{TaggedHash(TAG_PQKH)};
    ss.write(AsBytes(keyblob));
    return ss.GetSHA256();
}

std::vector<unsigned char> PQKeyBlob(Span<const unsigned char> pubkey)
{
    std::vector<unsigned char> blob;
    blob.reserve(1 + pubkey.size());
    blob.push_back(PQ_ALGO_MLDSA44);
    blob.insert(blob.end(), pubkey.begin(), pubkey.end());
    return blob;
}

bool IsPayToPQKeyHash(const CScript& script, uint256* pqkh)
{
    if (script.size() != PQ_SCRIPTPUBKEY_SIZE || script[0] != PQ_KEYHASH_SIZE || script[PQ_SCRIPTPUBKEY_SIZE - 1] != OP_CHECKPQSIG) {
        return false;
    }
    if (pqkh) {
        std::copy(script.begin() + 1, script.begin() + 1 + PQ_KEYHASH_SIZE, pqkh->begin());
    }
    return true;
}

CScript GetScriptForPQKeyHash(const uint256& pqkh)
{
    return CScript() << std::vector<unsigned char>(pqkh.begin(), pqkh.end()) << OP_CHECKPQSIG;
}

template <class T>
uint256 PQSigHash(const T& tx, unsigned int nIn, const CAmount& amount, const CScript& scriptCode, const PrecomputedTransactionData* cache)
{
    assert(nIn < tx.vin.size());

    uint256 hashPrevouts, hashSequence, hashOutputs;
    if (cache && cache->m_bip143_segwit_ready) {
        hashPrevouts = cache->hashPrevouts;
        hashSequence = cache->hashSequence;
        hashOutputs = cache->hashOutputs;
    } else {
        {
            HashWriter ss{};
            for (const auto& txin : tx.vin) ss << txin.prevout;
            hashPrevouts = ss.GetHash();
        }
        {
            HashWriter ss{};
            for (const auto& txin : tx.vin) ss << txin.nSequence;
            hashSequence = ss.GetHash();
        }
        {
            HashWriter ss{};
            for (const auto& txout : tx.vout) ss << txout;
            hashOutputs = ss.GetHash();
        }
    }

    // PQ_SIGNATURES.md s3.5 — the BIP-143 shape, SIGHASH_ALL only, tagged.
    HashWriter ss{TaggedHash(TAG_SIGHASH)};
    ss << tx.version;
    ss << hashPrevouts;
    ss << hashSequence;
    ss << tx.vin[nIn].prevout;
    ss << scriptCode; // varint length + the 34-byte P2PQH scriptPubKey
    ss << amount;
    ss << tx.vin[nIn].nSequence;
    ss << hashOutputs;
    ss << tx.nLockTime;
    ss << PQ_SIGHASH_ALL;
    return ss.GetSHA256();
}

template uint256 PQSigHash(const CTransaction& tx, unsigned int nIn, const CAmount& amount, const CScript& scriptCode, const PrecomputedTransactionData* cache);
template uint256 PQSigHash(const CMutableTransaction& tx, unsigned int nIn, const CAmount& amount, const CScript& scriptCode, const PrecomputedTransactionData* cache);

uint256 PQSeedForIndex(Span<const unsigned char> master_seed32, uint32_t index)
{
    HashWriter ss{TaggedHash(TAG_SEED)};
    ss.write(AsBytes(master_seed32));
    ss << index; // uint32 little-endian
    return ss.GetSHA256();
}

} // namespace pq
