// Copyright (c) 2026 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_PQ_H
#define BITCOIN_SCRIPT_PQ_H

#include <consensus/amount.h>
#include <script/script.h>
#include <span.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct PrecomputedTransactionData;

/** Blazecoin post-quantum output type P2PQH — consensus primitives.
 *
 *  Spec of record: PQ_SIGNATURES.md (s3 output type, s3.5 digest, s4 sizes,
 *  s6 derivation). Semantic authority for every constant and hash here:
 *  test/pqsig/generate_pqsig_vectors.py + pqsig_vectors.json (pure-Python,
 *  dilithium-py); src/test/pqsig_tests.cpp pins this implementation to them.
 *
 *  scriptPubKey (34 bytes):   0x20 <pqkh:32> OP_CHECKPQSIG (0xba)
 *  scriptSig:                 <sig:2420> <keyblob:1313>   (exactly two pushes)
 *  keyblob  = algo_id (1) || pubkey;   pqkh = TaggedHash("Blazecoin/PQKH/v1", keyblob)
 *  msg      = TaggedHash("Blazecoin/PQSig/v1", BIP-143-shaped preimage)   (s3.5)
 *  verify   = ML-DSA-44.Verify(pubkey, msg, sig, ctx = "blazecoin-tx-v1")
 */
namespace pq {

/** Algorithm ids inside the key blob (s3.1). Only MLDSA44 is active; the
 *  others are reserved and fail OP_CHECKPQSIG until a later fork. */
constexpr unsigned char PQ_ALGO_MLDSA44 = 0x01;
constexpr unsigned char PQ_ALGO_MLDSA65_RESERVED = 0x02;
constexpr unsigned char PQ_ALGO_MLDSA87_RESERVED = 0x03;
constexpr unsigned char PQ_ALGO_SLHDSA128S_RESERVED = 0x04;
constexpr unsigned char PQ_ALGO_FNDSA512_RESERVED = 0x05;

constexpr size_t PQ_KEYHASH_SIZE = 32;
constexpr size_t PQ_MLDSA44_PUBKEY_SIZE = 1312;
constexpr size_t PQ_MLDSA44_SIG_SIZE = 2420;
/** 1 + 1312 */
constexpr size_t PQ_MLDSA44_KEYBLOB_SIZE = 1 + PQ_MLDSA44_PUBKEY_SIZE;
/** 0x20 + 32 + 0xba */
constexpr size_t PQ_SCRIPTPUBKEY_SIZE = 2 + PQ_KEYHASH_SIZE;
/** Stack element cap inside SigVersion::PQ (s3.4: room for ML-DSA-87); defined in script.h for CScript::HasValidOps. */
constexpr unsigned int MAX_PQ_SCRIPT_ELEMENT_SIZE = ::PQ_MAX_SCRIPT_ELEMENT_SIZE;
/** Legacy sigop weight of one OP_CHECKPQSIG (s4); defined in script.h for CScript::GetSigOpCount. */
constexpr unsigned int PQ_SIGOP_COST = ::PQ_SIGOP_COST;
/** The only sighash type in v1 (s3.5). */
constexpr uint32_t PQ_SIGHASH_ALL = 1;

const std::string TAG_PQKH{"Blazecoin/PQKH/v1"};
const std::string TAG_SIGHASH{"Blazecoin/PQSig/v1"};
const std::string TAG_SEED{"Blazecoin/MLDSA44/seed"};
/** FIPS 204 context string for transaction signatures (s3.4 step 6). */
const std::string CTX_TX{"blazecoin-tx-v1"};

/** pqkh = TaggedHash("Blazecoin/PQKH/v1", keyblob). */
uint256 PQKeyHash(Span<const unsigned char> keyblob);

/** keyblob = 0x01 || pubkey (ML-DSA-44 only). */
std::vector<unsigned char> PQKeyBlob(Span<const unsigned char> pubkey);

/** Exact template test: size 34, [0] == 0x20, [33] == OP_CHECKPQSIG. */
bool IsPayToPQKeyHash(const CScript& script, uint256* pqkh = nullptr);

/** 0x20 <pqkh> OP_CHECKPQSIG */
CScript GetScriptForPQKeyHash(const uint256& pqkh);

/** The s3.5 digest for input nIn of tx: TaggedHash("Blazecoin/PQSig/v1",
 *  BIP-143-shaped preimage committing to the amount and the 34-byte
 *  scriptCode). Uses the BIP-143 hashPrevouts/hashSequence/hashOutputs from
 *  cache when it is ready, otherwise computes them. */
template <class T>
uint256 PQSigHash(const T& tx, unsigned int nIn, const CAmount& amount, const CScript& scriptCode, const PrecomputedTransactionData* cache = nullptr);

/** s6: xi_i = TaggedHash("Blazecoin/MLDSA44/seed", master_seed32 || uint32_le(index)). */
uint256 PQSeedForIndex(Span<const unsigned char> master_seed32, uint32_t index);

} // namespace pq

#endif // BITCOIN_SCRIPT_PQ_H
