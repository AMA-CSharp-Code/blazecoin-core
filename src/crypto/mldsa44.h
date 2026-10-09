// Copyright (c) 2026 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_MLDSA44_H
#define BITCOIN_CRYPTO_MLDSA44_H

#include <span.h>

#include <cstddef>
#include <vector>

/** ML-DSA-44 (FIPS 204) — thin C++ wrapper over the vendored pq-crystals
 *  reference implementation in src/crypto/mldsa/ (deterministic signing,
 *  seeded key generation, no RNG linked). This is the only ML-DSA entry point
 *  the rest of the tree uses: consensus (OP_CHECKPQSIG, src/script/pq.h) and
 *  the wallet's P2PQH signer. Spec: PQ_SIGNATURES.md s2, s3.4, s6. */
namespace mldsa44 {

constexpr size_t PUBKEY_SIZE = 1312;
constexpr size_t SECKEY_SIZE = 2560;
constexpr size_t SIG_SIZE = 2420;
constexpr size_t SEED_SIZE = 32;
/** FIPS 204 caps the context string at 255 bytes. */
constexpr size_t MAX_CTX_SIZE = 255;

/** ML-DSA.KeyGen_internal(xi): expand a 32-byte seed into (pk, sk).
 *  Returns false only if seed32 is not exactly SEED_SIZE bytes. */
bool KeyGenFromSeed(Span<const unsigned char> seed32, std::vector<unsigned char>& pk, std::vector<unsigned char>& sk);

/** Deterministic ML-DSA.Sign(sk, msg, ctx) (FIPS 204 s5.2 with rnd = 0^32).
 *  Returns false if sk is not SECKEY_SIZE bytes or ctx exceeds MAX_CTX_SIZE. */
bool Sign(Span<const unsigned char> sk, Span<const unsigned char> msg, Span<const unsigned char> ctx, std::vector<unsigned char>& sig);

/** ML-DSA.Verify(pk, msg, sig, ctx) (FIPS 204 s5.3). Any size mismatch is a
 *  verification failure, never an exception. */
bool Verify(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> ctx, Span<const unsigned char> sig);

} // namespace mldsa44

#endif // BITCOIN_CRYPTO_MLDSA44_H
