// Copyright (c) 2026 The Blazecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mldsa44.h>

extern "C" {
#include <crypto/mldsa/params.h>
#include <crypto/mldsa/sign.h>
}


namespace mldsa44 {

static_assert(PUBKEY_SIZE == CRYPTO_PUBLICKEYBYTES, "vendored ML-DSA is not mode 2");
static_assert(SECKEY_SIZE == CRYPTO_SECRETKEYBYTES, "vendored ML-DSA is not mode 2");
static_assert(SIG_SIZE == CRYPTO_BYTES, "vendored ML-DSA is not mode 2");
static_assert(SEED_SIZE == SEEDBYTES, "unexpected seed size");

bool KeyGenFromSeed(Span<const unsigned char> seed32, std::vector<unsigned char>& pk, std::vector<unsigned char>& sk)
{
    if (seed32.size() != SEED_SIZE) return false;
    pk.assign(PUBKEY_SIZE, 0);
    sk.assign(SECKEY_SIZE, 0);
    crypto_sign_keypair_from_seed(pk.data(), sk.data(), seed32.data());
    return true;
}

bool Sign(Span<const unsigned char> sk, Span<const unsigned char> msg, Span<const unsigned char> ctx, std::vector<unsigned char>& sig)
{
    if (sk.size() != SECKEY_SIZE || ctx.size() > MAX_CTX_SIZE) return false;
    sig.assign(SIG_SIZE, 0);
    size_t siglen = 0;
    if (crypto_sign_signature(sig.data(), &siglen, msg.data(), msg.size(), ctx.data(), ctx.size(), sk.data()) != 0) {
        sig.clear();
        return false;
    }
    if (siglen != SIG_SIZE) {
        sig.clear();
        return false;
    }
    return true;
}

bool Verify(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> ctx, Span<const unsigned char> sig)
{
    if (pk.size() != PUBKEY_SIZE || sig.size() != SIG_SIZE || ctx.size() > MAX_CTX_SIZE) return false;
    return crypto_sign_verify(sig.data(), sig.size(), msg.data(), msg.size(), ctx.data(), ctx.size(), pk.data()) == 0;
}

} // namespace mldsa44
