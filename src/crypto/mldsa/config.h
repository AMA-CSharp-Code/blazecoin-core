#ifndef CONFIG_H
#define CONFIG_H

/* Blazecoin vendoring of pq-crystals ml-dsa (FIPS 204 final, commit d35ba3f):
 *  - DILITHIUM_MODE is forced to 2 (ML-DSA-44, PQ_SIGNATURES.md s2).
 *  - DILITHIUM_RANDOMIZED_SIGNING is deliberately NOT defined: signing is the
 *    deterministic variant (rnd = 32 zero bytes) so a signature over a given
 *    digest is reproducible and matches the Python authority byte-for-byte
 *    (test/pqsig/generate_pqsig_vectors.py, dilithium-py deterministic=True).
 *  - randombytes.c is not vendored: key generation takes an explicit seed
 *    (crypto_sign_keypair_from_seed in sign.c), so consensus code never links
 *    an RNG. */
#ifdef DILITHIUM_RANDOMIZED_SIGNING
#error "Blazecoin ML-DSA-44 must be built with deterministic signing"
#endif
//#define USE_RDPMC
//#define DBENCH

#ifdef DILITHIUM_MODE
#undef DILITHIUM_MODE
#endif
#define DILITHIUM_MODE 2

#if DILITHIUM_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium2_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium2_ref_##s
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium3_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium3_ref_##s
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium5_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium5_ref_##s
#endif

#endif
