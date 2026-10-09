// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/signmessage.h>
#include <crypto/mldsa44.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <pubkey.h>
#include <script/pq.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cassert>
#include <optional>
#include <string>
#include <variant>
#include <vector>

/**
 * Text used to signify that a signed message follows and to prevent
 * inadvertently signing a transaction.
 */
const std::string MESSAGE_MAGIC = "Blazecoin Signed Message:\n";
const std::string PQ_MESSAGE_TAG = "Blazecoin/PQMsg/v1";
const std::string PQ_MESSAGE_CTX = "blazecoin-msg-v1";

static Span<const unsigned char> PQMessageCtx()
{
    return {reinterpret_cast<const unsigned char*>(PQ_MESSAGE_CTX.data()), PQ_MESSAGE_CTX.size()};
}

/** Blazecoin P2PQH: verify base64(keyblob || sig) against a "BQ..." address (see MessageSignPQ). */
static MessageVerificationResult MessageVerifyPQ(const PQKeyHash& pqkh, const std::string& signature, const std::string& message)
{
    const auto bytes = DecodeBase64(signature);
    if (!bytes) {
        return MessageVerificationResult::ERR_MALFORMED_SIGNATURE;
    }
    if (bytes->size() != pq::PQ_MLDSA44_KEYBLOB_SIZE + pq::PQ_MLDSA44_SIG_SIZE || (*bytes)[0] != pq::PQ_ALGO_MLDSA44) {
        return MessageVerificationResult::ERR_MALFORMED_SIGNATURE;
    }
    const Span<const unsigned char> keyblob{bytes->data(), pq::PQ_MLDSA44_KEYBLOB_SIZE};
    const Span<const unsigned char> sig{bytes->data() + pq::PQ_MLDSA44_KEYBLOB_SIZE, pq::PQ_MLDSA44_SIG_SIZE};
    if (pq::PQKeyHash(keyblob) != uint256(pqkh)) {
        return MessageVerificationResult::ERR_NOT_SIGNED;
    }
    if (!mldsa44::Verify(keyblob.subspan(1), PQMessageDigest(message), PQMessageCtx(), sig)) {
        return MessageVerificationResult::ERR_NOT_SIGNED;
    }
    return MessageVerificationResult::OK;
}

MessageVerificationResult MessageVerify(
    const std::string& address,
    const std::string& signature,
    const std::string& message)
{
    CTxDestination destination = DecodeDestination(address);
    if (!IsValidDestination(destination)) {
        return MessageVerificationResult::ERR_INVALID_ADDRESS;
    }

    // Blazecoin: a "BQ..." address carries an ML-DSA-44 signature, self-contained (key blob inside).
    if (const PQKeyHash* pqkh = std::get_if<PQKeyHash>(&destination)) {
        return MessageVerifyPQ(*pqkh, signature, message);
    }

    if (std::get_if<PKHash>(&destination) == nullptr) {
        return MessageVerificationResult::ERR_ADDRESS_NO_KEY;
    }

    auto signature_bytes = DecodeBase64(signature);
    if (!signature_bytes) {
        return MessageVerificationResult::ERR_MALFORMED_SIGNATURE;
    }

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(MessageHash(message), *signature_bytes)) {
        return MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED;
    }

    if (!(PKHash(pubkey) == *std::get_if<PKHash>(&destination))) {
        return MessageVerificationResult::ERR_NOT_SIGNED;
    }

    return MessageVerificationResult::OK;
}

bool MessageSign(
    const CKey& privkey,
    const std::string& message,
    std::string& signature)
{
    std::vector<unsigned char> signature_bytes;

    if (!privkey.SignCompact(MessageHash(message), signature_bytes)) {
        return false;
    }

    signature = EncodeBase64(signature_bytes);

    return true;
}

bool MessageSignPQ(
    Span<const unsigned char> pubkey,
    Span<const unsigned char> seckey,
    const std::string& message,
    std::string& signature)
{
    if (pubkey.size() != mldsa44::PUBKEY_SIZE || seckey.size() != mldsa44::SECKEY_SIZE) return false;
    std::vector<unsigned char> sig;
    if (!mldsa44::Sign(seckey, PQMessageDigest(message), PQMessageCtx(), sig)) return false;
    std::vector<unsigned char> blob_and_sig = pq::PQKeyBlob(pubkey);
    blob_and_sig.insert(blob_and_sig.end(), sig.begin(), sig.end());
    signature = EncodeBase64(blob_and_sig);
    return true;
}

uint256 PQMessageDigest(const std::string& message)
{
    HashWriter hasher{TaggedHash(PQ_MESSAGE_TAG)};
    hasher << MessageHash(message);
    return hasher.GetSHA256();
}

uint256 MessageHash(const std::string& message)
{
    HashWriter hasher{};
    hasher << MESSAGE_MAGIC << message;

    return hasher.GetHash();
}

std::string SigningResultString(const SigningResult res)
{
    switch (res) {
        case SigningResult::OK:
            return "No error";
        case SigningResult::PRIVATE_KEY_NOT_AVAILABLE:
            return "Private key not available";
        case SigningResult::SIGNING_FAILED:
            return "Sign failed";
        // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}
