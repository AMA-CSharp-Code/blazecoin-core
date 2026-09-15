#!/usr/bin/env python3
# Copyright (c) 2026 The Blazecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blazecoin P2PQH helpers for the functional tests - a port of the vector
authority test/pqsig/generate_pqsig_vectors.py (PQ_SIGNATURES.md s3, s5, s6)
onto the test framework's CTransaction, so a functional test can create and
sign post-quantum spends without the daemon wallet.

Requires dilithium-py (pure-Python FIPS 204 ML-DSA-44):  pip install dilithium-py
"""
import hashlib
import struct

from .messages import CTransaction, ser_compact_size
from .script import CScript

try:
    from dilithium_py.ml_dsa import ML_DSA_44
except ImportError:  # pragma: no cover - the test skips itself
    ML_DSA_44 = None

# ---------------------------------------------------------------- constants (PQ_SIGNATURES.md)
ALGO_MLDSA44 = 0x01
PK_LEN, SK_LEN, SIG_LEN, SEED_LEN = 1312, 2560, 2420, 32
OP_CHECKPQSIG = 0xBA
TAG_PQKH = b"Blazecoin/PQKH/v1"
TAG_SIGHASH = b"Blazecoin/PQSig/v1"
TAG_SEED = b"Blazecoin/MLDSA44/seed"
CTX_TX = b"blazecoin-tx-v1"
SIGHASH_ALL = 1
PREFIX_MAIN = bytes([0x46, 0x50])   # "BQ..."
PREFIX_TEST = bytes([0xb2, 0x73])   # "TQ..." (testnet/testnet4/signet/regtest)
MAX_PQ_ELEMENT = 5000
PQ_SCRIPTSIG_LEN = 3 + SIG_LEN + 3 + PK_LEN + 1   # 3739
PQ_INPUT_LEN = 36 + 3 + PQ_SCRIPTSIG_LEN + 4      # 3782


def have_dilithium():
    return ML_DSA_44 is not None


def sha256(b):
    return hashlib.sha256(b).digest()


def sha256d(b):
    return sha256(sha256(b))


def tagged_hash(tag, m):
    t = sha256(tag)
    return sha256(t + t + m)


B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + sha256d(payload)[:4]
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n:
        n, r = divmod(n, 58)
        out.append(B58[r])
    pad = len(data) - len(data.lstrip(b"\0"))
    return (B58[0:1] * pad + bytes(reversed(out))).decode()


def push(data):
    """Minimal push of `data` (the canonical encoding the vectors use)."""
    n = len(data)
    if n < 0x4c:
        return bytes([n]) + data
    if n <= 0xff:
        return b"\x4c" + bytes([n]) + data
    if n <= 0xffff:
        return b"\x4d" + struct.pack("<H", n) + data
    return b"\x4e" + struct.pack("<I", n) + data


# ---------------------------------------------------------------- keys / scripts / addresses
def keyblob(pk, algo=ALGO_MLDSA44):
    return bytes([algo]) + pk


def pqkh(blob):
    return tagged_hash(TAG_PQKH, blob)


def p2pqh_script(h32):
    assert len(h32) == 32
    return CScript(b"\x20" + h32 + bytes([OP_CHECKPQSIG]))


def pq_address(h32, prefix=PREFIX_TEST):
    return b58check(prefix + h32)


def derive_xi(master_seed, i):
    return tagged_hash(TAG_SEED, master_seed + struct.pack("<I", i))


class PQKey:
    """ML-DSA-44 key i derived from a 32-byte master seed (PQ_SIGNATURES.md s6)."""

    def __init__(self, master_seed, i=0):
        assert ML_DSA_44 is not None, "dilithium-py is required"
        self.i = i
        self.xi = derive_xi(master_seed, i)
        self.pk, self.sk = ML_DSA_44.key_derive(self.xi)
        self.blob = keyblob(self.pk)
        self.h = pqkh(self.blob)
        self.spk = p2pqh_script(self.h)

    def address(self, prefix=PREFIX_TEST):
        return pq_address(self.h, prefix)

    def sign(self, msg32, ctx=CTX_TX):
        return ML_DSA_44.sign(self.sk, msg32, ctx, deterministic=True)


# ---------------------------------------------------------------- PQSigHash on test_framework transactions
def _outpoint_ser(txin):
    return txin.prevout.serialize()


def pq_sighash_preimage(tx: CTransaction, n_in, amount, script_code, sighash_type=SIGHASH_ALL):
    hash_prevouts = sha256d(b"".join(_outpoint_ser(i) for i in tx.vin))
    hash_sequence = sha256d(b"".join(struct.pack("<I", i.nSequence) for i in tx.vin))
    hash_outputs = sha256d(b"".join(o.serialize() for o in tx.vout))
    tin = tx.vin[n_in]
    script_code = bytes(script_code)
    return (struct.pack("<i", tx.version) + hash_prevouts + hash_sequence + _outpoint_ser(tin)
            + ser_compact_size(len(script_code)) + script_code + struct.pack("<q", amount)
            + struct.pack("<I", tin.nSequence) + hash_outputs + struct.pack("<I", tx.nLockTime)
            + struct.pack("<I", sighash_type))


def pq_sighash(tx, n_in, amount, script_code):
    return tagged_hash(TAG_SIGHASH, pq_sighash_preimage(tx, n_in, amount, script_code))


def pq_script_sig(sig, blob):
    return CScript(push(sig) + push(blob))


def sign_pq_input(tx: CTransaction, n_in, amount, key: PQKey, ctx=CTX_TX):
    """Fill tx.vin[n_in].scriptSig with <sig> <keyblob> for a P2PQH prevout of `key`."""
    msg = pq_sighash(tx, n_in, amount, key.spk)
    tx.vin[n_in].scriptSig = pq_script_sig(key.sign(msg, ctx), key.blob)
    return msg


def is_p2pqh(spk):
    spk = bytes(spk)
    return len(spk) == 34 and spk[0] == 0x20 and spk[33] == OP_CHECKPQSIG
