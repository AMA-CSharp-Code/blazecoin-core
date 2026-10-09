#!/usr/bin/env python3
"""
Blazecoin P2PQH / PQSigHash test-vector generator — the semantic authority (PQ_SIGNATURES.md §10.1).

Pure Python: dilithium-py (FIPS 204 ML-DSA-44), hashlib. Independent of both production
implementations (the daemon's vendored pq-crystals C and the wallet's BouncyCastle).

Usage:  python generate_pqsig_vectors.py [out.json]

Vector families:
  derivation  — master_seed → ξ_i → (pk, pqkh, scriptPubKey, address) for i = 0..2, mainnet + regtest
  sighash     — PQSigHash preimage + digest for every PQ input of three transactions (1 / 2 / 26 inputs,
                mixed P2PKH + P2PQH, locktime/sequence/amounts exercised), plus the signed scriptSigs
  spend       — per-input script cases: (tx, input index, prevout) → "OK" or the failure reason
  constants   — sizes, tags, ctx, opcode, address prefixes, examples from the spec
"""
import hashlib, json, struct, sys
from dilithium_py.ml_dsa import ML_DSA_44

# ---------------------------------------------------------------- constants (PQ_SIGNATURES.md)
ALGO_MLDSA44 = 0x01
PK_LEN, SK_LEN, SIG_LEN, SEED_LEN = 1312, 2560, 2420, 32
OP_CHECKPQSIG = 0xBA
TAG_PQKH = b"Blazecoin/PQKH/v1"
TAG_SIGHASH = b"Blazecoin/PQSig/v1"
TAG_SEED = b"Blazecoin/MLDSA44/seed"
CTX_TX = b"blazecoin-tx-v1"
SIGHASH_ALL = 1
PREFIX_MAIN = bytes([0x46, 0x50])   # "BQ…"
PREFIX_TEST = bytes([0xb2, 0x73])   # testnet/regtest: "TQ..." (52 chars, stable across the payload range)
MAX_PQ_ELEMENT = 5000
P2PKH_VERSION_MAIN = 26             # "B…" legacy addresses
MAX_STANDARD_TX_BYTES = 100_000

def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def tagged_hash(tag: bytes, m: bytes) -> bytes:
    t = sha256(tag); return sha256(t + t + m)
def hash160(b): return hashlib.new("ripemd160", sha256(b)).digest()

B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58check(payload: bytes) -> str:
    data = payload + sha256d(payload)[:4]
    n = int.from_bytes(data, "big"); out = bytearray()
    while n: n, r = divmod(n, 58); out.append(B58[r])
    pad = len(data) - len(data.lstrip(b"\0"))
    return (B58[0:1] * pad + bytes(reversed(out))).decode()

def varint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

def push(data: bytes) -> bytes:
    n = len(data)
    if n < 0x4c: return bytes([n]) + data
    if n <= 0xff: return b"\x4c" + bytes([n]) + data
    if n <= 0xffff: return b"\x4d" + struct.pack("<H", n) + data
    return b"\x4e" + struct.pack("<I", n) + data

# ---------------------------------------------------------------- keys / scripts / addresses
def keyblob(pk: bytes, algo=ALGO_MLDSA44) -> bytes: return bytes([algo]) + pk
def pqkh(blob: bytes) -> bytes: return tagged_hash(TAG_PQKH, blob)
def p2pqh_script(h32: bytes) -> bytes: return b"\x20" + h32 + bytes([OP_CHECKPQSIG])
def p2pkh_script(h20: bytes) -> bytes: return b"\x76\xa9\x14" + h20 + b"\x88\xac"
def pq_address(h32: bytes, prefix=PREFIX_MAIN) -> str: return b58check(prefix + h32)

def derive_xi(master_seed: bytes, i: int) -> bytes:
    return tagged_hash(TAG_SEED, master_seed + struct.pack("<I", i))

class PQKey:
    def __init__(self, master_seed: bytes, i: int):
        self.i = i
        self.xi = derive_xi(master_seed, i)
        self.pk, self.sk = ML_DSA_44.key_derive(self.xi)
        self.blob = keyblob(self.pk)
        self.h = pqkh(self.blob)
        self.spk = p2pqh_script(self.h)
    def sign(self, msg32: bytes, ctx=CTX_TX) -> bytes:
        return ML_DSA_44.sign(self.sk, msg32, ctx, deterministic=True)

# ---------------------------------------------------------------- transactions
class TxIn:
    def __init__(self, txid_le: bytes, vout: int, prev_amount: int, prev_spk: bytes, seq=0xffffffff, script_sig=b""):
        self.txid_le, self.vout, self.prev_amount, self.prev_spk, self.seq, self.script_sig = txid_le, vout, prev_amount, prev_spk, seq, script_sig
    def outpoint(self): return self.txid_le + struct.pack("<I", self.vout)
    def ser(self): return self.outpoint() + varint(len(self.script_sig)) + self.script_sig + struct.pack("<I", self.seq)

class TxOut:
    def __init__(self, value: int, spk: bytes): self.value, self.spk = value, spk
    def ser(self): return struct.pack("<q", self.value) + varint(len(self.spk)) + self.spk

class Tx:
    def __init__(self, version=2, vin=None, vout=None, locktime=0):
        self.version, self.vin, self.vout, self.locktime = version, vin or [], vout or [], locktime
    def ser(self):
        return (struct.pack("<i", self.version) + varint(len(self.vin)) + b"".join(i.ser() for i in self.vin)
                + varint(len(self.vout)) + b"".join(o.ser() for o in self.vout) + struct.pack("<I", self.locktime))
    def txid(self): return sha256d(self.ser())[::-1].hex()

def pq_sighash_preimage(tx: Tx, n_in: int, amount: int, script_code: bytes, sighash_type=SIGHASH_ALL) -> bytes:
    hash_prevouts = sha256d(b"".join(i.outpoint() for i in tx.vin))
    hash_sequence = sha256d(b"".join(struct.pack("<I", i.seq) for i in tx.vin))
    hash_outputs = sha256d(b"".join(o.ser() for o in tx.vout))
    tin = tx.vin[n_in]
    return (struct.pack("<i", tx.version) + hash_prevouts + hash_sequence + tin.outpoint()
            + varint(len(script_code)) + script_code + struct.pack("<q", amount) + struct.pack("<I", tin.seq)
            + hash_outputs + struct.pack("<I", tx.locktime) + struct.pack("<I", sighash_type))

def pq_sighash(tx: Tx, n_in: int, amount: int, script_code: bytes) -> bytes:
    return tagged_hash(TAG_SIGHASH, pq_sighash_preimage(tx, n_in, amount, script_code))

def pq_script_sig(sig: bytes, blob: bytes) -> bytes: return push(sig) + push(blob)

# ---------------------------------------------------------------- deterministic fixtures
def det(n: int, salt: bytes) -> bytes: return sha256(salt + struct.pack("<I", n))
MASTER = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
keys = [PQKey(MASTER, i) for i in range(30)]
legacy_h160 = [hash160(det(i, b"legacy-pubkey"))[:20] for i in range(4)]
def fake_txid(i): return det(i, b"prev-txid")

def build_tx(n_pq: int, with_legacy: bool, locktime: int, seqs, amounts, key_offset=0):
    vin = []
    for i in range(n_pq):
        k = keys[key_offset + i]
        vin.append(TxIn(fake_txid(100 + i), i % 3, amounts[i], k.spk, seqs[i]))
    if with_legacy:
        vin.insert(1, TxIn(fake_txid(999), 7, 12_345_678, p2pkh_script(legacy_h160[0]), 0xfffffffe, b""))
    total = sum(i.prev_amount for i in vin)
    vout = [TxOut(total - 100_000 - 1_500, p2pkh_script(legacy_h160[1])), TxOut(100_000, keys[29].spk)]
    return Tx(2, vin, vout, locktime)

def sign_tx(tx: Tx):
    records = []
    for n, tin in enumerate(tx.vin):
        if len(tin.prev_spk) == 34 and tin.prev_spk[0] == 0x20 and tin.prev_spk[33] == OP_CHECKPQSIG:
            k = next(k for k in keys if k.spk == tin.prev_spk)
            pre = pq_sighash_preimage(tx, n, tin.prev_amount, tin.prev_spk)
            msg = tagged_hash(TAG_SIGHASH, pre)
            sig = k.sign(msg)
            tin.script_sig = pq_script_sig(sig, k.blob)
            rec = {"input": n, "key_index": k.i, "amount": tin.prev_amount, "scriptCode": tin.prev_spk.hex(), "digest": msg.hex(), "sig": sig.hex()}
            if len(tx.vin) <= 3: rec["preimage"] = pre.hex(); rec["scriptSig"] = tin.script_sig.hex()
            records.append(rec)
    return records

# ---------------------------------------------------------------- vectors
out = {"_comment": "Blazecoin P2PQH / PQSigHash vectors — generated by test/pqsig/generate_pqsig_vectors.py (dilithium-py, pure Python). Semantic authority for the C++ daemon and the C# lite wallet. See PQ_SIGNATURES.md.",
       "constants": {
           "algo_id_mldsa44": ALGO_MLDSA44, "pubkey_len": PK_LEN, "seckey_len": SK_LEN, "sig_len": SIG_LEN, "seed_len": SEED_LEN,
           "op_checkpqsig": OP_CHECKPQSIG, "tag_pqkh": TAG_PQKH.decode(), "tag_sighash": TAG_SIGHASH.decode(),
           "tag_seed": TAG_SEED.decode(), "ctx_tx": CTX_TX.decode(), "sighash_all": SIGHASH_ALL,
           "address_prefix_main": PREFIX_MAIN.hex(), "address_prefix_test": PREFIX_TEST.hex(),
           "max_pq_element_size": MAX_PQ_ELEMENT, "scriptsig_len": 3 + SIG_LEN + 3 + PK_LEN + 1, "input_len": 36 + 3 + 3 + SIG_LEN + 3 + PK_LEN + 1 + 4,
           "address_examples": {"pqkh_00": pq_address(b"\0" * 32), "pqkh_ff": pq_address(b"\xff" * 32)},
       },
       "derivation": [], "sighash": [], "spend": []}

assert out["constants"]["address_examples"]["pqkh_00"] == "BQGeaQmsowAjL1ZG8q1AfVH4NgBvtJKJSsjnnKEf62BMjekdU82n"
assert out["constants"]["address_examples"]["pqkh_ff"] == "BQJbKb1KqnbQZ9NqqjanfSbf9bJYbx29KfNrtZPLz1qN89DPR4Hh"
assert out["constants"]["input_len"] == 3782 and out["constants"]["scriptsig_len"] == 3739

for k in keys[:3]:
    out["derivation"].append({"master_seed": MASTER.hex(), "index": k.i, "xi": k.xi.hex(), "pubkey": k.pk.hex(),
                              "seckey_sha256": sha256(k.sk).hex(), "keyblob_sha256": sha256(k.blob).hex(), "pqkh": k.h.hex(),
                              "scriptPubKey": k.spk.hex(), "address_main": pq_address(k.h), "address_test": pq_address(k.h, PREFIX_TEST)})

# --- sighash + valid spends: three transactions
tx1 = build_tx(1, False, 0, [0xffffffff], [5_000_000_000], key_offset=0)
tx2 = build_tx(2, True, 4_246_000, [0xfffffffd, 0x00000000], [1, 2_100_000_000_000_000], key_offset=3)
tx26 = build_tx(26, False, 12345, [0xffffffff - i for i in range(26)], [100_000_000 * (i + 1) for i in range(26)], key_offset=3)
txs = [("1 PQ input", tx1), ("1 legacy + 2 PQ inputs, locktime 4246000, sequences", tx2), ("26 PQ inputs - the standard-size maximum", tx26)]
for ti, (label, tx) in enumerate(txs):
    recs = sign_tx(tx)
    out["sighash"].append({"label": label, "tx": tx.ser().hex(), "txid": tx.txid(),
                           "prevouts": [{"amount": i.prev_amount, "scriptPubKey": i.prev_spk.hex()} for i in tx.vin], "inputs": recs})
    for r in recs:
        # "tx_ref": index into "sighash" (the signed tx hex lives there once); every PQ input of every valid tx must verify
        out["spend"].append({"label": f"valid: {label}, input {r['input']}", "tx_ref": ti, "input": r["input"],
                             "amount": r["amount"], "scriptPubKey": r["scriptCode"], "expect": "OK"})
assert len(tx26.ser()) <= MAX_STANDARD_TX_BYTES, len(tx26.ser())
out["constants"]["tx26_serialized_len"] = len(tx26.ser())

# --- invalid spends, each derived from tx1
def variant(label, mutate, expect):
    t = build_tx(1, False, 0, [0xffffffff], [5_000_000_000], key_offset=0)
    sign_tx(t)
    mutate(t)
    out["spend"].append({"label": label, "tx": t.ser().hex(), "input": 0, "amount": t.vin[0].prev_amount,
                         "scriptPubKey": t.vin[0].prev_spk.hex(), "expect": expect})

k0, k1 = keys[0], keys[1]
def m_wrong_pqkh(t):        # keyblob of another key: hash mismatch
    sig = k1.sign(pq_sighash(t, 0, t.vin[0].prev_amount, t.vin[0].prev_spk)); t.vin[0].script_sig = pq_script_sig(sig, k1.blob)
variant("invalid: keyblob does not hash to pqkh", m_wrong_pqkh, "PQ_KEYHASH_MISMATCH")
def m_inactive_algo(t):     # algo_id 0x02 with a correctly-sized (1952-byte) dummy pubkey; pqkh in scriptPubKey rewritten to match so only the ID check fails
    blob = bytes([0x02]) + det(0, b"fake-mldsa65")*61
    blob = blob[:1953]
    t.vin[0].prev_spk = p2pqh_script(pqkh(blob))
    sig = k0.sign(pq_sighash(t, 0, t.vin[0].prev_amount, t.vin[0].prev_spk)); t.vin[0].script_sig = pq_script_sig(sig, blob)
variant("invalid: reserved algo_id 0x02 (ML-DSA-65) not active", m_inactive_algo, "PQ_ALGO_INACTIVE")
def m_bad_pk_len(t):        # algo 0x01 with a 1311-byte pubkey; pqkh rewritten to match
    blob = bytes([0x01]) + k0.pk[:-1]
    t.vin[0].prev_spk = p2pqh_script(pqkh(blob))
    sig = k0.sign(pq_sighash(t, 0, t.vin[0].prev_amount, t.vin[0].prev_spk)); t.vin[0].script_sig = pq_script_sig(sig, blob)
variant("invalid: pubkey length 1311 for algo 0x01", m_bad_pk_len, "PQ_PUBKEY_LENGTH")
def m_three_pushes(t):      # an extra push: stack must be exactly two elements
    t.vin[0].script_sig = push(b"\x01") + t.vin[0].script_sig
variant("invalid: three pushes in scriptSig", m_three_pushes, "PQ_STACK_SIZE")
def m_one_push(t):
    t.vin[0].script_sig = push(k0.blob)
variant("invalid: one push in scriptSig", m_one_push, "PQ_STACK_SIZE")
def m_non_push(t):          # OP_NOP inside the scriptSig
    t.vin[0].script_sig = t.vin[0].script_sig + b"\x61"
variant("invalid: scriptSig not push-only", m_non_push, "SIG_PUSHONLY")
def m_wrong_amount(t):      # signature made over a digest with a different amount
    sig = k0.sign(pq_sighash(t, 0, t.vin[0].prev_amount + 1, t.vin[0].prev_spk)); t.vin[0].script_sig = pq_script_sig(sig, k0.blob)
variant("invalid: signature over the wrong digest (amount + 1)", m_wrong_amount, "PQ_SIG_INVALID")
def m_wrong_ctx(t):
    sig = k0.sign(pq_sighash(t, 0, t.vin[0].prev_amount, t.vin[0].prev_spk), ctx=b"blazecoin-msg-v1"); t.vin[0].script_sig = pq_script_sig(sig, k0.blob)
variant("invalid: signature under the wrong FIPS 204 ctx", m_wrong_ctx, "PQ_SIG_INVALID")
def m_wrong_output(t):      # outputs changed after signing
    t.vout[0].value -= 1
variant("invalid: output amount changed after signing", m_wrong_output, "PQ_SIG_INVALID")
def m_sig_len(t):
    sig = k0.sign(pq_sighash(t, 0, t.vin[0].prev_amount, t.vin[0].prev_spk)); t.vin[0].script_sig = pq_script_sig(sig[:-1], k0.blob)
variant("invalid: signature length 2419", m_sig_len, "PQ_SIG_INVALID")
out["spend"].append({"label": "pre-activation: a valid spend evaluated in SigVersion::BASE (before H_Q) fails as a bad opcode / oversized push",
                     "tx_ref": 0, "input": 0, "amount": tx1.vin[0].prev_amount, "scriptPubKey": tx1.vin[0].prev_spk.hex(),
                     "expect": "PRE_ACTIVATION", "sigversion": "BASE"})

path = sys.argv[1] if len(sys.argv) > 1 else "pqsig_vectors.json"
with open(path, "w", newline="\n") as f:
    json.dump(out, f, indent=1)
print(f"wrote {path}: {len(out['derivation'])} derivation, {len(out['sighash'])} sighash txs, {len(out['spend'])} spend cases; tx26 = {len(tx26.ser())} B")
