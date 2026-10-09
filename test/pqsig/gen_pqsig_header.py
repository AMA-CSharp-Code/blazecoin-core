#!/usr/bin/env python3
"""
Turn test/pqsig/pqsig_vectors.json (the semantic authority, produced by
test/pqsig/generate_pqsig_vectors.py) into src/test/pqsig_vector_data.h for
src/test/pqsig_tests.cpp.

Usage (from the repo root):  python test/pqsig/gen_pqsig_header.py

Transactions are emitted as byte arrays (the 26-input tx is 98 KB, past MSVC's
string-literal limit); every other field stays a hex string. Re-run whenever the
JSON changes; the header is committed so the Boost build needs no Python.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SRC_JSON = os.path.join(HERE, "pqsig_vectors.json")
OUT = os.path.join(ROOT, "src", "test", "pqsig_vector_data.h")


def cstr(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def byte_array(name, hexstr, out):
    data = bytes.fromhex(hexstr)
    out.append(f"static const unsigned char {name}[] = {{")
    for i in range(0, len(data), 32):
        out.append("    " + ",".join(f"0x{b:02x}" for b in data[i:i + 32]) + ",")
    out.append("};")
    out.append(f"static const size_t {name}_LEN = {len(data)};")


def main():
    with open(SRC_JSON) as f:
        v = json.load(f)
    c = v["constants"]
    out = []
    out.append("// GENERATED FILE - DO NOT EDIT.")
    out.append("// Source: test/pqsig/pqsig_vectors.json, produced by test/pqsig/generate_pqsig_vectors.py")
    out.append("// (pure-Python dilithium-py, the semantic authority for PQ_SIGNATURES.md).")
    out.append("// Regenerate with: python test/pqsig/gen_pqsig_header.py")
    out.append("#ifndef BITCOIN_TEST_PQSIG_VECTOR_DATA_H")
    out.append("#define BITCOIN_TEST_PQSIG_VECTOR_DATA_H")
    out.append("")
    out.append("#include <cstddef>")
    out.append("#include <cstdint>")
    out.append("")
    out.append("namespace pqsig_vectors {")
    out.append("")
    out.append("// ---- constants")
    for k in ("algo_id_mldsa44", "pubkey_len", "seckey_len", "sig_len", "seed_len", "op_checkpqsig",
              "sighash_all", "max_pq_element_size", "scriptsig_len", "input_len", "tx26_serialized_len"):
        out.append(f"static const uint32_t {k.upper()} = {c[k]};")
    for k in ("tag_pqkh", "tag_sighash", "tag_seed", "ctx_tx", "address_prefix_main", "address_prefix_test"):
        out.append(f"static const char* const {k.upper()} = {cstr(c[k])};")
    out.append(f"static const char* const ADDRESS_EXAMPLE_PQKH_00 = {cstr(c['address_examples']['pqkh_00'])};")
    out.append(f"static const char* const ADDRESS_EXAMPLE_PQKH_FF = {cstr(c['address_examples']['pqkh_ff'])};")
    out.append("")
    out.append("// ---- derivation")
    out.append("struct DerivationVector {")
    out.append("    const char* master_seed; uint32_t index; const char* xi; const char* pubkey; const char* seckey_sha256;")
    out.append("    const char* keyblob_sha256; const char* pqkh; const char* scriptPubKey; const char* address_main; const char* address_test;")
    out.append("};")
    out.append("static const DerivationVector DERIVATION[] = {")
    for d in v["derivation"]:
        out.append("    {" + ", ".join([cstr(d["master_seed"]), str(d["index"]), cstr(d["xi"]), cstr(d["pubkey"]), cstr(d["seckey_sha256"]),
                                        cstr(d["keyblob_sha256"]), cstr(d["pqkh"]), cstr(d["scriptPubKey"]), cstr(d["address_main"]), cstr(d["address_test"])]) + "},")
    out.append("};")
    out.append(f"static const size_t DERIVATION_COUNT = {len(v['derivation'])};")
    out.append("")
    out.append("// ---- sighash transactions")
    out.append("struct Prevout { int64_t amount; const char* scriptPubKey; };")
    out.append("struct InputVector {")
    out.append("    uint32_t input; uint32_t key_index; int64_t amount; const char* scriptCode; const char* digest; const char* sig;")
    out.append("    const char* preimage; /* nullptr when absent */ const char* scriptSig; /* nullptr when absent */")
    out.append("};")
    out.append("struct TxVector {")
    out.append("    const char* label; const unsigned char* tx; size_t tx_len; const char* txid;")
    out.append("    const Prevout* prevouts; size_t n_prevouts; const InputVector* inputs; size_t n_inputs;")
    out.append("};")
    for i, s in enumerate(v["sighash"]):
        byte_array(f"SIGHASH_TX{i}", s["tx"], out)
        out.append(f"static const Prevout SIGHASH_TX{i}_PREVOUTS[] = {{")
        for p in s["prevouts"]:
            out.append(f"    {{{p['amount']}LL, {cstr(p['scriptPubKey'])}}},")
        out.append("};")
        out.append(f"static const InputVector SIGHASH_TX{i}_INPUTS[] = {{")
        for r in s["inputs"]:
            pre = cstr(r["preimage"]) if "preimage" in r else "nullptr"
            ssig = cstr(r["scriptSig"]) if "scriptSig" in r else "nullptr"
            out.append("    {" + ", ".join([str(r["input"]), str(r["key_index"]), f"{r['amount']}LL", cstr(r["scriptCode"]), cstr(r["digest"]), cstr(r["sig"]), pre, ssig]) + "},")
        out.append("};")
    out.append("static const TxVector SIGHASH[] = {")
    for i, s in enumerate(v["sighash"]):
        out.append(f"    {{{cstr(s['label'])}, SIGHASH_TX{i}, SIGHASH_TX{i}_LEN, {cstr(s['txid'])}, SIGHASH_TX{i}_PREVOUTS, {len(s['prevouts'])}, SIGHASH_TX{i}_INPUTS, {len(s['inputs'])}}},")
    out.append("};")
    out.append(f"static const size_t SIGHASH_COUNT = {len(v['sighash'])};")
    out.append("")
    out.append("// ---- spend cases")
    out.append("struct SpendVector {")
    out.append("    const char* label; int tx_ref; /* index into SIGHASH, or -1 when tx is given */ const unsigned char* tx; size_t tx_len;")
    out.append("    uint32_t input; int64_t amount; const char* scriptPubKey; const char* expect; const char* sigversion; /* nullptr = PQ */")
    out.append("};")
    own = 0
    names = []
    for s in v["spend"]:
        if "tx" in s:
            name = f"SPEND_TX{own}"
            own += 1
            byte_array(name, s["tx"], out)
            names.append(name)
        else:
            names.append(None)
    out.append("static const SpendVector SPEND[] = {")
    for s, name in zip(v["spend"], names):
        tx_ref = s.get("tx_ref", -1)
        txp = name if name else "nullptr"
        txl = f"{name}_LEN" if name else "0"
        sv = cstr(s["sigversion"]) if "sigversion" in s else "nullptr"
        out.append("    {" + ", ".join([cstr(s["label"]), str(tx_ref), txp, txl, str(s["input"]), f"{s['amount']}LL", cstr(s["scriptPubKey"]), cstr(s["expect"]), sv]) + "},")
    out.append("};")
    out.append(f"static const size_t SPEND_COUNT = {len(v['spend'])};")
    out.append("")
    out.append("} // namespace pqsig_vectors")
    out.append("")
    out.append("#endif // BITCOIN_TEST_PQSIG_VECTOR_DATA_H")
    with open(OUT, "w", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {OUT}: {len(v['derivation'])} derivation, {len(v['sighash'])} sighash txs, {len(v['spend'])} spend cases")


if __name__ == "__main__":
    main()
