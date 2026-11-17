#!/usr/bin/env python3
"""
Turn test/pqsig/mldsa44_acvp_vectors.json (NIST ACVP ML-DSA-44 cases, selected by import_acvp_mldsa44.py) into
src/test/mldsa44_acvp_data.h for src/test/mldsa44_kat_tests.cpp.

Usage (from the repo root):  python test/pqsig/gen_mldsa44_acvp_header.py

Fields are hex string literals, split into adjacent pieces under MSVC's per-literal limit (C2026); the test parses
them with ParseHex. The header is committed so the Boost build needs no Python.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SRC_JSON = os.path.join(HERE, "mldsa44_acvp_vectors.json")
OUT = os.path.join(ROOT, "src", "test", "mldsa44_acvp_data.h")
CHUNK = 8000  # chars per literal piece


def hexlit(s):
    if s == "":
        return '""'
    return " ".join('"' + s[i:i + CHUNK] + '"' for i in range(0, len(s), CHUNK))


def main():
    with open(SRC_JSON) as f:
        v = json.load(f)
    out = []
    out.append("// GENERATED FILE - DO NOT EDIT.")
    out.append("// Source: test/pqsig/mldsa44_acvp_vectors.json = NIST ACVP-Server ML-DSA FIPS 204 known-answer cases")
    out.append(f"// ({v['source']}; vsId keyGen {v['vsId']['keyGen']}, sigGen {v['vsId']['sigGen']}, sigVer {v['vsId']['sigVer']};")
    out.append(f"// imported {v['imported']} by test/pqsig/import_acvp_mldsa44.py). Regenerate with: python test/pqsig/gen_mldsa44_acvp_header.py")
    out.append("#ifndef BITCOIN_TEST_MLDSA44_ACVP_DATA_H")
    out.append("#define BITCOIN_TEST_MLDSA44_ACVP_DATA_H")
    out.append("")
    out.append("#include <cstddef>")
    out.append("#include <cstdint>")
    out.append("")
    out.append("namespace mldsa44_acvp {")
    out.append("")
    out.append(f"static const char* const SOURCE_URL = \"{v['source_url']}\";")
    out.append(f"static const char* const REVISION = \"{v['revision']}\";")
    out.append("")
    out.append("struct KeyGenVector { uint32_t tgId; uint32_t tcId; const char* seed; const char* pk; const char* sk; };")
    out.append("static const KeyGenVector KEYGEN[] = {")
    for t in v["keygen"]:
        out.append(f"    {{{t['tgId']}, {t['tcId']}, {hexlit(t['seed'])}, {hexlit(t['pk'])}, {hexlit(t['sk'])}}},")
    out.append("};")
    out.append(f"static const size_t KEYGEN_COUNT = {len(v['keygen'])};")
    out.append("")
    out.append("/** rnd is nullptr for deterministic cases (rnd = 32 zero bytes); internal = the ACVP internal interface (no")
    out.append(" *  domain-separator prefix), otherwise external/pure with the FIPS 204 prefix 0x00 || len(ctx) || ctx. */")
    out.append("struct SigGenVector {")
    out.append("    uint32_t tgId; uint32_t tcId; bool internal; bool deterministic; const char* message; const char* context;")
    out.append("    const char* sk; const char* pk; const char* signature; const char* rnd;")
    out.append("};")
    out.append("static const SigGenVector SIGGEN[] = {")
    for t in v["siggen"]:
        rnd = hexlit(t["rnd"]) if "rnd" in t else "nullptr"
        out.append("    {" + ", ".join([str(t["tgId"]), str(t["tcId"]), "true" if t["interface"] == "internal" else "false",
                                        "true" if t["deterministic"] else "false", hexlit(t["message"]), hexlit(t["context"]),
                                        hexlit(t["sk"]), hexlit(t["pk"]), hexlit(t["signature"]), rnd]) + "},")
    out.append("};")
    out.append(f"static const size_t SIGGEN_COUNT = {len(v['siggen'])};")
    out.append("")
    out.append("struct SigVerVector {")
    out.append("    uint32_t tgId; uint32_t tcId; bool internal; const char* message; const char* context; const char* pk;")
    out.append("    const char* signature; bool testPassed; const char* reason;")
    out.append("};")
    out.append("static const SigVerVector SIGVER[] = {")
    for t in v["sigver"]:
        out.append("    {" + ", ".join([str(t["tgId"]), str(t["tcId"]), "true" if t["interface"] == "internal" else "false",
                                        hexlit(t["message"]), hexlit(t["context"]), hexlit(t["pk"]), hexlit(t["signature"]),
                                        "true" if t["testPassed"] else "false", '"' + t["reason"].replace('"', '\\"') + '"']) + "},")
    out.append("};")
    out.append(f"static const size_t SIGVER_COUNT = {len(v['sigver'])};")
    out.append("")
    out.append("} // namespace mldsa44_acvp")
    out.append("")
    out.append("#endif // BITCOIN_TEST_MLDSA44_ACVP_DATA_H")
    with open(OUT, "w", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {OUT}: {len(v['keygen'])} keygen, {len(v['siggen'])} siggen, {len(v['sigver'])} sigver, {os.path.getsize(OUT) / 1e6:.2f} MB")


if __name__ == "__main__":
    main()
