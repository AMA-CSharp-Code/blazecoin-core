#!/usr/bin/env python3
"""
Select the ML-DSA-44 known-answer vectors this tree can exercise from NIST's ACVP-Server files and write them to
test/pqsig/mldsa44_acvp_vectors.json (committed). The ACVP files themselves (about 14 MB) are not committed.

Source (NIST, public domain):
  https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/
    ML-DSA-keyGen-FIPS204/internalProjection.json
    ML-DSA-sigGen-FIPS204/internalProjection.json
    ML-DSA-sigVer-FIPS204/internalProjection.json

Usage:  python test/pqsig/import_acvp_mldsa44.py <dir with keyGen.json sigGen.json sigVer.json>

What is kept (parameter set ML-DSA-44 only):
  keyGen            every case: seed -> (pk, sk)                                   -> mldsa44::KeyGenFromSeed
  sigGen external   signatureInterface=external, preHash=pure:
                    deterministic (rnd = 0^32)                                       -> mldsa44::Sign
                    hedged (rnd given)                                               -> crypto_sign_signature_internal
  sigGen internal   signatureInterface=internal, externalMu=false (no domain separator, empty prefix):
                    deterministic and hedged                                         -> crypto_sign_signature_internal
  sigVer external   signatureInterface=external, preHash=pure, with the pass/fail reason -> mldsa44::Verify
  sigVer internal   signatureInterface=internal, externalMu=false                       -> crypto_sign_verify_internal
Not kept: preHash=preHash (HashML-DSA) and externalMu=true groups; the vendored reference code exposes neither.

To keep the generated C header a reasonable size, signing and verification cases are capped per group and the
longest messages are dropped first (a message's length does not change what the test proves). Every kept case
keeps its ACVP tgId/tcId so a reader can find it in NIST's file.
"""
import json
import os
import sys
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "mldsa44_acvp_vectors.json")
PARAM_SET = "ML-DSA-44"
# per-group caps (cases kept, shortest messages first)
CAP_SIGGEN_EXT = 8
CAP_SIGGEN_INT = 4
CAP_SIGVER = 15      # all: the failure reasons are the valuable part


def load(d, name):
    with open(os.path.join(d, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def groups(j, **want):
    for g in j["testGroups"]:
        if g.get("parameterSet") != PARAM_SET:
            continue
        if all(g.get(k) == v for k, v in want.items()):
            yield g


def shortest(tests, cap):
    return sorted(tests, key=lambda t: (len(t.get("message", "")), t["tcId"]))[:cap]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    d = sys.argv[1]
    kg, sg, sv = load(d, "keyGen"), load(d, "sigGen"), load(d, "sigVer")
    out = {
        "source": "NIST ACVP-Server gen-val/json-files, ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json",
        "source_url": "https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files",
        "algorithm": sg["algorithm"], "revision": sg["revision"], "vsId": {"keyGen": kg["vsId"], "sigGen": sg["vsId"], "sigVer": sv["vsId"]},
        "parameter_set": PARAM_SET, "imported": date.today().isoformat(),
        "selection": {"keygen": "all", "siggen_external_pure": f"{CAP_SIGGEN_EXT} shortest messages per group (deterministic, hedged)",
                      "siggen_internal": f"{CAP_SIGGEN_INT} shortest per group (deterministic, hedged)", "sigver": "all cases of the external/pure and internal groups",
                      "skipped": "preHash=preHash and externalMu=true groups"},
        "keygen": [], "siggen": [], "sigver": [],
    }
    for g in groups(kg):
        for t in g["tests"]:
            out["keygen"].append({"tgId": g["tgId"], "tcId": t["tcId"], "seed": t["seed"], "pk": t["pk"], "sk": t["sk"]})
    for iface, cap in (("external", CAP_SIGGEN_EXT), ("internal", CAP_SIGGEN_INT)):
        for det in (True, False):
            want = {"signatureInterface": iface, "deterministic": det, "externalMu": False}
            if iface == "external":
                want["preHash"] = "pure"
            for g in groups(sg, **want):
                for t in shortest(g["tests"], cap):
                    c = {"tgId": g["tgId"], "tcId": t["tcId"], "interface": iface, "deterministic": det,
                         "message": t["message"], "context": t.get("context", ""), "sk": t["sk"], "pk": t["pk"], "signature": t["signature"]}
                    if not det:
                        c["rnd"] = t["rnd"]
                    out["siggen"].append(c)
    for iface in ("external", "internal"):
        want = {"signatureInterface": iface, "externalMu": False}
        if iface == "external":
            want["preHash"] = "pure"
        for g in groups(sv, **want):
            for t in shortest(g["tests"], CAP_SIGVER):
                out["sigver"].append({"tgId": g["tgId"], "tcId": t["tcId"], "interface": iface, "message": t["message"],
                                      "context": t.get("context", ""), "pk": t["pk"], "signature": t["signature"],
                                      "testPassed": t["testPassed"], "reason": t["reason"]})
    with open(OUT, "w", newline="\n") as f:
        json.dump(out, f, indent=1)
    raw = sum(len(t["pk"] + t["sk"]) for t in out["keygen"]) // 2
    raw += sum(len(t["sk"] + t["pk"] + t["signature"] + t["message"]) for t in out["siggen"]) // 2
    raw += sum(len(t["pk"] + t["signature"] + t["message"]) for t in out["sigver"]) // 2
    print(f"wrote {OUT}: keygen {len(out['keygen'])}, siggen {len(out['siggen'])}, sigver {len(out['sigver'])}; "
          f"{os.path.getsize(OUT) / 1e6:.2f} MB json, {raw / 1e3:.0f} KB of vector bytes")


if __name__ == "__main__":
    main()
