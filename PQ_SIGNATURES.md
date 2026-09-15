# PQ Signatures — a post-quantum output type for Blazecoin (proposal)

> **Status: SPECIFICATION drafted 2026-09-14; ALL 13 DECISIONS IN §13 RATIFIED BY ANDREW 2026-09-14 (scheme, no hybrid, `BQ` prefix, opcode `0xba`, sigop weight 50, months of lead time + V1.5 retirement, codename left to marketing, lite-wallet PQ receive after activation, the digest, the 5,000-byte PQ push cap, seed-derived keys with BouncyCastle as the C# implementation of record, the migration order, the Python vector authority). BUILT 2026-09-14/15 and merged — §15 is the as-built record. **`H_Q` = 4,250,000, chosen by Andrew 2026-09-15 07:00 ("go for block 4,250,000"; ~25 h ahead of the tip at the time, ~1 day of notice — the sole-miner exemption of §7). Rollout record in §15.**
> Post-quantum plan item 3 (plan of record: MAUI `ROADMAP.md` §G; item 1 = the wallet's Quantum
> Exposure page, shipped; item 2 = key rotation, `docs/KEY_ROTATION.md` in the website repo, built
> 2026-09-13; item 4 = the benchmark library, **built 2026-09-14** — `BlazecoinWallet.PqBench` in the MAUI
> repo, results in its `docs/PQ_BENCHMARK.md`; the measured figures are the ones in §2 and §4 below).
> Written PHOENIX_413-style — the shape that carried the chain's first consensus change through
> in a day — because this would be the **second consensus change, an order of magnitude bigger**,
> and the decisions here are the ones that are expensive to change later.
>
> **Identity in one line:** a new output type, `P2PQH` ("pay to post-quantum key hash"), whose
> spend is authorised by an **ML-DSA-44** (FIPS 204) signature over a BIP-143-style transaction
> digest, carried in a legacy-format scriptSig under a new opcode, activated by a **hard fork at a
> flag height `H_Q`** that retires V1.5. The key blob commits to an **algorithm-ID byte**, so
> ML-DSA-65/87 or a future FIPS scheme can be added without another address format. Addresses
> start with **`BQ`**.
>
> **Wording rule (unchanged):** with this spec in existence the site may say *"designed with a
> defined post-quantum migration path"*. It may not say *"quantum hardened"* until `H_Q` has passed
> and the treasury has moved.

---

## 0. The threat, precisely

A P2PKH output commits to `HASH160(pubkey)`; the ECDSA public key itself becomes public **the
first time the address spends** (it sits in that input's scriptSig for ever). A cryptographically
relevant quantum computer (CRQC) running Shor's algorithm turns an exposed secp256k1 public key
into its private key. It can do nothing with a hash alone.

Two attack classes, borrowed from BIP-360's framing:

- **Long exposure** — keys already public on-chain (every address that has ever spent, every
  reused address). The attacker has years. **This is the class that matters for Blazecoin:** the
  operational wallets reuse keys by construction (item 2 is closing that), and twelve years of
  history has exposed most keys that ever held coin. The wallet's 2026-09-12 scan of the payout
  wallet alone found 1,130 distinct public keys on-chain.
- **Short exposure** — a key revealed in a transaction that is still unconfirmed, attacked inside
  the confirmation window. Needs a CRQC fast enough to break a key in seconds; BIP-360's own
  judgement is that early CRQCs will not be. With 30-second blocks Blazecoin's window is short.

**What is NOT threatened:** the scrypt proof-of-work (Grover is only quadratic; Phoenix-413's
per-block retarget absorbs any speed-up as ordinary hashrate), block hashes, txids, Merkle trees
(SHA256d — Grover again), HD seeds and BIP39 mnemonics (symmetric material), wallet encryption.
Only **signatures** — and therefore only coins on outputs whose key is, or becomes, public.

**Timeline anchor:** NIST IR 8547 (Nov 2024 draft) deprecates 112-bit-security ECC (secp256k1
falls in this class) by 2030 and disallows it by 2035. That is the planning horizon, not a
prediction of a CRQC.

## 1. Constraints specific to this chain (why this is not simply BIP-360)

| Constraint | Consequence |
|---|---|
| **Segwit / Taproot are consensus-disabled** (`SegwitHeight = INT_MAX`, BIP-341/342 never active; `BLAZECOIN_V2.md`) | There is **no witness to extend and no tapscript to put a new opcode in.** BIP-360 (P2MR) is a segwit-v2 output that requires BIPs 340–342; it cannot be ported as-is. What we port is its *decision structure*: a hash-only commitment, PQ signatures behind an explicit versioned envelope, long-exposure protection first. |
| `MAX_SCRIPT_ELEMENT_SIZE = 520` is enforced inside the interpreter (consensus for every push) | An ML-DSA-44 signature (2,420 B) and public key (1,312 B) cannot be pushed in a legacy script. The rule must be relaxed **only for inputs spending the new template** — a hard-fork change, not a NOP-upgrade soft fork. |
| Block capacity ≈ **1,000,000 B** serialized (weight 4 M with `WITNESS_SCALE_FACTOR` 4 and no witness data) | A PQ input costs ~3.8 KB (§4): ~260 all-PQ inputs per block, ~750,000 per day at 2,880 blocks. Plenty for this chain's volume; it bounds batch sizes for the nightly consolidation. |
| 30 s blocks, per-block ASERT retarget | Short-exposure window is small; nothing to change. |
| **Single operator runs every node** (3 home daemons, 2 OVH relays, 3 T630 VM nodes, the blade) | A **flag-height hard fork** is honest and practical — Phoenix-413 proved the rollout in one day. No BIP9, no miner signalling. |
| Three wallet generations: Original 0.8.6.2 (archived), **V1.5** (0.8-lineage, kept alive through Phoenix as V1.5.2), V2 (Core 28) | V1.5 cannot learn a new opcode, a relaxed push limit or a new sighash without a rewrite of its script engine. **Decision (§7): this fork retires V1.5.** V1.5 nodes freeze at `H_Q`; funds stay safe (keys and UTXOs unchanged); recovery = import into V2. |
| Fee floors are zero (`minrelaytxfee` / `blockmintxfee = 0`, legacy free-send compat) | Large PQ transactions are free like everything else; the 1 MB block bounds abuse exactly as today. No new fee rule in v1. |
| Lite wallets verify the chain themselves (header spine + trustless input verification) and **sign on-device in C#** | Every consensus rule here needs a **C# twin**, and every C# head must ship before `H_Q` — the Phoenix "hidden half", again. |

## 2. Choice of scheme

**ML-DSA-44 (FIPS 204, final August 2024), single-signature, no hybrid.**

| Scheme | Public key | Signature | Security cat. | Status | Verdict |
|---|---|---|---|---|---|
| **ML-DSA-44** | 1,312 B | 2,420 B | 2 (≈ AES-128) | FIPS 204 final | **First algorithm ID.** Best size/speed trade (measured verify **132 µs**, sign 537 µs, managed BouncyCastle, single core — faster than the wallet's managed ECDSA verify); NIST's primary lattice signature; in .NET 10 BCL, BouncyCastle 2.6.2 (already a wallet dependency), OpenSSL 3.5, liboqs, and the reference C code. |
| ML-DSA-65 | 1,952 B | 3,309 B | 3 | FIPS 204 final | Reserved ID 2. 5,311 B/input, verify 192 µs. |
| ML-DSA-87 | 2,592 B | 4,627 B | 5 | FIPS 204 final | Reserved ID 3. 7,269 B/input caps a 1 MB block at 137 inputs — the nightly sweep would not fit its batches; verify 303 µs; not first. |
| SLH-DSA-SHA2-128s | 32 B | 7,856 B | 1 | FIPS 205 final | Hash-based, most conservative assumptions, but 7,936 B per input and **835 ms per signature** (measured; a 12-input transaction signs in 10 s). Reserved ID 4 as the "lattice-failure" fallback only. |
| FN-DSA-512 (Falcon) | 897 B | ~666 B | 1 | FIPS 206 **draft** | Smallest by far, but not final, and its floating-point signing is the classic implementation hazard. Reserve an ID (5) once FIPS 206 is final; not now. |

Why **no hybrid (ECDSA + ML-DSA in one spend):** the purpose of the output type is to stop
depending on ECDSA; a hybrid keeps an ECDSA key in every spend and doubles the exposure surface
for no security gain once ECDSA falls. The hedge against an ML-DSA implementation bug is the
**algorithm-ID byte** plus reserved IDs, not a second classical signature in every input. (BIP-360
reaches the same place from the other side: the hash commitment protects against long exposure
*before* any PQ signature exists.)

Why **ML-DSA and not a hash-committed script tree (P2MR proper):** P2MR's long-exposure protection
comes from never exposing a key path — but its script paths still end in a *classical* signature
until a PQ opcode exists, so on its own it moves exposure from "first spend" to "first spend of that
leaf". Blazecoin has no tapscript to host leaves anyway. Doing the signature scheme first and
keeping the output a plain hash commitment is the smaller, self-contained change for this chain.

## 3. The output type — `P2PQH`

### 3.1 Key blob and commitment

```
keyblob  = algo_id (1 byte) || pubkey (algo-dependent length)
             algo_id 0x01 = ML-DSA-44 (1,312-byte pubkey)      — THIS SPEC
             algo_id 0x02 = ML-DSA-65 (1,952)                   — reserved, not active
             algo_id 0x03 = ML-DSA-87 (2,592)                   — reserved, not active
             algo_id 0x04 = SLH-DSA-SHA2-128s (32)              — reserved, not active
             algo_id 0x05 = FN-DSA-512 (897)                    — reserved pending FIPS 206
pqkh     = TaggedHash("Blazecoin/PQKH/v1", keyblob)             (32 bytes)
```

`TaggedHash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)` — the BIP-340 construction, so
the C# side can reuse its existing tagged-hash helper. Committing to the **algorithm ID inside the
hash** is what gives crypto-agility without a second address format: an output does not reveal
which algorithm will spend it, and a spender cannot substitute a weaker algorithm for the one the
key was generated under.

### 3.2 scriptPubKey (34 bytes)

```
0x20 <pqkh:32> OP_CHECKPQSIG
```

- `OP_CHECKPQSIG` = opcode **`0xba`**, today one past `MAX_OPCODE` (`OP_NOP10 = 0xb9`) and therefore
  **"bad opcode"** in every current interpreter (V2 and V1.5 alike). It is *not* a redefined NOP:
  the template is unspendable before activation rather than anyone-can-spend, which is the safer
  failure (§3.6).
  *Implementation note (2026-09-14):* Core 28 already names `0xba` `OP_CHECKSIGADD` for Tapscript. Taproot
  and segwit are `NEVER_ACTIVE` on Blazecoin mainnet/testnet, so Tapscript can never execute there; the
  byte keeps both names and its meaning is selected by the interpreter context — `SigVersion::PQ` →
  `OP_CHECKPQSIG`, `TAPSCRIPT` → unchanged (regtest keeps Taproot for the upstream vectors), `BASE` /
  `WITNESS_V0` → bad opcode, exactly as before.
- Template recognition (for `IsStandard`, `ExtractDestination`, the indexer, the pool) is exact:
  length 34, `[0] == 0x20`, `[33] == 0xba`.

### 3.3 scriptSig (spend)

```
<sig:2,420> <keyblob:1,313>          — exactly two pushes, push-only, no other opcodes
```

Serialized: `OP_PUSHDATA2 74 09 <sig>` (3 + 2,420) + `OP_PUSHDATA2 21 05 <keyblob>` (3 + 1,313)
= **3,739 bytes** of scriptSig; with outpoint (36), scriptSig length varint (3) and sequence (4)
one ML-DSA-44 input is **3,782 bytes**.

### 3.4 Verification (consensus, for an input whose prevout is a P2PQH template)

1. **Context:** the interpreter runs in a new `SigVersion::PQ` (beside `BASE`, `WITNESS_V0`,
   `TAPSCRIPT`), chosen by the caller from the prevout's scriptPubKey template — the same way
   segwit picks its version from the program. In this context:
   - `MAX_SCRIPT_ELEMENT_SIZE` is **5,000** (room for ML-DSA-87's 4,627-byte signature under a
     future ID) instead of 520;
   - the scriptSig must be push-only and leave **exactly two** stack elements (consensus, not just
     policy);
   - `OP_CHECKPQSIG` is defined; in `SigVersion::BASE` it stays "bad opcode".
2. `OP_CHECKPQSIG` pops `pqkh`, `keyblob`, `sig` (top first: `pqkh` was pushed by scriptPubKey).
3. `TaggedHash("Blazecoin/PQKH/v1", keyblob) == pqkh`, else fail.
4. `keyblob[0]` must be an **active** algorithm ID (v1: only `0x01`); pubkey length must match the
   algorithm exactly; a reserved-but-inactive ID fails (a future fork activates it — see §3.7).
5. `msg = PQSigHash(tx, input_index, prevout.amount, prevout.scriptPubKey)` (§3.5).
6. `ML-DSA-44.Verify(pubkey, msg, sig, ctx = "blazecoin-tx-v1")` per FIPS 204 §5.3 — the
   **context string** is the algorithm-level domain separation FIPS 204 provides for exactly this
   purpose; it makes a Blazecoin transaction signature unusable as a signature over anything else,
   even for an application that reuses the key.
7. Push `true`. Failure anywhere = script failure (never "unknown/anyone-can-spend").

Signature verification results are cached in the existing script cache (keyed by txid + flags),
so a transaction verified at mempool acceptance is not re-verified at block connect.

### 3.5 The digest — `PQSigHash` (BIP-143 shape, tagged)

```
preimage =
    nVersion            (4, LE)
    hashPrevouts        (32)  = SHA256d(all outpoints)
    hashSequence        (32)  = SHA256d(all nSequence)
    outpoint            (36)  this input's
    scriptCode          (varint-length + the 34-byte P2PQH scriptPubKey being spent)
    amount              (8, LE) this input's prevout value in satoshi
    nSequence           (4, LE) this input's
    hashOutputs         (32)  = SHA256d(all outputs serialized)
    nLockTime           (4, LE)
    sighash_type        (4, LE) = 0x00000001 (SIGHASH_ALL)  — the only type in v1
msg = TaggedHash("Blazecoin/PQSig/v1", preimage)                (32 bytes)
```

Why this and not the legacy `SignatureHash`: it commits to the **amount** (hardware/lite signers
can prove fees without the parent transactions — the lite wallet's trustless input verification
already fetches amounts), it is **O(n)** per transaction instead of the legacy O(n²) hashing, and it
has no `SIGHASH_SINGLE` bug. `SIGHASH_ALL` only in v1: `NONE`/`SINGLE`/`ANYONECANPAY` add
malleability surface for use cases this chain does not have; they can be added under the same
`sighash_type` field later without changing the envelope.

### 3.6 Before activation

- Creating a P2PQH output is valid at any height (a scriptPubKey is not executed on creation), but
  **non-standard** until `H_Q` (not relayed, not in `getblocktemplate`), and the daemon wallet
  refuses to pay a `BQ` address before `H_Q`. Anything that reaches the chain earlier anyway is
  **unspendable until `H_Q`** — not stolen; that is why `0xba`, not a NOP, was chosen.
- Spending a P2PQH output before `H_Q` fails (bad opcode / push size) in every node.

### 3.7 After activation — what a later fork can change without a new address format

Activate a reserved `algo_id` (§3.4 step 4), raise the PQ element-size cap, add sighash types.
Each is a consensus change with its own flag height; the address, the template and the hash
commitment stay. A key generated under `0x01` is only ever spendable under `0x01`.

## 4. Sizes, limits, cost

| | ECDSA P2PKH today | **ML-DSA-44 P2PQH** | ML-DSA-87 (reserved) |
|---|---|---|---|
| scriptPubKey | 25 B | 34 B | 34 B |
| Input (outpoint + scriptSig + seq) | 148 B | **3,782 B** | 7,269 B |
| Inputs per 1 MB block (all-input tx) | ~6,700 | **~264** | ~137 |
| Inputs per day (2,880 blocks) | ~19 M | **~760 k** | ~395 k |
| Nightly consolidation, 40 batches × 150 inputs | ~890 KB total | **~22.7 MB ≈ 23 blocks** (0.8 % of a day) | ~44 MB |
| Verify, measured 2026-09-14 (managed BouncyCastle, one EPYC core; MAUI `docs/PQ_BENCHMARK.md`) | 254 µs (NBitcoin managed; native libsecp256k1 in the daemon is ~5× faster) | **132 µs** — a full 264-input block ≈ **35 ms** | 303 µs — a full 137-input block ≈ 42 ms |
| Sign, measured | 783 µs (managed) | **537 µs** — a 26-input standard tx ≈ 14 ms | 869 µs |

Standard transaction size limit (`MAX_STANDARD_TX_WEIGHT` 400,000 ⇒ 100 KB serialized) admits
**26 ML-DSA-44 inputs per standard transaction**; the consolidation runbook's `-BatchSize` must
drop from 150 to ≤ 26 for PQ inputs (its `MAX_STANDARD_TX_BYTES` assert already refuses larger).
Sigops: `OP_CHECKPQSIG` counts as **50 legacy sigops** toward `MAX_BLOCK_SIGOPS_COST` (80,000 ⇒
1,600 PQ verifications per block, ~6× the byte-limited maximum — the byte limit binds first; the
sigop weight is a belt-and-braces bound on verification time: at the measured 132 µs, 1,600 verifications
are ~0.2 s, so 50 is very conservative and could drop to 20 without risk).

Storage: at Blazecoin's real volume (a few hundred transactions a day, most of them the pool's) the
UTXO set and chain growth stay negligible; a fully PQ chain at today's rate adds well under 1 GB a
year.

## 5. Addresses

**Base58Check with a two-byte version prefix `0x46 0x50`** over the 32-byte `pqkh`:
`Base58Check(0x46 || 0x50 || pqkh)` — **52 characters, always starting `BQ`** (verified across
the whole payload range). Examples for `pqkh = 0x00…00` and `0xff…ff`:

```
BQGeaQmsowAjL1ZG8q1AfVH4NgBvtJKJSsjnnKEf62BMjekdU82n
BQJbKb1KqnbQZ9NqqjanfSbf9bJYbx29KfNrtZPLz1qN89DPR4Hh
```

Why base58check and not bech32m: the chain's whole tooling, docs and user habit are "an address
starts with `B`"; a `BQ…` address keeps that, needs no new checksum code in three languages, and
cannot be mistaken by a segwit-aware library for a witness program (a `blz1…` bech32m string would
be, and this chain has no segwit to decode it against). The 4-byte double-SHA256 checksum is the
same protection every existing address has. Testnet/regtest/testnet4/signet: `0xb2 0x73` — renders **`TQ…`**, 52 chars, stable across the
payload range (chosen at implementation 2026-09-14; pinned by the vectors' `address_test`).

`validateaddress` / `getaddressinfo` report `"type": "pqkh"`, `"algorithm": "ML-DSA-44"`; the
explorer shows a **PQ** badge; the wallet's Quantum Exposure page classifies `BQ` outputs as
*post-quantum* (never "exposed", since the key hash reveals nothing on spend that Shor can use).

## 6. Keys, wallets and derivation (the C++ / C# twin)

ML-DSA key generation is deterministic from a 32-byte seed ξ (FIPS 204 `ML-DSA.KeyGen_internal`).
Every wallet therefore derives PQ keys **from the seed it already backs up**, so no backup format
changes and an existing backup already covers future PQ addresses:

```
ξ_i = TaggedHash("Blazecoin/MLDSA44/seed", master_seed || uint32_le(i))
(pk_i, sk_i) = ML-DSA-44.KeyGen_internal(ξ_i)
```

- **V2 daemon (Core 28 descriptor wallet):** a new descriptor `pqkh(mldsa44:<hex master>/*)` with
  `master_seed` = the wallet's existing HD seed passed through
  `TaggedHash("Blazecoin/PQ/master", k || chain)` with `k` = the 32-byte BIP32 master private key and `chain` = `0x00` receive / `0x01` change (as built — §15); keypool, `getnewaddress "label" "pq"`, `ismine`,
  `listunspent`, PSBT field for the PQ signature (proprietary key type `0xfc "blz" 0x01`), the
  raw-tx path (`createrawtransaction` / `signrawtransactionwithwallet` — the consolidation script
  needs nothing new beyond `-BatchSize`). Secret keys stored in the SQLite wallet like any other
  descriptor key; wallet encryption unchanged.
- **Lite wallet (C#, on-device, BIP39):** `master_seed` = `HMAC-SHA512(key = "Blazecoin PQ", data = the 64-byte BIP39 seed)[0:32]` (BIP32 convention: the constant is the HMAC key; built 2026-09-14)
  (the mnemonic remains the single backup); BouncyCastle 2.6.2 `MLDsaSigner` /
  `MLDsaParameters.ml_dsa_44` (already referenced by `BlazecoinWallet.Core`), with .NET 10's BCL
  `System.Security.Cryptography.MLDsa` as the alternative once it leaves `[Experimental]`
  (SYSLIB5006) — Windows CNG PQC / OpenSSL 3.5 at runtime. Android: BouncyCastle (managed, no
  platform dependency).
- **MAUI desktop:** no signing role (RPC to the daemon); display + the Quantum page's sweep.
- **Pool coinbase:** the inbox wallet's epoch-address list (`Tools/New-CoinbaseAddressList.ps1`,
  KEY_ROTATION step 4) is regenerated as `BQ` addresses; `StratumCryptoHelpers.BuildScriptPubKeyFromAddress`
  learns the 2-byte version and emits the 34-byte template. Coinbase outputs are then PQ from the
  first post-fork block the operator chooses.

## 7. Activation and the V1.5 decision

- **Flag height `H_Q`** in `Consensus::Params` (`pqsigHeight`), buried deployment `DEPLOYMENT_PQSIG`
  next to `DEPLOYMENT_PHOENIX413`; regtest activates via the existing `-testactivationheight=pqsig@N`
  pattern (regtest stays upstream-tuned, DESIGN_AUDIT D1). **Hard fork:** blocks from `H_Q` on may
  contain inputs no pre-fork node can validate. **Activation boundary (as built, Core convention):** the
  flag applies to every block at height ≥ `H_Q` — a PQ spend is rejected in block `H_Q − 1` and accepted
  in block `H_Q`; the mempool switches for the next block, and `getdeploymentinfo` reports `active` for the
  next block, so it turns true at tip `H_Q − 1`.
- **Choosing `H_Q`:** every V2 daemon (home ×3, relays ×2, T630 VMs ×3, blade) and **every lite
  head** (WASM on gw/gw2, Android sideload) must run fork code first, with ≥ 2 weeks of margin; the
  Phoenix rule "the miner stays OFF until every box runs fork code" applies again if the height is
  chosen near the tip. A round or memorable number; `H_A + 413 × k` is the obvious motif.
- **V1.5 (and Original) are retired by this fork — DECIDED here, to be ratified with `H_Q`.**
  V1.5.2's script engine is 0.8.6.2's: 520-byte pushes, no `0xba`, legacy sighash. Teaching it
  P2PQH means a new interpreter context, a new digest and an ML-DSA implementation against OpenSSL
  1.x-era code — a rewrite, not a patch, for a client whose only remaining purpose was to keep
  2014-lineage users on the network through Phoenix. At `H_Q` V1.5 nodes reject the first block
  containing a PQ spend and freeze; **funds are never at risk** (keys, UTXOs and the legacy
  transaction format are unchanged), and the migration path is the one that already exists:
  import the wallet into V2 (MAUI Import / lite WIF sweep). Communication = the Phoenix pattern:
  V1.5 README banner ("stops at `H_Q`; move to V2"), the Wallet page card set, the Bitcointalk
  lineage thread, and a **generous notice period** (months, not weeks — this time nobody is
  waiting on a stranded chain).
- **Rollback:** pre-`H_Q`, ordinary deploy rollback. Post-`H_Q`, reverting is itself a fork —
  acceptable only in the shadow of a consensus bug; the test plan exists so that path is never
  taken. The operator runs every node, so it stays *possible*.

### 7.1 Client update banner — "update required before block N" (added 2026-09-14; BUILT the same night, §15)

The lite heads are the one place a stale client can be *silent*: a V2 daemon that lacks fork code
simply stops at `H_Q` and the operator notices; a web-wallet tab or a sideloaded APK that lacks it
keeps showing a balance while its trustless verifier rejects every post-`H_Q` block that carries a
PQ spend — and Android has no store channel to push an update (Play deferred, sideload only). So the
notice must travel *inside the protocol the wallet already speaks*, not only on the website:

- **Announcement, served by the gateway.** The lite gateway's existing status/tip response gains
  three optional fields, all `null` until the operator sets them in gateway configuration
  (`Fork:Name`, `Fork:Height`, `Fork:MinClientVersion`): `forkName` (the codename, §13 open item 7),
  `forkHeight` (`H_Q`) and `minClientVersion` (the first lite build carrying the fork rules).
  gw and gw2 are configured identically; the operator sets the fields the day `H_Q` is chosen —
  months ahead, per the notice period above.
- **Behaviour in the head (WASM on gw/gw2 and Android alike).** Each build carries a constant
  `SupportedForks` (today: `phoenix413`; later: `+ pqsig`). On every tip poll the head compares its
  own version against `minClientVersion` and the tip against `forkHeight`, and renders **one**
  persistent banner above the balance, in three states:
  1. *Notice* (`forkHeight − tip` > 40,320 blocks, i.e. more than two weeks at 30 s):
     "**Update required before block N** (about D days). Your wallet (vX) will stop following the
     chain at that block. Get vY from blazecoin.co.uk/Wallet." Dismissible per session, returns
     on the next launch.
  2. *Warning* (within two weeks, or `minClientVersion` newer than the running build at any
     distance): same text, amber, not dismissible; Send still works.
  3. *Stopped* (tip ≥ `forkHeight` and the build lacks the fork rules): red, blocks Send and
     Receive-address generation, keeps the balance visible as *"last verified at block N"* — the
     verifier's honest state — with the download link. Funds are unaffected; the mnemonic restores
     into the new build.
  Days are derived from the 30-second target (`blocks ÷ 2,880`) and rounded down; block counts are
  the authority, never the calendar (Phoenix lesson).
- **The web head has one extra failure mode:** a cached WASM bundle. The banner code lives in the
  served page, and the service-worker/cache policy on gw/gw2 must let a redeploy reach open tabs;
  state 2 doubles as *"reload to update"* when `minClientVersion` is newer than the loaded bundle.
- **Ship the banner first, long before the fork code.** A banner only helps clients that already
  contain it. The mechanism (fields + rendering + tests) therefore goes into the *next* lite
  release after this note, with all three fields `null`, so that by the time `H_Q` is announced
  every client in the field can display it. This is the earliest deliverable on the whole
  programme and the cheapest — a day, including tests.
- **Test pins:** Lite.Core tests for the three states at the exact boundaries (`forkHeight − tip`
  = 40,321 / 40,320 / 0; `minClientVersion` equal / newer), `null` fields render nothing, and the
  §10.5 dress rehearsal drives a stale head through all three states against the regtest gateway.
- **What it is not:** not an auto-updater (Android sideload cannot be), not a kill switch (state 3
  only reflects what the verifier already does), and not a substitute for the website/Telegram
  notices — it is the copy of the notice that reaches the user who reads none of them.

## 8. Migration — what moves, in what order

The fork creates the option; **moving coin is what removes exposure**, and each move is the last
time an ECDSA key signs, so the KEY_ROTATION rule governs: *spend once, entirely, to a `BQ`
address, never pay the old address again.*

1. **Treasury vaults** (operator-held; wallet names and sizes withheld) - first, attended, straight from the encrypted vault wallets to fresh `BQ` addresses, one output per address.
2. **Operational wallets** (the payout wallet float, the inbox epoch addresses) — the pool's coinbase
   list becomes `BQ`; the nightly sweep's fresh destinations become `BQ`; the payout wallet's existing
   ECDSA UTXOs drain naturally through payouts and are replaced by PQ inputs from the sweep.
3. **Users** — the wallet's Quantum Exposure page gains *"sweep to a post-quantum address"*
   (desktop) and the lite wallet gains a `BQ` receive type + the same sweep; the account page's
   verified-address flow accepts `BQ` addresses (Identity's `VerifiedAddress` is a string; the
   signmessage ceremony needs an ML-DSA `signmessage`/`verifymessage` — a daemon RPC addition,
   same tagged-hash discipline, ctx `"blazecoin-msg-v1"`).
   *Checked 2026-09-14:* the five largest exposed balances that are NOT ours — `BY3ErQk2…` 46.3 M (active blocks
   1.10 M–2.40 M), `BYc5bzCp…` 24.3 M (2.05 M–2.40 M), `BgeJrRMm…` 16.9 M (0.54 M–2.40 M), `BZcYW2Xr…` 15.8 M
   (0.76 M–1.05 M), `BZuc3PZJ…` 10.3 M (1.55 M–3.22 M, 1.78 M transactions — a 2014-era pool) — have all been dormant
   for years (last activity around block 2.4 M ≈ 2016, the newest at 3.2 M ≈ 2018) and no loaded wallet owns them.
   They are the chain's long-exposure exposure and nobody can move them but their holders; the explorer figure
   is dominated by them (≈ 114 M of the 385 M).
4. **Never forced.** Legacy P2PKH stays valid for ever (BIP-360's "entirely voluntary" stance);
   the chain-wide exposed-BLZ figure on the explorer is how progress is measured — **built 2026-09-14**:
   Indexer `GET api/supply/quantum-exposure` (exposed = funded address that has ever spent; on this
   P2PKH-only chain that is exactly "key on-chain") and the Supply page's Quantum Exposure section.

## 9. Coupled work outside the daemon (the hidden half, larger than Phoenix's)

| Component | Change |
|---|---|
| **Lite wallet (C#, critical path)** | ✅ BUILT 2026-09-14 (`pq-lite-core`, §15) — **First: the §7.1 update banner** (`SupportedForks` constant, three-state rendering, tests) in the next lite release, fields still `null`. Then `BQ` address codec; P2PQH template recognition in the UTXO walker and trustless input verifier; `PQSigHash` + ML-DSA signing (BouncyCastle) on Send; key derivation §6; receive type; sweep. Ships **before `H_Q`** on gw/gw2 + Android. |
| **Indexer** | ✅ BUILT (`pq-address`) — Template → address extraction (new `pqkh` type), rich list / HODL / vintage attribution by address string unchanged, explorer PQ badge, `PoolDetector` unaffected (scriptSig tag lives in the coinbase input, which has no PQ material). |
| **Pool / solo proxy** | ✅ BUILT (`pq-address`) — Coinbase output template for `BQ` (2-byte version in `BuildScriptPubKeyFromAddress`); `Miner.PayoutAddress` validation accepts `BQ`; nothing else — the pool never signs. |
| **Payout API / Identity** | ✅ BUILT (`pq-address`; both gates default OFF) — Address validation accepts `BQ`; `sendmany` unchanged (the daemon signs); `IsValidPayoutAddress` twin; faucet return addresses may be `BQ`. |
| **MAUI desktop** | ✅ Quantum page `PostQuantum` status built; sweep-to-`BQ` owed — Display, Quantum page sweep-to-`BQ`, Provenance raw-tx path passes through. |
| **Gateway / web wallet** | ✅ BUILT (`pq-banner`) — Status/tip response gains `forkName` / `forkHeight` / `minClientVersion` from `Fork:*` configuration (§7.1; `null` until `H_Q` is chosen); cache policy must let a redeploy reach open tabs. CSP/import-map otherwise unaffected; the WASM head is the lite wallet. |
| **Docs** | `BLAZECOIN_V2.md` (fourth delta section + address row), `ECOSYSTEM.md` §1 addresses row (`B…` P2PKH **and** `BQ…` P2PQH), Wallet page, V1.5 README banner, this note → activation record. |

## 10. Test plan (bit-exactness across two languages, like Phoenix)

1. **Shared vectors `test/pqsig/`** (Python generator = semantic authority, mirrored into the
   MAUI repo; ✅ BUILT 2026-09-14 — see §15 for what the file contains): (a) **ML-DSA-44 KATs** — NIST ACVP `keyGen` (seed → pk/sk) and `sigVer` vectors,
   plus our own seed-derivation vectors (§6) so C++ and C# derive identical keys from identical
   seeds; (b) **`PQSigHash` vectors** — transactions with 1/2/26 inputs, mixed P2PKH + P2PQH,
   every field exercised (locktime, sequence, amounts), preimage and digest listed byte-for-byte;
   (c) **end-to-end spend vectors** — serialized transaction + prevouts → `valid` / `invalid` with
   the reason (wrong `pqkh`, inactive `algo_id`, wrong pubkey length, malformed push count, sig
   over the wrong digest, signature under the wrong `ctx`, pre-activation height). The generator
   uses a pure-Python FIPS 204 implementation (e.g. `dilithium-py` in ML-DSA mode) cross-checked
   against the ACVP set, so the authority is independent of both production implementations.
2. **C++ (daemon):** vendored reference ML-DSA (pq-crystals `ml-dsa` branch, C, constant-time, no
   AVX2 required — the same "port the reference, keep the constants ours" discipline as ASERT;
   consider liboqs later) under `src/crypto/mldsa/`; Boost `script_tests` / `sighash_tests` /
   `mldsa_tests` from the vectors; fuzz targets for the interpreter's PQ context and the key blob
   parser; `feature_blazecoin_pqsig.py` in **both** lists of `run_blazecoin_tests.py`: activation
   boundary (spend rejected in block `H_Q − 1`, accepted in block `H_Q` — §7), pre-activation creation is
   unspendable-until-`H_Q`, push-size relaxation applies only to PQ inputs, a 26-input standard
   transaction and a 264-input block, reorg across `H_Q`, wallet `getnewaddress "pq"` →
   `sendtoaddress` → `signrawtransactionwithwallet` round-trip.
3. **C# (lite):** Core.Tests against the same vectors (derivation, digest, verify, address codec);
   the trustless verifier accepts a PQ-spending block and rejects each invalid vector.
4. **Full gate:** `Deploy-BlazecoinV2.ps1` runs the whole Boost suite + the functional set before
   any binary reaches a daemon — no new deploy machinery.
5. **Dress rehearsal:** a throwaway regtest chain mined through a simulated `H_Q` with the real
   binaries, a lite head against a local gateway, the pool building a `BQ` coinbase, the
   consolidation script sweeping PQ coinbases with `-BatchSize 26`, and a treasury-style vault
   move — **before** the mainnet `H_Q` is chosen.

## 11. Effort (honest order of magnitude)

Phoenix-413 was ~400 lines of consensus code with a 45-vector file, done in a day. This is:
daemon ~3–4 weeks (vendor ML-DSA, interpreter context, digest, wallet descriptor/keys/RPC/PSBT,
tests); lite wallet ~2 weeks (+ ~1 day for the §7.1 banner, which ships first and separately); pool/indexer/payout/identity ~1 week; MAUI + docs + comms ~1 week;
plus the notice period for V1.5 retirement. Plan item 4 (the benchmark library) is done (2026-09-14):
the §4 figures are measurements, and its `BlazecoinWallet.PqBench` scheme wrappers (seeded ML-DSA
keygen, ctx-aware sign/verify, tagged-hash seed derivation) are the seed of the C# twin.

## 12. What this does not do

- It does not protect coins that stay on exposed keys — only moving them does (§8).
- It does not remove short-exposure risk for **legacy** inputs; a legacy spend still reveals an
  ECDSA key for the ~30 s it waits for a block. Only `BQ` outputs close that.
- It does not change PoW, block size, subsidy, emission, P2P encryption (no BIP324 here) or the
  premine's history.
- It does not make `signmessage` address verification post-quantum until the RPC twin in §8.3 ships.
- It does not touch regtest's Bitcoin-shaped defaults (D1).

## 13. Decisions — RATIFIED 2026-09-14 (Andrew: "All 13 agreed")

Every item below is now the decision of record; the spec's text is authoritative as written. Re-opening one is a
change request against this section, not a discussion.

1. **Ratify the scheme** — ML-DSA-44 first, IDs 2–5 reserved as tabled (§2). Or ML-DSA-65 first at
   +40 % size for category 3?
2. **Ratify "no hybrid"** (§2).
3. **Address prefix** — `BQ` via `0x46 0x50` (§5); alternative pairs giving `Bq` (`0x49 0x32…`) or `Qb`
   exist if a different look is wanted. Testnet prefix at implementation.
4. **Opcode number** — `0xba` (§3.2) vs redefining `OP_NOP10`; the spec argues `0xba` (fail-closed
   pre-activation).
5. **Sigop weight** for `OP_CHECKPQSIG` — 50 (§4) is very conservative against the measured 132 µs verify; 20 would still bound a block at ~0.5 s.
6. **`H_Q` lead time and the V1.5 notice period** (§7) — months; and whether the first
   post-fork coinbase is PQ immediately.
7. **Codename** — the Phoenix arc suggests something forged from ash (*Aegis-44*? *Adamant*?);
   marketing decides, the spec does not care.
8. **Whether the lite wallet ships PQ receive before or only after `H_Q`** (§3.6 argues after:
   paying a `BQ` address early parks coin until `H_Q`).


## 15. As-built record (2026-09-14 → 15, Andrew: "lets build it all today")

Everything below was built the same night the decisions were ratified, on branches, with the shared
vectors as the arbiter. **Nothing is merged to a main branch or deployed and no `H_Q` is chosen**
until the §10.5 dress rehearsal has run. Andrew floated `H_Q` = 4,246,000 that evening; that block
arrived the same night with no code on any node, so the answer was no — the height is picked after
the rehearsal, and sole-miner status lets it sit close to the tip when that day comes.

- **Vectors (§10.1)** — `test/pqsig/generate_pqsig_vectors.py` + `pqsig_vectors.json` (dilithium-py 1.4.0
  as the pure-Python FIPS 204 authority; the pq-crystals reference C (commit `d35ba3f`) was cross-checked
  against it byte-for-byte for seeded keygen and deterministic signing under `ctx` before anything else
  was written). 3 derivation keys, 3 signed transactions (1 / 1+2 / 26 inputs, locktime, sequences,
  amounts), 40 spend cases each with a named verdict. Compiled into `src/test/pqsig_vector_data.h`;
  copied into the MAUI repo's `Lite.Core.Tests`. The ACVP KAT import is still owed.
- **Daemon, consensus half** — V2 branch `pq-consensus` (`685aac54b7` … `0bb896157f`, 74 files):
  vendored ML-DSA-44 under `src/crypto/mldsa/` (`libbitcoin_mldsa` MSVC project, randomness never
  linked, `DILITHIUM_RANDOMIZED_SIGNING` is an `#error`), `src/crypto/mldsa44.h` wrapper, `src/script/pq.h`,
  `OP_CHECKPQSIG`, `SigVersion::PQ`, the PQ path in `VerifyScript`, `CheckPQSignature` + sigcache entry,
  50-sigop weight, `DEPLOYMENT_PQSIG`/`pqsigHeight`, `GetBlockScriptFlags` + next-block mempool flags,
  `TxoutType::PQ_KEYHASH`, `PQKeyHash` destination, `Base58Type::PQ_ADDRESS`, key_io, RPC describe,
  policy (`pqsig_active` threaded through `IsStandardTx`/`IsStandard`/`AreInputsStandard`,
  `MAX_STANDARD_PQ_SCRIPTSIG_SIZE`), a reorg mempool filter. Tests: `test_blazecoin.exe` 632 cases /
  19,973,963 assertions, 0 failures; `run_blazecoin_tests.py` 10/10 functional incl.
  `feature_blazecoin_pqsig.py` (signs in Python, independent of the wallet). **Deviations from the text
  above, now normative:** `SCRIPT_VERIFY_PQSIG` is bit 21 (19 and 20 were taken); the script/address
  type string is `pqkh` everywhere (`decodescript` and `validateaddress` agree); the activation
  boundary is the Core convention (§7); `CScript::GetSigOpCount` charges 50 for every `0xba` byte
  regardless of context (no historical block carries one, so no delta on the real chain);
  `CScript::HasValidOps` accepts `0xba` and 5,000-byte elements (a decode heuristic, not consensus);
  pre-activation a PQ spend is refused by policy as `scriptsig-size` before consensus sees it.
  Not done: fuzz targets (no fuzz build on this box), the autotools build was not exercised.
- **Daemon, wallet half** — V2 branch `pq-wallet` (on top of `pq-consensus`). Commits `e2b6c7de63`, `238056271e`, `5cdac86553` (34 files). Descriptor `pqkh(mldsa44:<32-byte seed hex>/*)`
  (private, ranged; public/normalised form carries the 20-byte seed id; single `pqkh(mldsa44pub:<1312-byte pubkey hex>)`
  for `InferDescriptor`/watch-only) — `OutputType::PQ` = `"pq"` in every address-type RPC argument; the seed
  rides the existing crypted-key path (stored as a `CKey` under its secp256k1 marker pubkey), so wallet
  encryption covers it unchanged; expanded pubkeys are cached (`walletdescriptorpqcache`) because ML-DSA has
  no public derivation — a locked wallet recognises its coins but cannot top up the keypool.
  **Master seed (normative, replaces the §6 text):** `master_seed = TaggedHash("Blazecoin/PQ/master", k || chain)`
  with `k` = the 32-byte BIP32 master private key and `chain` = `0x00` receive / `0x01` change (one seed for
  both would derive identical addresses on the external and internal SPKMs). Signing: `SignStep` +
  `CreatePQSig`; PSBT input proprietary `0xFC "blz" 0x01` = signature, `0x02` = keyblob, assembled by a
  key-less `finalizepsbt`; fee sizing 3,782 vB per PQ input. Policy: pay-to-`BQ`, `-changetype=pq` and
  PQ inputs are refused with `post-quantum outputs are not standard until block N` until `tip + 1 ≥ H_Q`;
  pre-activation PQ coins show `spendable:false` (balance still counts them); generating `BQ` addresses
  pre-activation is allowed (the coinbase list needs them ahead of the fork). `dumpprivkey`/`importprivkey`
  refuse `BQ`. **Message signing (normative, new):** `digest = TaggedHash("Blazecoin/PQMsg/v1", MessageHash(message))`
  where `MessageHash` is the existing `"Blazecoin Signed Message:\n"` double-SHA256; `sig = ML-DSA-44.Sign(sk, digest,
  ctx = "blazecoin-msg-v1")`, deterministic; signature string = `base64(keyblob || sig)` (3,733 bytes);
  `verifymessage` recomputes `pqkh` from the keyblob and compares it with the address. Tests: `test_blazecoin.exe`
  642 cases run / 0 failures (+10); `run_blazecoin_tests.py` 11/11 incl. `wallet_blazecoin_pq.py`
  (getnewaddress pq → `TQ…`, pre-activation refusals, sendtoaddress / raw / PSBT spends after `H_Q`,
  signmessage + tamper, encrypted-wallet spend, dumpprivkey refused). Not done: an in-place PQ SPKM
  upgrade for existing wallets (they get a clear error), `getbalance` pre-activation PQ split, `sendall`
  gate (mempool rejects anyway). 🪤 The full gate needs a short `--tmpdirprefix` (MAX_PATH).
- **Lite wallet** — MAUI branch `pq-lite-core` (`6de8f91`, `5a47e75`, `2a71575`, `332f1e3`; `pq-banner`
  `4d70e81` merged in as `8e35879`): `Lite.Core/Pq/` (TaggedHash, `BQ`/`TQ` codec, template, two-push
  scriptSig, `PqSigHash`, ML-DSA-44 via BouncyCastle 2.6.2 deterministic + ctx, seed derivation,
  `PqInputVerifier` = the interpreter's seven steps with one verdict each), trustless verifier compares
  script bytes, gateway index derives `BQ` addresses and stores/serves `scriptPubKey`, PQ receive chain +
  a manual PQ send path, both gated on `BlazecoinChain.PqSigActivationHeight` (null; decision 8 keeps PQ
  receive post-fork), desktop Quantum page `PostQuantum` status; the §7.1 banner (`Lite.Core/Fork/`,
  gateway `forkName`/`forkHeight`/`minClientVersion` from `Fork:*`, Notice/Warning/Stopped, Send gated,
  Lite.UI 2.0.5, `SupportedForks = {phoenix413}` until the lite fork rules ship). Vectors bit-exact
  first run. Tests: Lite.Core 168→246, Gateway 29→32, UI 54→68, Core 208→209; WASM, Android and the
  MAUI Windows head build.
- **Services** — every submodule on `pq-address`: Pool (`08d22b5`; length-agnostic Base58Check,
  `TryClassifyAddress`, 34-byte coinbase template, 193→212 tests), Identity (`e28b7fd`; 52-char `BQ`
  format, `AddressVerification:AllowPostQuantum` gate default off → 409 `pq_not_yet_supported`,
  412→425), Indexer (`50b9833`; `P2PQH` script type, gateway-style local `BQ` derivation instead of
  `unknown`, quantum-exposure third bucket `postQuantumSupply`, 439→477), Payout (`acaf550`;
  `pay-in-address?type=pq` behind `Payout:PostQuantumAddresses` default off → 409 `pq_not_active`,
  `getnewaddress` type threaded, 173→186), MVC (`027a7c7`; facts card row, supply tile, tx pill,
  161→163), `Tools/New-CoinbaseAddressList.ps1 -AddressType`. No column widening needed anywhere
  (every address column is already ≥ 64). Docs: `ECOSYSTEM.md`, `KEY_ROTATION.md`, `LISTING_SPEC_PACK.md`,
  `PAYOUTS.md` (+ Desktop twin).
- **`H_Q` = 4,250,000 (2026-09-15).** Mainnet `pqsigHeight` set in `chainparams.cpp` the same morning (daemon 2.1.0); the lite constant and `SupportedForks` flipped; gateways announce `pqsig` / 4,250,000 / 2.0.5. Rollout order as executed is appended below as it happens.
  - 2026-09-15 07:25 — home daemons ×3 on the fork build via the deploy gate (Andrew; gate green; backup kept); `pqsig` reported buried at 4,250,000. (`PQ_ROLLOUT_4250000.md` item 1.)
  - 2026-09-15 07:40 — nightly sweep PQ-aware (`4534d24cdd`, 26-input PQ batches, auto destination type, 130 batches) + the 03:00 task re-pointed (item 7).
  - 2026-09-15 06:44–07:30 — both OVH relays on the fork daemon, gateways swapped (BQ index, fork fields) and announcing `pqsig` / 4,250,000 / min client 2.0.5 (item 2).
  - 2026-09-15 08:35 — web wallet 2.0.5 live on gw + gw2 (fork rules + banner); Android 1.2.0 (5) built + pushed (item 3).
  - 2026-09-15 08:45 — 7-service fleet rebuilt on the BQ-aware builds (item 4).
  - 2026-09-15 08:40 — the coinbase wallet + the payout wallet carry active `pqkh(mldsa44)` receive/change chains (imported random seeds, inside the wallets, fresh backups taken) (item 5).
  - 2026-09-15 08:43 — live coinbase list rewritten in place: 364 `BQ` entries, current + next epoch legacy; first PQ coinbase = block 4,250,880 (item 6). **Rollout complete ~1 day before `H_Q`; the network waits for the height.**
  - 2026-09-15 09:05 — gates `Payout:PostQuantumAddresses` + `AddressVerification:AllowPostQuantum` set true in the live configs (effective at the next Payout/Identity restart); pay-in button made height-aware (item 8).
- **Owed at the time the height was chosen (was: before choosing it):** merge the branches (done), deploy fork-aware daemons to every
  node (`Deploy-BlazecoinV2.ps1` gate), ship the lite heads (banner first) and the services, regenerate
  the coinbase list as `BQ`, the §10.5 dress rehearsal on regtest with every component, then the height
  and the months of notice.

## 14. References

- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA), NIST, August 2024
  (parameter sets, `ctx` string, `KeyGen_internal` seed form).
- FIPS 205 (SLH-DSA), FIPS 206 draft (FN-DSA). NIST IR 8547 (draft, Nov 2024) — transition to PQC,
  ECC deprecation 2030 / disallowed 2035.
- BIP-360 *Pay-to-Merkle-Root* (Beast, Heilman, Foxen Duke; merged into the BIPs repository
  2026-02-11) — https://bips.dev/360/ — the long-/short-exposure framing and the hash-commitment
  decision structure this note ports; its future PQ-signature work is what §3.7's reserved IDs
  track.
- BIP-143 (the digest shape), BIP-340 (tagged hashes).
- .NET 10 `System.Security.Cryptography.MLDsa` (experimental, SYSLIB5006; Windows CNG PQC on 24H2+ /
  OpenSSL 3.5 — **not available on the Windows 11 23H2 dev box**, measured); BouncyCastle.Cryptography
  2.6.2 ML-DSA (already a `BlazecoinWallet.Core` dependency — the implementation of record for the C# twin).
- MAUI repo `docs/PQ_BENCHMARK.md` + `BlazecoinWallet.PqBench` — plan item 4, the measurements behind §2/§4.
- pq-crystals `dilithium` (ML-DSA branch) reference C implementation; liboqs.
- This repo: `PHOENIX_413.md` (the rollout template), `BLAZECOIN_V2.md` (consensus deltas),
  `docs/KEY_ROTATION.md` in the website repo (items 2's rule that governs the migration in §8),
  the wallet's Quantum Exposure page (item 1, the measurement).
