# Fork 3 — "Script activation": the prerequisites for Lightning (and anything else that needs modern script)

**Status: a costed proposal, 2026-09-26. Nothing built. Written so the About page's Phase 4 "Lightning Network" line
has an engineering record behind it, and so the governance system (`blazecoin-governance`) has its first substantive
proposal.** The decision it asks for is at the end (§11). Companion records: `PHOENIX_413.md` (fork 1, difficulty),
`PQ_SIGNATURES.md` (fork 2, post-quantum outputs) — this document follows their shape.

## 0. Why this exists

Every Lightning implementation assumes four base-layer features. On Blazecoin mainnet all four are set to
**never-active** (`src/kernel/chainparams.cpp`):

```
consensus.BIP34Height  = BLAZECOIN_BIP_NEVER_ACTIVE;   // height in coinbase
consensus.BIP65Height  = BLAZECOIN_BIP_NEVER_ACTIVE;   // OP_CHECKLOCKTIMEVERIFY
consensus.BIP66Height  = BLAZECOIN_BIP_NEVER_ACTIVE;   // strict DER signatures
consensus.CSVHeight    = BLAZECOIN_BIP_NEVER_ACTIVE;   // OP_CHECKSEQUENCEVERIFY, BIP68 relative locks, BIP113 MTP
consensus.SegwitHeight = BLAZECOIN_BIP_NEVER_ACTIVE;   // witness programs, weight, commitment
Taproot: BIP9 deployment, nStartTime = NEVER_ACTIVE
```

`BLAZECOIN_V2.md` records this as "a legit legacy port, not a TODO": the 2014 chain never had them, and V2 (a Bitcoin
Core 28 fork) carries the never-active carve-outs so it validates the historical chain exactly. That was the right
call for a cutover. It is also the reason a Lightning repo cannot be started: **there is nothing to build on**.

## 1. What "never-active" means on this chain today

| Feature | Consensus today | Consequence |
|---|---|---|
| **SegWit** | `SegwitHeight` never; but `GetBlockScriptFlags` still sets `SCRIPT_VERIFY_WITNESS \| TAPROOT` unconditionally (upstream Core 28 buries them), while `IsWitnessEnabled` is false | A `blz1…` output can be *created* (any P2WPKH/P2WSH script is a valid output) but never spent: spending needs witness data, and pre-activation `ContextualCheckBlock` rejects any block carrying witness (`unexpected-witness`, `CheckWitnessMalleation`). **Coins sent to bech32 are burned.** Every head guards against it (desktop `AutoPayoutService.IsUnsafeSegwitAddress`, `BlazecoindRpcService`; lite `BlazecoinChain` "legacy-only"; `libblz-lite` accepts only `B…`/`BQ…`). |
| **CSV** | never | `OP_CHECKSEQUENCEVERIFY` is a NOP2-style no-op; `nSequence` relative locks are not enforced (`LOCKTIME_VERIFY_SEQUENCE` never set, `validation.cpp:2640`); block time rule is `nTime > median`, not BIP113 MTP for tx locktime |
| **CLTV** | never | `OP_CHECKLOCKTIMEVERIFY` is a no-op |
| **Strict DER** | never | high-S and non-canonical encodings are valid in blocks. **Deliberate**: `SCRIPT_VERIFY_LOW_S` is also omitted from *standardness* so 0.8.x-era high-S sends relay and mine (`policy.h:132`) |
| **BIP34** | never | coinbase need not carry the height; block version ≥ 2 not required |
| **Taproot** | BIP9 never-active | Schnorr/Tapscript unavailable |

Testnet4/regtest set all five heights to **1** (`chainparams.cpp` ~line 352) — the proving ground already exists.

## 2. What Lightning needs, feature by feature

| Requirement | Why | Needs |
|---|---|---|
| Non-malleable funding transactions | the commitment and refund transactions are pre-signed against the funding txid; if a third party can malleate the txid, every pre-signed transaction is void | **SegWit** (BIP141/143): witness-only malleation surface, and `SIGHASH` covers the amount |
| Revocable commitment with a to-self delay | breach remedy: the cheating party's output is spendable by them only after N blocks, by the victim immediately with the revocation key | **CSV** (BIP68/112) for the relative timelock |
| HTLC timeouts | routed payments must expire on-chain if not settled | **CLTV** (BIP65) for the absolute timelock |
| Canonical signatures | LN peers exchange signatures the specs require to be strict-DER, low-S | **BIP66** in consensus; **LOW_S** at least in standardness (see §5) |
| Fee estimation, RBF-adjacent policy, mempool acceptance of child transactions | LN daemons drive `estimatesmartfee`, `sendrawtransaction`, anchors, CPFP | present in Core 28; Blazecoin's `minrelaytxfee = 0` / `incrementalrelayfee = 0` free-send policy is *non-standard for LN fee logic* — a config question, not a fork question |
| Block time | timelock arithmetic is in blocks | 30 s blocks: every BIP68/CLTV delta is ~20× shorter in wall time than on Bitcoin; LN's defaults (`to_self_delay` 144 → 72 min here) need re-tuning, not code |

Taproot is **not** required for classic BOLT channels. Simple-taproot channels are optional and can wait.

## 3. The rule: Fork 3 = "script activation" at one height `H_S`

Activate, in the same block, as buried deployments at a single height:

- `DEPLOYMENT_DERSIG` (BIP66), `DEPLOYMENT_CLTV` (BIP65), `DEPLOYMENT_CSV` (BIP68/112/113), `DEPLOYMENT_SEGWIT`
  (BIP141/143/144/147 — witness, weight limit, commitment, NULLDUMMY).
- **Decision:** `DEPLOYMENT_HEIGHTINCB` (BIP34) at the same height — harmless and tidy (block version ≥ 2, height in
  coinbase; the pool already writes a height? — verify) — recommended yes.
- **Decision:** Taproot at `H_S` too, or leave never-active. Recommended: **activate**, because a second script fork
  later costs the same coordination again and Taproot's MuSig/PTLC path is where LN is heading; but it widens the
  test surface (`feature_taproot.py` is the largest functional test in the tree). Either answer is defensible.

Mechanism: the two shipped forks' pattern — a height in `Consensus::Params`, `BLAZECOIN_BIP_NEVER_ACTIVE` until
chosen, regtest via `-testactivationheight=<name>@N`. The five upstream heights already exist as fields; **this fork
is mostly *un-disabling* upstream code, not writing new consensus code** — the opposite of PQ.

## 4. Consensus mechanics — soft fork in name, everyone-must-upgrade in practice

In Bitcoin terms these are soft forks (they only *restrict* validity). On Blazecoin the practical effect is a hard
fork for every existing node: a pre-`H_S` V2 node has `IsWitnessEnabled == false` and **rejects any block that
carries witness data** (`unexpected-witness`). The first block after `H_S` containing a SegWit spend forks every
un-upgraded node off the chain. Therefore the PQ rollout rule applies unchanged: **every daemon (home ×3, relays ×2,
T630 VMs ×3, blade) and every head runs fork code before `H_S`, with ≥ 2 weeks of margin.** V1.5 and Original are
already retired (they froze at `H_Q`), so no legacy-client decision arises this time.

Activation boundary follows the Core convention the PQ record documents: rules apply to every block at height ≥ `H_S`;
the mempool switches for the next block; `getdeploymentinfo` reports `active` at tip `H_S − 1`.

Checkpoint/assumevalid: the fork ships with the usual `defaultAssumeValid` / `nMinimumChainWork` / `chainTxData`
refresh and the pending `H_Q` checkpoint (`PQ_SIGNATURES.md` §16 owes it to "the next daemon release" — this is that
release if it comes first).

## 5. Policy changes that ride with it

- **LOW_S standardness.** Today omitted so legacy high-S sends relay. LN requires low-S signatures from peers but that
  is enforced by the LN daemons, not the chain. Options: (a) keep omitted — legacy sends keep working, LN unaffected;
  (b) add `SCRIPT_VERIFY_LOW_S` to standardness at `H_S` — the 0.8.x compatibility promise ends. Recommended **(a)**
  until a real listing changes who is sending; record it as a standing decision.
- **Fee policy.** `minrelaytxfee = 0` stays; LN daemons should be configured with an explicit fee floor and
  `estimatesmartfee` fallback rather than trusting a zero-floor mempool.
- **Witness discount and block weight.** Automatic with SegWit; the 30 s block economy (subsidy 25.8 BLZ) is
  unaffected by weight accounting.

## 6. Coupled work outside the daemon (the hidden half — smaller than PQ's, not small)

| Component | Change |
|---|---|
| **Lite wallet (`Lite.Core`)** | bech32 `blz1…` receive + send (P2WPKH), `BlazecoinAddress` accepts a third kind, the "legacy-only" note in `BlazecoinChain` retires, `LiteTransactionBuilder` gains witness signing (NBitcoin has it), the fork banner (`SupportedForks`) gains `scriptactivation`, checkpoint refresh. **Ships ahead of `H_S`** like the PQ rule: a lite head must not sign a witness tx before activation. |
| **Desktop (MAUI)** | lift the three `blz1` guards (`AutoPayoutService`, `BlazecoindRpcService`, send validation) **only after `H_S`** — before it they are protecting funds; Quantum/Provenance pages decode witness scripts. |
| **Indexer** | `ScriptTypeAnalyticsService` already names `witness_*` types; address extraction for `blz1`; explorer badges; the balance-at-height read is script-agnostic. |
| **Pool / solo proxy** | optional bech32 payout addresses; if BIP34 activates, the coinbase height rule must hold for every template. |
| **Gateway / web wallet** | fork announcement fields (`Fork:*`) reused; `LiteTxVerifier` handles witness proofs (txid vs wtxid — proofs commit to txid, unchanged). |
| **`libblz-lite` (IoT)** | `blz_address` gains bech32 decode (a ~120-line module); receive-only devices need nothing else. |
| **`blazecoin-pay`** | invoice addresses may become `blz1…` once heads can pay them; nothing in the state machine changes. |
| **Docs** | `BLAZECOIN_V2.md` fifth delta section; `ECOSYSTEM.md` §1 BIPs row; the Wallet page; this note → activation record. |

## 7. Then, and only then: the Lightning port itself

A **separate repo** (`blazecoin-lightning`), a fork of one implementation:

- **LND** (Go). Litecoin support proves the scrypt/alt-chain path; chain params are a struct (chain hash, HRP `blz`,
  default port, fee floor, `DefaultBitcoinTimeLockDelta`). Largest community.
- **Core Lightning** (C). Plugin architecture, a cleaner chain-backend abstraction (`bcli`), smaller footprint. Fits
  the estate's C work (IoT) and the OVH boxes.

Parameters to re-derive for 30 s blocks: `to_self_delay`, `cltv_expiry_delta`, `min_final_cltv_expiry`, funding
confirmation depth (6 blocks = 3 min is too shallow for channel funding on a sole-miner chain — 20+), dust limits
for a 25.8 BLZ subsidy economy, fee floors. A Blazecoin LN starts as the operator's hub plus whoever joins; say so.

**The sentence any announcement must carry:** LN channels are ECDSA constructions. A Lightning layer on Blazecoin is
a *classical-security* layer over a chain whose lead is post-quantum. No PQ channel design exists anywhere yet.
That is not a reason not to build it; it is a reason not to imply the two are the same story.

## 8. Test plan

1. **Re-enable the upstream functional tests** the never-active setting sidelines, on regtest/testnet4 where the
   heights are already 1: `feature_segwit.py`, `p2p_segwit.py`, `feature_csv_activation.py`, `feature_bip68_sequence.py`,
   `feature_cltv.py`, `feature_dersig.py`, `feature_nulldummy.py`, `wallet_implicitsegwit.py`, and if Taproot ships
   `feature_taproot.py` + `wallet_taproot.py`. These are the proof the un-disabling is complete.
2. **`feature_blazecoin_scriptactivation.py`** in `run_blazecoin_tests.py`'s list, the PQ pattern: a witness spend is
   rejected in block `H_S − 1` and accepted in block `H_S`; a CSV/CLTV script behaves as a no-op before and enforces
   after; a high-S/non-DER spend is valid before and (if consensus DERSIG) invalid after; pre-fork node behaviour on
   the first witness block (`feature_presegwit_node_upgrade.py` covers the upgrade path).
3. **Boost unit suite** unchanged plus the un-disabled script tests; **bit-exact vectors across C# and C** for bech32
   (Lite.Core ↔ `libblz-lite`), like the Phoenix/PQ vector discipline.
4. **Rollout rehearsal on testnet4** with an LN daemon opening, routing and force-closing a channel — the only test
   that shows the parameters are right for 30 s blocks.

## 9. Effort (honest order of magnitude)

Daemon: **days, not weeks** — the consensus code is upstream's; the work is the height, the test re-enablement, the
boundary test, the checkpoint refresh and the release. Heads and services (§6): **~2 weeks**, the lite wallet's
witness signing being the largest piece. Rollout: the PQ runbook, ~1 week of margin. **The LN port (§7): months**, and
it is the part that should not start until `H_S` is on mainnet.

## 10. What this does not do

It does not make Lightning exist; it makes it possible. It does not change the PQ story, the subsidy, the block time
or the address set (it adds one). It does not remove the free-send policy. It does not require Taproot (decision §3).

## 11. Decisions this asks for — put to `blazecoin-governance`

1. **Go / no-go on Fork 3 at all.** For: it is the door to LN, to PayJoin-friendly script, to any covenant-style work,
   and it removes a growing list of carve-outs from a Core 28 codebase that assumes them. Against: a third consensus
   change within a year, exchanges prefer a stable ruleset, and a classical LN layer dilutes the PQ differentiator.
2. `H_S` — a round number with ≥ 2 weeks of margin after every node and head runs fork code.
3. Taproot at `H_S`: yes / later.
4. BIP34 at `H_S`: yes (recommended) / no.
5. LOW_S standardness: keep omitted (recommended) / enforce.
6. LN implementation to port: LND / Core Lightning — decided after `H_S`, not before.

## 12. References

- `src/kernel/chainparams.cpp` (mainnet heights ~95–130; testnet/regtest ~350–360), `src/consensus/params.h`
  (`BLAZECOIN_BIP_NEVER_ACTIVE`, buried deployments), `src/validation.cpp` (`GetBlockScriptFlags` ~2416,
  `LOCKTIME_VERIFY_SEQUENCE` 2640, `CheckWitnessMalleation` 4008), `src/policy/policy.h` (fees, LOW_S note 132),
  `src/deploymentinfo.cpp`.
- BIPs 34, 65, 66, 68, 112, 113, 141, 143, 144, 147; BOLTs 2, 3, 5 (channel construction, timelocks).
- `PHOENIX_413.md`, `PQ_SIGNATURES.md` §7/§9/§16, `PQ_ROLLOUT_4250000.md` — the two shipped forks' method.
- Phase 4 plan: `blazecoin-lightning` README (private repo) — the decision note this document expands.
