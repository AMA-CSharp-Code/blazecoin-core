# Phoenix-413 — per-block difficulty retarget (proposal)

> **Status: 🔥 ACTIVATED ON MAINNET — 2026-08-26, the same day it was drafted,
> ratified, implemented, and shipped.**
>
> - **`H_A` = 4,194,000** — anchor block
>   `add35fb660b3424e73ffccddee2ac84933b92b75e99f0fe874605b716f8a96a0`
>   (the old rule's last act: its characteristic +10% ease after the deliberate
>   mining freeze). Now checkpointed in the V2 and V1.5 sources.
> - **First Era-3 block: 4,194,001** —
>   `d8063c33455a636603aea3ef6d893b16a5ec4b007348bb42a4d133935e87104a`,
>   nBits `1c403041` — **verified BIT-EXACT against the canonical reference**, as
>   were 4,194,002 (`1c4049db`) and 4,194,003 (`1c403c2d`): the target moved every
>   block from the first, exactly as computed.
> - **Network crossing:** all 3 home daemons + both OVH relays followed as one
>   chain; both wallet gateways synced. The 2014 seed nodes freeze at `H_A` as
>   accepted. Rollout was operator-driven (mining stopped at tip 4,193,990 →
>   height chosen → every implementation shipped → mining resumed).
> - **Shipped that day:** V2 daemons (home ×3 + relays ×2), web wallet (gw+gw2),
>   Android 1.1.0(4), V1.5.2 releases for Windows/macOS/Linux, the Rekindling
>   vintage badge (key 7 → block 4,194,001) + homepage slide, lore finalized.
>
> - **Activation pass complete (same evening):** the §7 collateral all shipped —
>   Rekindling vintage badge (key 7 → block 4,194,001; Indexer self-heal
>   VERIFIED re-bucketing the coinbase to key 7, 5,162,500,000 sats), homepage
>   carousel slide live, lore docs finalized with block/hash/date, H_A
>   checkpointed in V2 + V1.5 sources. **Bitcointalk announcement POSTED** to
>   the 2014 lineage thread (source: `Desktop\Blazecoin Marketing\
>   Bitcointalk-Phoenix413-ANN.txt` — V1.5.2-first structure, new-generation
>   teaser at the end).
>
> Decision history and the rejected Option A live in MAUI `ROADMAP.md` §G.
>
> **Implementation progress (rollout day 2026-08-26):**
> ✅ Canonical vectors (45, `test/phoenix413/` — the Python generator is the authority).
> ✅ **`H_A` = 4,194,000 — CHOSEN by the operator 2026-08-26**: mining deliberately
>   STOPPED at tip 4,193,990 so the height cannot be crossed until every
>   implementation ships; 4,194,000 is the next Era-2 retarget boundary (÷120) and
>   becomes the anchor. The fork crosses ~5 minutes after mining resumes.
> ✅ **V2 daemon** (`803355f36d`): ASERT core in `pow.cpp` (overflow-exact split for
>   regtest's 2^255 powLimit — a real bug the functional test caught), buried
>   deployment `phoenix413` + regtest `-testactivationheight` wiring, mainnet
>   height baked; `pow_tests` vectors+dispatch green, `feature_blazecoin_phoenix413.py`
>   green (live regtest activation, stall clamp, reorg) and in BOTH runner lists.
> ✅ **Lite C# verifier** (MAUI `e326a2b`): EXACT per-block target validation above
>   `H_A` — stronger than the old ±10% band, since the header stream supplies the
>   anchor (captured crossing the fork, persisted in the checkpoint record; legacy
>   state still parses) and every parent timestamp; shipped checkpoint refreshed to
>   4,193,880 (below `H_A`−1 by design); suites 167+54+29 green, vectors bit-exact.
> ✅ **V1.5.2 final**: `H_A` baked, released 2026-08-26 for Windows / macOS / Linux (`v1.5.2-*` tags).
> ✅ **Deploys (2026-08-26)**: WASM → gw/gw2, sideload APK 1.1.0(4), home daemons ×3 via
>   `Deploy-BlazecoinV2.ps1`, relays ×2 via the vps kit — all five daemons on fork code.
> ✅ Standing rule honoured: the miner stayed OFF until every box ran fork code (blocks
>   mined past 4,194,000 under old rules would have been rejected by upgraded nodes).
> ✅ **ACTIVATED**: mining resumed, block 4,194,001 `d8063c33…` sealed and verified bit-exact;
>   the gated collateral (§7) shipped with the real block number; `H_A` is now a checkpoint.
>   *(Status block re-trued 2026-09-04 — it had been left showing its pre-activation boxes.)*
>
> **Identity in one line:** the ASERT exponential retarget (the settled endpoint of the
> 2014–2020 difficulty-algorithm era; BCH mainnet since Nov 2020) tuned to Blazecoin's
> own constants — 30-second blocks, **half-life 413 blocks**. The mechanism is proven;
> the parameters, the name, and the story are ours. *The chain that rekindles itself.*

---

## 1. Motivation (short — the full working is in `ROADMAP.md` §G and backend `TODO.md` › Network resilience)

The live rule retargets every 120 blocks clamped to **±10% per window** (Era 2, height
≥ 600,000; `GetRetargetTimespanBounds`, `src/pow.cpp`). On a ~756 MH/s single-operator
chain in a petahash scrypt world this is an **asymmetric ratchet**: visiting hashrate
N× the baseline drives difficulty up within hours (fast blocks ⇒ fast windows), then
leaves; recovery costs ~**10×N hours** because each 120-block window now takes 30s×N
per block and buys only −10%. One modern LTC ASIC (~23×) ⇒ ~10 days near-frozen; a
small farm (~100×) ⇒ ~2 months. The same clamp is why the second-miner sizing rule
demands a backup within ~10× of the primary.

Phoenix-413 replaces the windowed clamp with a per-block exponential rule. Recovery
from any hashrate loss becomes `log₂(R) × 3.4 h` — **nothing strands the chain for
more than about a day**, and a cheap 60 MH/s device becomes a viable second miner.

| Scenario | Era-2 rule (today) | Phoenix-413 |
|---|---|---|
| One L9 hit-and-run (23×) | ~10 days | ~15 h |
| Small farm leaves (100×) | ~2 months | ~23 h |
| Primary dies onto a 60 MH/s backup (13×) | ~5 days | ~13 h |
| Primary dies onto an equal backup | ~10 h | ~0 (no gap to close) |

## 2. The rule

For every block at height `h > H_A` (the activation height):

```
target(h) = anchor_target × 2^( (Δt − Δh·T) / τ )

Δt  = timestamp(parent of h) − timestamp(anchor parent)     [seconds]
Δh  = h − H_A                                               [blocks]
T   = 30                                                    [target spacing, s]
τ   = 413 × 30 = 12,390                                     [half-life, s]
```

clamped to `params.powLimit`. Difficulty = 1/target as usual; block identity stays
SHA256d, PoW evaluation stays scrypt(1024,1,1,256) — **this rule changes only how the
target is computed, nothing about how work is measured.**

Plain-English behavior:

- Chain runs **behind** schedule (hashrate left) → target grows exponentially:
  difficulty **halves for every 3.4 hours** of accumulated deficit. No windows — the
  very next block after a stall is already easier.
- Chain runs **ahead** of schedule (farm arrived) → difficulty **doubles per 3.4 hours**
  of accumulated surplus, capping how hard a visitor can ratchet it up.
- The formula is **absolute** (always computed from the fixed anchor, never iterated
  block-to-block), so rounding error cannot accumulate and every node computes the
  identical target from the header chain alone — which also keeps the lite wallets'
  trustless header verification exact.

### 2.1 Anchor

`H_A` = activation height (see §4). The **anchor target** is the nBits of block
`H_A` computed under the old Era-2 rule (i.e. the last old-rule target), and the
**anchor parent time** is the timestamp of block `H_A − 1`. Using the *parent*
timestamp on both ends is the standard ASERT trick that stops the anchor block's own
miner from biasing the schedule origin.

### 2.2 Why these constants

- **τ = 413 blocks** is not just the brand number — it sits squarely in the sane band.
  Much shorter (minutes) and single lucky/slow blocks whipsaw the target; much longer
  (a day+) trends back toward today's stranding problem. ~3.4 h half-life means solo
  variance at 30 s blocks averages out (413 blocks of smoothing) while any real
  hashrate change is fully priced in within half a day. For calibration, BCH runs
  τ = 2 days at 600 s spacing = 288 blocks of smoothing; Phoenix-413's 413 blocks is
  the same order of smoothing, on a chain that needs faster wall-clock response.
- **T = 30 s** unchanged. Phoenix-413 deliberately does **not** touch block time,
  subsidy, halvings, MAX_MONEY, maturity, addresses, or any BIP-activation stance —
  the vintage consensus surface stays 2014 except this one rule.

### 2.3 Timestamp-manipulation bounds (the adversarial analysis)

Miners control timestamps within two existing rules, both kept as-is: a block's time
must exceed the **median of the last 11** (MTP) and may be at most **2 h in the
future** (`MAX_FUTURE_BLOCK_TIME`). Under ASERT the worst a miner can do with the 2 h
future window is transiently inflate `Δt` by 7,200 s ⇒ target × 2^(7200/12390) ≈
**1.5× easier at most**, self-correcting because the formula is absolute (the next
honest timestamp snaps the schedule back — no drift is banked, unlike iterated
algorithms, and unlike KGW there is no window edge to time-warp). Backdating is
bounded by MTP monotonicity. Optional hardening (open decision, §8): tighten
`MAX_FUTURE_BLOCK_TIME` for post-`H_A` blocks; 2 h was sized for 10-minute blocks.

## 3. Why the ASERT core rather than an invented mechanism

Recorded so the choice survives re-litigation: difficulty rules are adversarial-
environment code whose failure modes appear only under strategic miners. The
2014–2020 field test across hundreds of small chains eliminated the clever ideas —
discrete emergency valves recreate BCH's EDA oscillation (gamed within weeks, months
of excess supply), short-window averages recreate KGW (time-warp exploited, chains
51%'d), and the smooth continuous limit of "let difficulty decay when stalled" *is*
ASERT. Adopting it is convergent evolution, not copying; the creative surface that is
safely ours is parameters (τ = 413), integration, and identity. Novel *mechanisms*
buy unaudited game-theoretic risk and nothing else. (DigiShield was the runner-up —
12 years on Doge — but it is iterated rather than absolute; absolute wins for us
because the lite wallets re-derive targets independently and must match bit-exactly.)

## 4. Consensus mechanics

- **Era dispatch:** `GetNextWorkRequired` becomes three-era: h < 600,000 → Era 1
  (±400%); h ≤ H_A → Era 2 (±10%/120); h > H_A → Phoenix-413. Eras 1–2 are untouched
  so historical validation is byte-identical.
- **Activation height `H_A`:** a `Consensus::Params` field, mainnet value chosen at
  deploy time. Criteria: far enough out that every node **and every lite-wallet head**
  ships first (≥ 2 weeks of margin at minimum); ideally a memorable 413-motif or
  round number. There is no miner-signalling or BIP9 machinery — this chain's nodes
  are all operator-run, so a flag height is honest and sufficient.
- **Implementation:** new `CalculateASERT` + `GetNextWorkPhoenix` beside the existing
  functions in `src/pow.cpp`, porting the reference **aserti3-2d** fixed-point form
  (integer exponent split + cubic 2^frac approximation, 16-bit fixed point; MIT) with
  Blazecoin constants. No floating point anywhere in consensus. Target clamped to
  `powLimit`; sub-1 targets impossible by construction.
- **Regtest:** stays upstream-tuned (DESIGN_AUDIT D1's do-not-"fix" rule stands). The
  functional suite activates Phoenix via the existing Core 28
  `-testactivationheight=`-style override pattern (regtest-only arg, default = never),
  so the Boost/functional harness keeps its Bitcoin-shaped assumptions everywhere else.
- **Checkpoint:** add a checkpoint shortly after `H_A` once buried (standard 500k
  cadence continues; one extra near the fork is cheap insurance).
- **Rollback story:** pre-`H_A`, shipping is revertable by ordinary deploy
  (`Deploy-BlazecoinV2.ps1` gate + rollback). Post-`H_A`, reverting is itself a fork —
  acceptable only in the shadow of a consensus bug, feasible because the operator
  runs every node; the test plan (§6) exists to make this path never needed.

## 5a. Legacy clients (Original 0.8.6.2 / V1.5) — and the V1.5.2 decision

Without action, both legacy full-node clients enforce the old retarget in their own
consensus code, so at `H_A` they would reject the first Phoenix block and every one
after it — and 0.8-lineage DoS scoring would then progressively **ban** the V2 peers
feeding them "invalid" blocks. They would freeze at the last Era-2 block: funds
always safe (keys/UTXOs/tx format unchanged; recovery via MAUI wallet Import or the
lite wallet's WIF sweep), but the clients dead as network participants. The two 2014
seed nodes take this path (accepted).

**DECIDED 2026-08-26 (reversing this spec's earlier no-V1.5.2 lean): V1.5 is kept a
live client through the fork via V1.5.2.** Status: **implemented + pushed the same
day, INERT** — `Blazecoin_Core_V1.5` branches `linux` (`31b9a1d`) + `dev`
(`2ad8af7`): self-contained `src/phoenix413.h` (raw OpenSSL BN, aserti3-2d fixed
point), Era-3 dispatch in `GetNextWorkRequired` behind
`PHOENIX_ACTIVATION_HEIGHT = 0x7fffffff` (never active — the built binary is
consensus-identical to 1.5.1 today), anchor = block `H_A`'s nBits + its parent's
time, cached (safe: the activation release ships a checkpoint at/near `H_A`).
Standalone harness `src/test-phoenix413.cpp` **passes all 45 canonical vectors**;
tree reports `1.5.2.0-prerelease`. The Original 2016 snapshot repo stays untouched
(historical artifact, frozen at `H_A` by design). Fork-day comms still owed: the
website wallet-page + V1.5 README notice ("update to V1.5.2 before block `H_A`").

**🚦 RELEASE GATE (Andrew, 2026-08-26): NO GitHub release, tag, or downloadable
binary for V1.5.2 until EVERY wallet implementation is done** — V2 daemon, lite
heads (WASM/Android/iOS as applicable), and all V1.5 platforms — and `H_A` is
chosen. Branch pushes are source-only; `CLIENT_VERSION_IS_RELEASE` stays `false`
until the gate lifts. Per-platform V1.5.2 build status (2026-08-26):
- **Windows daemon** — ✅ built (msbuild Release x64), reports `1.5.2.0-prerelease`.
- **Windows Qt GUI** — ✅ compile-verified 2026-08-26: `blazecoin-qt.exe` built from
  `dev`, ProductVersion 1.5.2.0. (Two pre-existing, unrelated finds fixed/noted en
  route: the `linux` branch had `message_box_dialog.h` trapped inside
  `#ifdef USE_QRCODE` — Windows GUI could not compile there at all; fixed `16c6920`.
  The vcxproj's post-build DLL copy uses literal wildcards (`libssl-*-x64.dll`,
  MSB3021) — exe links fine; stage DLLs by hand at release time or fix the entries.)
- **Linux daemon/GUI** — source on `linux` branch ✅; rebuild via `makefile.unix`
  (WSL/Ubuntu) at release time.
- **macOS** — `macos-v1.5.0` branch NOT yet carrying the change (deliberate: it is
  unbuildable/untestable on this box). At release time: merge `31b9a1d` into the
  branch **on a Mac**, build the universal .app, test, then release together with
  everything else.

## 5. Coupled work outside the daemon (the hidden half)

- **Lite wallets (MAUI repo — the critical path):** the trustless spine
  (`HeaderChainSync` + the C1/M3 verifier) independently validates the retarget rule
  today (±10% bound). It must gain the Phoenix rule, height-gated so pre-fork headers
  still validate under Era 2. **Every lite head must ship before `H_A`** — WASM
  (both gw boxes, self-serve redeploy), Android (sideload APK + `downloads/` swap —
  note: with Play deferred, *no third-party review gates our shipping*, a genuine
  advantage while it lasts), and the checkpoint anchor refreshed at the same release.
  The C# and C++ implementations must match **bit-exactly**: both are built against a
  shared test-vector file (§6).
- **Pool / solo proxy / indexer / MVC:** audit pass, expected near-zero — the pool and
  proxy take nBits from `getblocktemplate` and never recompute the retarget; the
  Indexer stores per-block difficulty as reported. Anything found recomputing the
  window rule gets the same height-gated function.
- **Desktop wallet:** no consensus role (full-node RPC); display only.
- **Docs:** `BLAZECOIN_V2.md` gains the third era in its parameters section + a
  Recent-work entry; `ECOSYSTEM.md` §1 table row; the ROADMAP §G item flips to point
  here as decided; halving-style lore/era treatment optional (§7).

## 6. Test plan

1. **Shared test vectors — ✅ EXIST (2026-08-26): `test/phoenix413/` in this repo**
   (`phoenix413_vectors.json` + `generate_phoenix_vectors.py`, mirrored in the V1.5
   repo's `contrib/phoenix413/`). The Python generator is the **semantic authority**:
   it pins C-truncating division for the exponent, arithmetic-shift floor, two's-
   complement low-16 fraction, the aserti3-2d cubic, right-shift floors, zero→1,
   powLimit clamp, and the compact codec. 45 vectors: steady state at several
   depths, single-block jitter, exact half-life boundaries ×5 both directions,
   13×/23×/100× strands, 2 h future-time abuse, both clamps, three anchor
   difficulties, and a 120-block LCG sequential walk (absolute-rule drift check).
   **Every** consensus implementation (V1.5 C++ ✅, V2 C++ ✅, lite C# ✅ — all 45/45 green by activation day)
   asserts against this same file — this is the bit-exactness guarantee.
2. **Boost unit tests:** `pow_tests` gains Phoenix cases from the vectors (economics
   already BLZ-adapted per the 2026-07-06 pass).
3. **Functional tests:** new `feature_phoenix413.py` in **both** lists of
   `run_blazecoin_tests.py` (per the both-lists rule): activation boundary (last
   Era-2 block / first Phoenix block), recovery-after-stall using `setmocktime`,
   ratchet-up bound, reorg across `H_A`.
4. **Full gate:** `Deploy-BlazecoinV2.ps1` already runs the whole Boost suite + the
   functional set before any binary reaches a daemon — Phoenix rides the existing
   sanctioned path, no new deploy machinery.
5. **Dress rehearsal:** a throwaway regtest chain mined through a simulated
   fork-height with the real binaries + a lite head pointed at a local gateway,
   before the mainnet `H_A` is chosen.

## 7. Marketing / identity (why "Phoenix")

The chain's mythology is already a phoenix arc (Eruption → The Ashes → Stirring →
Rebirth). Phoenix-413 is the rule by which the chain *rekindles itself* — difficulty
reborn from any collapse within hours, carrying the chain's own number as its time
constant. Hooks, all non-consensus and optional: a fork-block vintage medallion
(the icon system already handles event badges), a lore entry for the era list, the
launch framing "one precise, provable change to a 2014 chain — tuned to 30 seconds
and 413." The honest positioning: *not a new algorithm — the settled exponential law,
wearing our constants.*

**Collateral already drafted (2026-08-26, all future-gated on activation — ship at
fork time, not before):** "The Rekindling" entry (flame medallion + voice-matched
lore line) in all three Desktop `Special Vintage Lore*.html` docs, and a homepage
carousel announcement slide (Gekko 5b US-clean register) in
`Vintage Carousel Slide Ideas.html`. At activation: port the badge into
`VintageBadges.cs` / `_VintageCard.cshtml` anchored to the real fork block, fill the
slide's `[ACTIVATION HEIGHT]`, and only then ship either to the live site.

## 8. Open decisions (settle at implementation time)

1. **`H_A` value** — after all heads ship + margin; 413-motif optional.
2. **Tighten `MAX_FUTURE_BLOCK_TIME`** post-fork (2 h → e.g. 10 min)? Bounded either
   way (≤1.5× transient at 2 h); tightening shrinks it to ~1.03×. Cheap, but it is a
   second consensus change — decide deliberately.
3. **Testnet dry-run** — testnet3 has a re-mined genesis but is not live; a public
   dry-run is optional given the regtest rehearsal (§6.5).
4. **Era-2 sunset note in lore** — whether the retirement of the 2014 rule gets its
   own era name.
