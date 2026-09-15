# Blazecoin Core V2

The reference node and daemon for **Blazecoin (BLZ)** — a scrypt proof-of-work cryptocurrency launched
on 23 May 2014 whose block reward of 413 BLZ honours fire station #413 and whose foundation funded
volunteer fire departments. This is the V2 line: the 2014 code base re-homed onto a
**Bitcoin Core 28** fork in 2026, with Blazecoin's consensus rules carried across unchanged and two
additions — the **Phoenix-413** per-block difficulty retarget, activated at block 4,194,000 on
26 August 2026 (see `PHOENIX_413.md`), and **P2PQH**, a post-quantum output type signed with
ML-DSA-44 (FIPS 204), activating at block **4,250,000** (see `PQ_SIGNATURES.md`). Legacy `B…`
outputs stay valid indefinitely; existing keys and coins are unaffected. **Every node must run
release 2.1.0 or later before block 4,250,000** — an older node stops at the first post-quantum
spend after the fork.

The chain never stopped: every block since 2014 validates under this software. Roughly 94 % of all BLZ
that will ever exist (≈ 888.9 M) has been mined.

## Network facts

| | |
|---|---|
| Algorithm | scrypt (N = 1024, r = 1, p = 1), block IDs SHA256d |
| Block target | 30 seconds |
| Retarget | every block since Phoenix-413 (height 4,194,000); every 120 blocks before |
| Reward | 25.8125 BLZ after Halving IV at block 4,204,800; halves every 1,051,200 blocks |
| Ports | P2P **55414**, RPC **55413** |
| Addresses | legacy P2PKH starting with `B`; post-quantum P2PQH starting with `BQ` (52 characters, spendable from block 4,250,000). No bech32 — segwit is consensus-disabled |
| Post-quantum fork | block 4,250,000: ML-DSA-44 signatures (`getnewaddress "" pq`, `validateaddress` type `pqkh`); V1.5 and every V2 release before 2.1.0 stop there |
| Genesis | `5d871c1b6ea542c2bb8a3b3ac70028a591bbf81369e90c2446c1a2bbfb89459b` |
| Public relays | `51.210.47.141:55414`, `54.39.23.245:55414` (baked in as fixed seeds) |

Website: https://blazecoin.co.uk · Original 2014 announcement: https://bitcointalk.org/index.php?topic=624778.0

## Downloads

Binaries are published on the **Releases** page of this repository: a Windows x64 daemon bundle and
a Linux x86_64 daemon tarball (`blazecoind` + `blazecoin-cli` + a default `blazecoin.conf`). The
desktop wallet installer, which bundles the Windows daemon, is released from the companion
`blazecoin-wallet` repository. Every release carries a `SHA256SUMS` file — verify before you run.

## Building

This is Bitcoin Core 28 underneath, so its build documentation applies verbatim: `doc/build-unix.md`,
`doc/build-osx.md` and, for Windows, the Visual Studio solution under `build_msvc/`. The binaries are
named `blazecoind`, `blazecoin-cli`, `blazecoin-tx`, `blazecoin-wallet`.

A minimal `blazecoin.conf` for a node is in `share/examples/blazecoin.conf`. RPC uses `rpcauth` (or the
cookie file); keep RPC bound to loopback.

## Consensus references

- `PHOENIX_413.md` — the retarget specification and its canonical test vectors (45, shared with the
  wallets).
- `PQ_SIGNATURES.md` — the P2PQH post-quantum output type (ML-DSA-44, `BQ…` addresses, activation at
  block 4,250,000); its test vectors live in `test/pqsig/` and are shared with the wallets.
- `src/kernel/chainparams.cpp` — chain parameters, genesis, checkpoints, fixed seeds.
- `test/functional/` — the Blazecoin functional tests alongside upstream's.

## Licence

MIT, as Bitcoin Core (`COPYING`). Copyright the Bitcoin Core developers and the Blazecoin contributors.
This project is not affiliated with Bitcoin Core.

## Disclaimer

Blazecoin is a mined, traded digital currency with no issuer, no promise of value and no active
exchange market at the time of writing. Nothing here is investment advice. Run this software at your
own risk and keep backups of any wallet you create.
