# Security Policy

Blazecoin Core is the node software for Blazecoin (BLZ), a scrypt proof-of-work coin mined
continuously since 23 May 2014, built on a Bitcoin Core 28 base. This policy covers this
repository (the daemon, its RPC surface, the wallet code, and the consensus code including the
P2PQH post-quantum output type and the Phoenix-413 retarget). The desktop, Android and web wallets
and the website share the same reporting address and the same bounty.

## Supported versions

| Version | Status |
|---|---|
| The latest release on the Releases page (2.1.x) | Supported: security fixes are released here. |
| 2.1.0 | Follows the chain; update to the latest release. |
| V2 releases before 2.1.0 | Stop at the first post-quantum spend after block 4,250,000. Not supported. |
| V1.5.2 | Followed the chain only up to the post-quantum fork at block 4,250,000 (16 September 2026), where it was retired. Not supported. |
| V1.5.1 and earlier, and the 2014 0.8.6.2 client | Cannot follow the chain past block 4,194,000. Not supported. Import the wallet file or sweep the keys into a current wallet. |

## Reporting a vulnerability

Email **admin@blazecoin.co.uk** with `security` or `bug bounty` in the subject line. This mailbox
is not for support questions; those go to the community channels listed on https://blazecoin.co.uk.

Please include:

- the software and version (`blazecoind --version`, or the wallet build),
- the steps to reproduce, with what you expected and what happened,
- where it applies, a transaction, block or script on your own test setup,
- how you would like to be credited, and a Blazecoin address for any reward.

**Please do not open a public issue, post in the forum thread or publish the details** until a
fix is released. A public disclosure before that forfeits the reward. Consensus-affecting reports
are handled the way Bitcoin Core handles them: privately, with a coordinated release.

What to expect from us:

- an acknowledgement within **3 days**,
- a verdict (confirmed, duplicate, out of scope, or not reproducible) within **14 days**, with a
  short explanation either way,
- credit in the release notes, unless you ask otherwise,
- payment of the bounty once the fix is released.

We do not yet publish a PGP key. If a report needs to be encrypted, say so in a first email
without the details and we will arrange a key.

## Scope

In scope: this daemon and its RPC surface; the wallet code; the Phoenix-413 retarget; the P2PQH
post-quantum output type, the new opcode, the relaxed element limit for PQ inputs and the vendored
ML-DSA-44 implementation (`src/crypto/mldsa/`); the desktop, Android and web wallets
(https://github.com/AMA-CSharp-Code/blazecoin-wallet); and the website and its services (accounts,
invite codes, the earn and withdrawal system, the mining pool, the lite-wallet gateways).

Out of scope: anything that requires a denial-of-service, flooding or spam attack against the live
site, the pool or the public nodes (test against your own node instead); social engineering or
phishing; other people's accounts; automated scanner output without a working proof; duplicates of
known issues; issues in third-party sites and services; theoretical weaknesses with no demonstrated
effect.

Test only against your own node, wallet and accounts.

## Bug bounty

Confirmed bugs are rewarded in BLZ, first reporter only, by severity:

| Severity | Examples |
|---|---|
| Critical | a consensus split; forging or bypassing signatures, classic or post-quantum; spending coins you do not own; crashing other people's nodes remotely |
| High | exposure of wallet keys or seed phrases; bypassing the website's login or two-factor checks; taking rewards from the earn system you are not owed |
| Medium | bugs with a real effect that need unusual conditions or user interaction |
| Low | minor issues with a clear fix |

The current amounts are published in the bounty thread on bitcointalk and on the website. Severity
is decided by the team after reproducing the report. Amounts may change for new reports; a reward
already agreed is not reduced. Team members and their households are not eligible. These are
participation rewards for helping the project, not an income.

Crypto-assets are volatile and largely unregulated; their value can fall to zero. Nothing here is
financial or investment advice.
