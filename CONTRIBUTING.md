# Contributing

Blazecoin Core V2 is a Bitcoin Core 28 fork with a small, deliberate set of changes: the chain
parameters, the scrypt proof-of-work, the 30-second block schedule, the Phoenix-413 retarget and the
P2PQH post-quantum output type (ML-DSA-44, active from block 4,250,000).
Upstream's code style, test layout and review habits apply.

- **Consensus changes** are not accepted as ordinary pull requests. Open an issue first; anything that
  changes block validity needs a specification, test vectors, and a coordinated activation height.
- **Everything else** — build fixes, tests, documentation, RPC ergonomics — is welcome as a pull request
  against `main`. Keep upstream files as close to Bitcoin Core as possible so future rebases stay
  tractable; put Blazecoin-specific logic where the existing Blazecoin changes already live.
- **Tests**: `test/functional/` and the unit-test binary must pass. The Phoenix-413 vectors in
  `PHOENIX_413.md` are the ground truth for the retarget; the P2PQH vectors in `test/pqsig/` are the
  ground truth for post-quantum signing and verification.
- **Licence**: contributions are accepted under the MIT licence in `COPYING`.
