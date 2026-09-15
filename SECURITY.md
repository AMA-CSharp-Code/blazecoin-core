# Security Policy

## Supported versions

Only the latest release on the Releases page is supported. Pre-fork clients (V1.5.1 and earlier, and the 2014
0.8.6.2 client) cannot follow the chain past block 4,194,000 and receive no fixes. V1.5.2 follows the chain
only up to the post-quantum fork at block 4,250,000, where it is retired, and receives no fixes. V2 releases
before 2.1.0 stop at the first post-quantum spend after block 4,250,000; run 2.1.0 or later.

## Reporting a vulnerability

Please do not open a public issue for anything that could put coins or nodes at risk. E-mail
**admin@blazecoin.co.uk** with a description and, if you have one, a proof of concept. You will get an
acknowledgement, and a fix or a mitigation before any public disclosure. Consensus-affecting reports
are handled with the same care Bitcoin Core applies: privately, with coordinated release notes.

## Scope

The daemon, its RPC surface, the wallet code, the Phoenix-413 retarget implementation and the P2PQH
post-quantum output type including the vendored ML-DSA-44 implementation (`src/crypto/mldsa/`). Reports
against the website, the mining pool or the lite-wallet gateways are welcome at the same address.
