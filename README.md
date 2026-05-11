# bsh

Public source repository for the BSH Solana program.

BSH is the Beton ecosystem token program deployed at `91ahrFntCbnRAcJhsSQGd4j2QNdiUZTbESA6cJYKeovn`.

The program currently implements:

- one-time initialization of global state and locked inventory
- a fixed-price sale of 60,000 BSH across three sale tiers
- permissionless SOL -> BSH and BSH -> SOL swap flows against the program vault
- milestone bounty claims from a dedicated 5,000 BSH bounty allocation
- permissionless close paths for exhausted sale and bounty vaults

This public repo is the source referenced by BSH on-chain `security.txt` metadata and by the verified-build release flow.

For vulnerability reporting and operational security policy, see `SECURITY.md`.
