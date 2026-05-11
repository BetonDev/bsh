# Security Policy

## Scope

This policy covers the public BSH source published at https://github.com/BetonDev/bsh and the deployed `bsh` Solana program.

## Reporting A Vulnerability

Report vulnerabilities privately to betondev@proton.me.

Include the affected program, network, program ID, reproduction steps, expected impact, and any proof of concept needed to validate the issue.

Do not publicly disclose the issue before a fix is available.
Do not access, move, or place user funds at risk.
Do not degrade service availability or perform denial-of-service testing against production infrastructure.

Valid reports are reviewed and handled as coordinated disclosures. Any acknowledgements or bug bounty payouts are at the project's discretion.

## Disclosure Process

After validating a report, the project will work toward a fix and coordinate public disclosure once remediation is available.

## Operational Hardening (Mainnet)

The following operational invariants are part of the production security model and MUST hold before each mainnet deploy or upgrade of `bsh`.

### Upgrade authority

The deployed `bsh` program retains a single offline upgrade authority. That key is not a day-to-day operator credential.

Rules:

1. Use the upgrade authority only for audited program deploys, authority rotation, or final authority revocation.
2. Whenever the upgrade authority is brought online and used, transfer program upgrade authority immediately to a fresh offline key.
3. Never expose the upgrade-authority keypair online except for dedicated single use.

Verification:

```sh
solana program show 91ahrFntCbnRAcJhsSQGd4j2QNdiUZTbESA6cJYKeovn --url mainnet-beta
```

### BSH lifecycle hardening

`bsh` may retain upgrade authority while audited lifecycle changes are still expected. The intended end state after the fixed sale and bounty lifecycle is a swap-only surface followed by authority revocation once the code is considered final.

### No pause mechanism

The current production posture intentionally does not include a pause switch or admin circuit breaker in `bsh`.

Rules:

1. Sale, swap, claim, and auto-close flows rely on the authority model explicitly coded into the program; there is no separate pause PDA.
2. Incident response falls back to the existing upgrade authority model and, if needed, an audited program upgrade.

### IDL pinning

The BSH IDL published to chain (`anchor idl init` / `anchor idl upgrade`) MUST match the reviewed release used for the on-chain binary, byte-for-byte. Off-chain clients should pin to the reviewed release IDL rather than blindly trusting a chain-fetched copy before each upgrade is audited.

### Verified-build provenance

The mainnet `bsh.so` artifact MUST be reproducible from the exact public GitHub commit referenced by the on-chain BSH security metadata.

Rules:

1. The public repo URL, security-policy URL, and audit-report URL referenced by BSH on-chain metadata must all resolve at release time.
2. After the verified build completes, the deploy must use that exact artifact without rebuilding or replacing it.

### Pre-deploy checklist

Before each mainnet `solana program deploy` or `anchor program upgrade` of `bsh`:

1. `cargo test -p bsh --lib` passes on the exact commit being shipped.
2. The shipped `bsh.so` was produced by the verified-build pipeline from the exact public GitHub commit referenced by on-chain security metadata.
3. The shipped commit hash and artifact digest are recorded alongside the on-chain program-data slot in the release ledger.
4. The security-metadata URLs in `anchor/programs/bsh/src/lib.rs` still point at the same public repo, policy file, and audit report used for the release.
