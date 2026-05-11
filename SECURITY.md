# Security Policy

## Scope

This policy covers the public BSH source published at https://github.com/BetonDev/bsh and the deployed `beton` and `bsh` Solana programs.

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

The following operational invariants are part of the program security model and
MUST be in place before each mainnet upgrade. Auditors and downstream
integrators may verify these on-chain at any time.

### Upgrade authority — multisig required before production cutover

Both `beton` (`BpwBgBZ8WFDk7BswjJNoepmisZS1KfuoKbybCLaF5Hj6`) and `bsh`
(`91ahrFntCbnRAcJhsSQGd4j2QNdiUZTbESA6cJYKeovn`) program upgrade authorities
MUST be set to a Squads (or equivalent) multisig with **threshold ≥ 2 of 3**
human-controlled keys held by separate operators on hardware wallets.

Temporary exception for a fresh deployment and validation window:

1. A single operator-controlled EOA may hold upgrade authority only for the
   narrow deployment, initialization, and private testing window immediately
   after a fresh publish.
2. That temporary authority state is not production-ready and must not be the
   final public operating state.
3. After deployment checks and smoke tests pass, both programs MUST transfer
   upgrade authority to the configured multisig before public production
   cutover.

Verification:

```sh
solana program show BpwBgBZ8WFDk7BswjJNoepmisZS1KfuoKbybCLaF5Hj6 --url mainnet-beta
solana program show 91ahrFntCbnRAcJhsSQGd4j2QNdiUZTbESA6cJYKeovn --url mainnet-beta
```

The reported `Authority` must equal the configured multisig vault PDA before
public production cutover. A single EOA upgrade authority is **not acceptable**
as the final production state.

### Treasury & jackpot signing keys

`beton` `fee_treasury_*` recipients and the `bsh` upgrade-authority signer used
for `init_jackpot`, `init_reward_*`, `set_reward_campaign_active`, and
`close_reward_campaign` MUST also be multisig-controlled. Treasury rotations
must follow the same multisig review path; ad-hoc rotation via a hot key is
prohibited on mainnet.

### Browser RPC ingress

The public browser RPC path MUST terminate behind a reverse proxy that
overwrites the configured `TRUSTED_CLIENT_IP_HEADER` before forwarding to the
Next.js app. Client-supplied copies of that header must be stripped.

Production browser traffic must use `/api/solana-rpc-public` for read and
simulation methods only. The protected `/api/solana-rpc` route is reserved for
server-side checks and operator tooling authenticated by
`SOLANA_RPC_PROXY_TOKEN`.

### IDL pinning

The IDLs published to chain (`anchor idl init` / `anchor idl upgrade`) MUST match the
git-tagged release used for the on-chain binary, byte-for-byte. CI must fail
if `anchor build` produces a diff against the committed
`anchor/target/idl/*.json` artefacts. Off-chain clients should pin to the
checked-in IDL JSON, not the chain-fetched one, until each upgrade is reviewed.

### Pre-deploy checklist

Before each mainnet `solana program deploy` or `anchor program upgrade`:

1. `cargo test -p beton --lib` and `cargo test -p bsh --lib` pass on the exact
   commit being shipped.
2. `cargo build-sbf` artefacts in `anchor/target/deploy/{beton,bsh}.so` were
   produced from a clean checkout of the same commit (no local `target/`
   cache).
3. The shipped commit hash is recorded alongside the on-chain program-data
   slot in the release ledger.
4. The pinned discriminator regression
   (`mollusk_reset_win_streak_discriminator_pinned`) is green — guarantees
   the bsh→beton CPI path remains valid for the deployed beton build.

### Pause-switch (deferred)

A first-class pause switch (a `PauseSwitch` PDA gating every mutating
handler) is **not** present in the current programs. Until it lands, incident
response relies on the upgrade authority to ship a hot-fix that early-returns
from the affected handlers.

Implementing the pause switch requires:

- A new `PauseSwitch { paused: bool, authority: Pubkey, bump: u8 }` PDA per
  program.
- `init_pause_switch` and `set_paused` instructions, both gated on the
  multisig upgrade authority.
- An additional `pause: Account<'info, PauseSwitch>` constraint on every
  mutating `Accounts` struct, with `require!(!pause.paused, BshError::Paused)`
  (or `BetonError::Paused`) at the top of each handler.
- IDL re-publish — this is a breaking change for downstream signers.

This work is tracked as a post-launch hardening item; ship only with the
multisig and incident-response runbook in place above.
