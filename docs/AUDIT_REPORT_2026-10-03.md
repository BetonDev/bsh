# BSH Program Security Audit

| Item          | Detail                                                                 |
| ------------- | --------------------------------------------------------------------- |
| Review date   | 2026-10-03                                                            |
| Target        | `anchor/programs/bsh` (crate `bsh` v1.4.2) + `anchor/crates/shared-types` |
| Commit basis  | `5425a22` ("beton HSVo / bsh v1.4.2 mainnet source")                 |
| Program ID    | `91ahrFntCbnRAcJhsSQGd4j2QNdiUZTbESA6cJYKeovn` (mainnet)             |
| Method        | Manual source review of all instruction handlers, account contexts, PDA/seed derivations, cross-program reads, value-movement paths, and build configuration; host compilation (`cargo check`). |
| Scope note    | On-chain program logic only. Off-chain clients, the beton program's own internals, RPC/indexer infrastructure, and key custody are out of scope. |

> This report documents a review performed on the owner's own source. One High-severity issue was found in the SOL funding (prefund) introspection used by the swap and locked-sale flows; a remediation is included in the same branch as this report. Readers should note the **deployed on-chain program remains affected until an audited upgrade ships the fix**.

---

## 1. Findings summary

| ID    | Title                                                                 | Severity      | Status in this branch |
| ----- | -------------------------------------------------------------------- | ------------- | --------------------- |
| H-1   | Prefund funding transfer is reusable across CPI-stacked swaps/buys  | **High**      | Fixed (code)          |
| L-1   | Published source cannot build its own test suite                     | Low           | Default path fixed    |
| I-1   | AMM has no fee and prices on fixed `total_supply`                    | Informational | Reported              |
| I-2   | Swap / locked-sale buy are now restricted to top-level invocation    | Informational | Documented            |
| I-3   | No `.gitignore`; build artifacts easy to commit by accident          | Informational | Fixed (added)         |

---

## 2. H-1 — Prefund funding transfer is reusable across CPI-stacked swaps/buys

**Severity:** High (unauthorized movement of protocol funds)
**Affected:** `swap_sol_for_bsh`, `buy_locked_bsh` via `validate_swap_sol_prefund` / `validate_locked_sale_prefund` (`src/lib.rs`)

### Description

Both the SOL→BSH swap and the locked-sale buy require the caller to pre-fund
the program's **payment router** with a plain `SystemProgram::transfer` placed
*immediately before* the program instruction. The handlers verify this by
reading the instructions sysvar:

```text
current_index = load_current_index_checked(sysvar)
require current_index > 0
funding_ix   = load_instruction_at_checked(current_index - 1, sysvar)
assert funding_ix is a System transfer: payer -> payment_router, amount == deposit/quote
```

The instructions sysvar's *current index* is the index of the executing
**top-level** transaction instruction, and the runtime does **not** advance it
across CPI. The handlers checked only that `current_index - 1` is a matching
transfer; they did **not** check that the handler itself was reached as a
direct top-level instruction.

Consequently a caller **program** can, inside a single top-level instruction,
invoke `swap_sol_for_bsh` (or `buy_locked_bsh`) by CPI more than once. Every
nested call reads the same `current_index` and therefore re-validates against
the *same* preceding funding transfer, while each call routes `deposited_lamports`
out of the payment router via `route_payment_router_lamports`.

The only remaining backstop, `require_payment_router_reserve`, merely requires
the router to retain its rent-exempt reserve after each route. The router does
not stay at its reserve in normal operation: the beton program routes its
reward/bonus platform fees into this shared router, where they accumulate until
someone calls the permissionless `distribute_payment_router`. Whenever the
router holds a balance above the reserve, an attacker can drain that excess:

- one real funding transfer of `d` lamports (the attacker's own SOL), then
- `N` CPI calls each routing `d` out of the router, where
  `N - 1 ≈ (router_balance − rent_reserve) / d`.

The extra routes are paid for out of the router's pre-existing balance (beton
fees pending distribution), not the attacker's funds. For each routed `d` the
attacker receives BSH (swap) or locked-sale BSH (buy) at the on-chain price.
Net effect: the router's pending fees are converted into BSH owned by the
attacker — the treasury's share of those fees is lost and vault/sale inventory
is extracted for SOL the attacker never provided. The per-transaction loss is
bounded by the router's excess balance and the compute budget, and the attack
is repeatable as the router re-accumulates fees.

`swap_bsh_for_sol` and `distribute_payment_router` are unaffected (no prefund
introspection / fixed canonical routing).

### Remediation (applied in this branch)

Require the executing instruction to be a **direct top-level invocation of the
bsh program** before trusting `current_index - 1`. When the program is reached
by CPI, the instruction at `current_index` belongs to the *caller* program
(program id ≠ bsh), so the guard rejects it and CPI-stacking is impossible. A
legitimate top-level `[transfer, swap]` / `[transfer, buy]` transaction is
unaffected.

```rust
fn is_top_level_bsh_invocation(sysvar: &AccountInfo, current_index: usize) -> Result<bool> {
    let current_ix = load_instruction_at_checked(current_index, sysvar)?;
    Ok(current_ix.program_id == crate::ID)
}
// ...checked in both validate_swap_sol_prefund and validate_locked_sale_prefund.
```

Two error codes (`SwapMustBeTopLevel`, `LockedSaleMustBeTopLevel`) were
**appended** to `BshError` so existing error-code discriminants are unchanged.

### Residual / operational note

This source change does not alter the already-deployed binary. Until an audited
upgrade ships, operators should keep the payment router drained (call
`distribute_payment_router` promptly / keep its excess balance low) to minimize
the exploitable amount, and monitor swap/buy events whose routed SOL exceeds the
caller's net lamport outflow.

### Suggested follow-up test

Add a regression test (second on-chain program that CPIs the swap twice behind a
single transfer) asserting the second nested call fails with
`SwapMustBeTopLevel`. This requires the test harness in finding L-1 to build
first.

---

## 3. L-1 — Published source cannot build its own test suite

**Severity:** Low (no on-chain bytecode impact; release-process / reproducibility integrity)

`src/lib.rs` declares `mod mollusk_tests;` and `mod program_tests;`, but those
files are **not present** in the published tree, and no `[dev-dependencies]`
(`mollusk-svm`, `solana-sdk`) are declared, so the inline `#[cfg(test)] mod
tests` also fails to resolve its imports (plus an `Account` name collision
between `solana_sdk::account::Account` and the Anchor prelude). `cargo test -p
bsh --lib` therefore fails at **compile time** on the published commit:

```
error[E0583]: file not found for module `mollusk_tests`
error[E0583]: file not found for module `program_tests`
error[E0433]: cannot find module or crate `solana_sdk` / `mollusk_svm`
error[E0107]: missing generics for struct `anchor_lang::...::Account`
```

This directly contradicts `SECURITY.md`:

- Pre-deploy checklist item 1 states `cargo test -p bsh --lib` must pass on the
  exact shipped commit — it cannot even compile on the published commit.
- The "Verified-build provenance" section states the mainnet artifact must be
  reproducible from the exact public commit; anyone running the documented
  verification will hit this breakage.

The program's compiled bytecode is unaffected (tests are not linked into the
`.so`), so this is not an exploitable on-chain flaw — but it undermines the
stated verification workflow and provenance guarantees.

**Remediation applied in this branch (default test path):**

- Removed the two dangling `mod mollusk_tests; / mod program_tests;`
  declarations (those external suites were omitted from the public tree and
  cannot be restored faithfully here).
- Added the missing dev-dependency (`solana-instruction`) and moved the
  pure-logic unit tests into a `logic_tests` module.
- The inline Mollusk harness needs a prebuilt SBF artifact and the full Solana
  test toolchain, so it is now gated behind an opt-in `sbf-tests` cargo feature
  (`mollusk-svm` / `solana-sdk` are declared as optional dependencies). It is
  preserved for the team's own toolchain; it was **not** compiled in the audit
  sandbox, whose `rustc 1.97.0` is below the `1.97.1` required by mollusk-svm's
  transitive Solana-SVM crates, and its version pins may need alignment with the
  team's toolchain.

As a result, `cargo test -p bsh --lib` now compiles and passes (18 tests,
including the H-1 regression tests below) with a plain stable toolchain and no
SBF artifact — restoring the default verification path. The full
`SECURITY.md` gate (which also exercises the Mollusk integration tests) still
requires the team to restore the omitted external suites and/or run
`cargo test -p bsh --features sbf-tests` after `anchor build --features
test-mode`; `SECURITY.md` should be updated to describe this split, or the
external suites re-added.

**H-1 regression tests (added here, run by default):** `logic_tests` builds a
synthetic instructions sysvar reproducing the account state a CPI-stacked call
produces (the top-level instruction at the sysvar's current index is a foreign
program; the reused funding transfer sits at `current_index - 1`) and asserts
`validate_swap_sol_prefund` / `validate_locked_sale_prefund` now reject it with
`SwapMustBeTopLevel` / `LockedSaleMustBeTopLevel`, plus positive cases for a
genuine top-level call. These lock in the H-1 fix without a second on-chain
program or the SBF toolchain. An end-to-end two-program CPI test under
`sbf-tests` remains a nice-to-have.

---

## 4. Informational observations

### I-1 — AMM has no swap fee and prices on fixed `total_supply`

The swap prices tokens as `p = sol_vault_net_balance / total_supply` with
`total_supply` fixed at 100,000. Buy uses the post-deposit balance and sell uses
the pre-withdrawal balance, so an atomic buy→sell round-trip is value-neutral
apart from integer truncation (which rounds in the protocol's favor) — a good
anti-arbitrage property. There is, however, no spread for the protocol to accrue
value from swap volume, and the linear price can be moved by large trades or
when the vault's SOL/token balance is low. This is a design choice, not a
defect; keep swap-flow telemetry as a monitoring control.

### I-2 — Swap / locked-sale buy are top-level-only (consequence of the H-1 fix)

After the H-1 remediation, `swap_sol_for_bsh` and `buy_locked_bsh` must be
issued as top-level instructions, each immediately preceded by the
`SystemProgram::transfer` that funds the payment router. They can no longer be
composed through a wrapper program via CPI. This was already implicitly required
by the prefund design; integrators should confirm their clients submit these as
top-level instructions.

### I-3 — No `.gitignore`

The repository had no `.gitignore`, so `anchor/target/` (build artifacts,
keypairs under `target/deploy`) is untracked and easy to commit by accident —
which would bloat the "verified-build source" and risk leaking a stray program
keypair. A minimal `.gitignore` was added in this branch.

---

## 5. Strengths observed

- Cross-program reads of beton `Activity` / `UserProfile` / `ReferralLink` are
  constrained by owner (via the shared-types `Owner` pinning) **and** seed
  derivation with `seeds::program = BETON_PROGRAM_ID`, so foreign/forged
  accounts are rejected; bsh holds no write authority over beton state.
- Value movement uses checked arithmetic with `overflow-checks = true`, and swap
  math consistently rounds in the protocol's favor.
- Treasury, inventory wallet, and mint addresses are pinned by address
  constraints; the sale/swap/bounty inventories are kept isolated and re-derived
  at every call site (defense-in-depth).
- Bounty / referral-bounty funds are locked with no authority drain or timed
  sweep — residual unclaimed BSH stays locked (no-rug guarantee).
- Double-claim protection uses explicit `initialized` flags rather than a
  `bump == 0` sentinel; per-wallet claim PDAs and per-milestone caps are
  enforced.
- `GlobalState` is version-gated and re-asserted on every read, with a
  dedicated, upgrade-authority-gated legacy migration path.

---

## 6. Disclaimer

This review is a best-effort manual assessment of the on-chain source at the
commit noted above. It is not a guarantee of correctness or of the absence of
other vulnerabilities, and it does not cover off-chain services, the beton
program's internals, deployment custody, or economic/game-theoretic design.
Operators remain responsible for release verification, key management, and
independent validation of deployed artifacts.
