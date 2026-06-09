#![allow(unexpected_cfgs)]
#![allow(clippy::diverging_sub_expression)]
#![cfg_attr(
    feature = "check-cfg",
    check_cfg(
        feature,
        values(
            "anchor-debug",
            "custom-heap",
            "custom-panic",
            "cpi",
            "default",
            "idl-build",
            "no-entrypoint",
            "no-idl",
            "no-log-ix-name",
            "test-mode"
        )
    )
)]

// Audit notes (deferred or compatibility-scoped):
//   * M10 — Historical coverage note retired. The prior follow-ups no longer
//     describe live risk: `BuyLockedBsh` caps each purchase at 5_000 BSH, so
//     a >10_000-BSH single-call cross-tier case is unreachable; the
//     `fee_treasury_1` sink is pinned by address constraints; and the current
//     suite now covers prefunding, stale quotes, sold-out close-out, swap
//     balance updates, and bounty authority validation. An exact rent-reserve
//     boundary regression remains nice-to-have only, not a deployment blocker.
//   * L7 — Current policy intentionally does not add a paused mode.
//     `GlobalState` keeps reserve bytes for layout compatibility only, and
//     any future authority-bearing change must be justified on its own.
//     Sale bootstrap remains permissioned where explicitly modeled; swap,
//     claim, and auto-close paths stay permissionless so routine users are
//     not blocked by an admin-only circuit breaker.

use anchor_lang::{prelude::*, system_program};
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Mint, Token, TokenAccount},
};
use solana_instructions_sysvar::{
    load_current_index_checked, load_instruction_at_checked, ID as INSTRUCTIONS_SYSVAR_ID,
};
// Audit H1: match the on-chain program identity to the deployed address per
// network. The `mainnet` build feature embeds the canonical mainnet id; every
// other build (stage devnet, test-mode, IDL) keeps the devnet/stage identity,
// so a mainnet artifact can never be built with the wrong `declare_id`.
#[cfg(feature = "mainnet")]
declare_id!("91ahrFntCbnRAcJhsSQGd4j2QNdiUZTbESA6cJYKeovn");
#[cfg(not(feature = "mainnet"))]
declare_id!("7bSkdiZXEUtDT37RwefCJqCZRW9pviUPAAKFHqStkVzw");

// Audit C-2 (production hardening): require an explicit network feature
// for the on-chain build, mirroring the beton program.
#[cfg(all(feature = "mainnet", feature = "test-mode"))]
compile_error!("features `mainnet` and `test-mode` are mutually exclusive");
#[cfg(all(
    target_os = "solana",
    not(feature = "mainnet"),
    not(feature = "test-mode"),
    not(feature = "no-entrypoint"),
    not(feature = "idl-build"),
    not(test),
))]
compile_error!("bsh on-chain build must select exactly one of `mainnet` / `test-mode` features");

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "BSH",
    project_url: "https://github.com/BetonDev/bsh",
    contacts: "email:betondev@proton.me,link:https://github.com/BetonDev/bsh/security/policy",
    policy: "https://github.com/BetonDev/bsh/security/policy",
    preferred_languages: "en",
    source_code: "https://github.com/BetonDev/bsh",
    auditors: "https://github.com/BetonDev/bsh/blob/main/docs/PUBLIC_AUDIT_REPORT_2026-04-30.md",
    acknowledgements: "None published."
}

#[cfg(any(not(feature = "test-mode"), test))]
const BSH_MINT: Pubkey = pubkey!("3UyKBPAd6i9Ym1cf7aJsu2JEpGKT7QPUVtnmjykqUb6s");
const INVENTORY_WALLET: Pubkey = pubkey!("BN6M5dhF45eitvZYnux2NK24ZMZq258BqvHKbLVbAxNm");
const BETON_TREASURY_1: Pubkey = pubkey!("8REY953gpSbJNQmWd9bBbYGNw6x9VWudZ16r13MNmFax");
const TOTAL_SUPPLY: u64 = 100_000;
// New sale schedule (60_000 BSH locked, three tiers):
//   Tier 1 — 30 000 BSH @ 0.1 SOL  (100_000_000     lamports)
//   Tier 2 — 20 000 BSH @ 0.5 SOL  (500_000_000     lamports)
//   Tier 3 — 10 000 BSH @ 1.0 SOL  (1_000_000_000   lamports)
// Total sale lock = 60 000 BSH; the separate bounty lock consumes another
// 5 000 BSH, so 35 000 BSH remain in the inventory wallet after initialize.
const LOCKED_SUPPLY: u64 = 60_000;
const SALE_MIN_PURCHASE: u64 = 1;
const SALE_MAX_PURCHASE: u64 = 5_000;
const SALE_TIERS: &[(u64, u64)] = &[
    (30_000, 100_000_000),
    (20_000, 500_000_000),
    (10_000, 1_000_000_000),
];
const STATE_SEED: &[u8] = b"state";
const SOL_VAULT_SEED: &[u8] = b"sol_vault";
const PAYMENT_ROUTER_SEED: &[u8] = b"payment_router";
const MIN_PAYMENT_ROUTER_DISTRIBUTION_LAMPORTS: u64 = 10_000;
// Small data allocation so the vault PDA persists rent-exempt.
const SOL_VAULT_SPACE: usize = 8;

// New module added in v3.2 — bounty (preload-style milestone payouts).
// Replaces the legacy jackpot/reward modules that have been moved into
// the upgradable beton program.
pub mod bounty;

// v3.5 — referral bounty: capped BSH milestone payouts to referrers plus a
// one-time welcome bounty to referents. Funded by a separate vault from the
// activity `bounty` module; reads beton's `UserProfile` / `ReferralLink` /
// `Activity` cross-program with strict owner + seed checks.
pub mod referral_bounty;

// Anchor's `#[program]` macro generates `crate::__client_accounts_<snake>`
// for each `Context<Foo>` argument, where the `__client_accounts_*` modules
// are emitted next to each `#[derive(Accounts)]` definition. Re-export at
// crate root so they are visible at the path the macro expects.
#[allow(ambiguous_glob_reexports)]
pub use bounty::*;
#[allow(ambiguous_glob_reexports)]
pub use referral_bounty::*;

#[program]
pub mod bsh {
    use super::*;

    /// Initialize the BSH global state and lock the sale inventory.
    ///
    /// Permissioned: the program upgrade authority must sign as `authority`,
    /// and the canonical `INVENTORY_WALLET` must sign as `inventory_owner`
    /// to transfer `LOCKED_SUPPLY` BSH from inventory into the sale ATA. The
    /// handler verifies that the mint authority and freeze authority are
    /// already cleared, that mint decimals are 0, and that the post-transfer
    /// vault/sale ATA balances match the protocol invariants.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ensure_system_account(&ctx.accounts.authority.to_account_info())?;
        ensure_system_account(&ctx.accounts.inventory_owner.to_account_info())?;

        #[cfg(not(feature = "test-mode"))]
        require_keys_eq!(ctx.accounts.mint.key(), BSH_MINT, BshError::InvalidBshMint);
        #[cfg(not(feature = "test-mode"))]
        require_keys_eq!(
            ctx.accounts.inventory_owner.key(),
            INVENTORY_WALLET,
            BshError::InvalidInventoryWallet
        );

        let bumps = ctx.bumps;
        let state_bump = bumps.state;
        let vault_bump = bumps.sol_vault;

        {
            let state = &mut ctx.accounts.state;
            state.version = GLOBAL_STATE_VERSION;
            state.mint = ctx.accounts.mint.key();
            state.sol_vault = ctx.accounts.sol_vault.key();
            state.vault_token_account = ctx.accounts.vault_token_account.key();
            state.sale_token_account = ctx.accounts.sale_token_account.key();
            state.total_supply = TOTAL_SUPPLY;
            state.bumps = Bumps {
                state: state_bump,
                // Legacy field retained for account compatibility after moving to an external mint.
                mint: 0,
                vault: vault_bump,
            };
            state._reserved = [0u8; 23];
            state.last_swap_slot = 0;
        }

        validate_locked_inventory_layout(
            ctx.accounts.state.key(),
            ctx.accounts.mint.key(),
            ctx.accounts.sol_vault.key(),
            ctx.accounts.state.vault_token_account,
            ctx.accounts.state.sale_token_account,
        )?;

        require_eq!(ctx.accounts.mint.decimals, 0, BshError::InvalidMintDecimals);
        require_eq!(
            ctx.accounts.mint.supply,
            TOTAL_SUPPLY,
            BshError::InvalidInitialSupply
        );
        require!(
            ctx.accounts.mint.mint_authority.is_none(),
            BshError::MintAuthorityStillSet
        );
        require!(
            ctx.accounts.mint.freeze_authority.is_none(),
            BshError::FreezeAuthorityStillSet
        );
        require!(
            ctx.accounts.inventory_token_account.amount
                >= LOCKED_SUPPLY + bounty::BOUNTY_LOCKED_SUPPLY,
            BshError::InsufficientLockedInventory
        );

        // 1) Sale lock: 60_000 BSH -> sale_token_account.
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                token::Transfer {
                    from: ctx.accounts.inventory_token_account.to_account_info(),
                    to: ctx.accounts.sale_token_account.to_account_info(),
                    authority: ctx.accounts.inventory_owner.to_account_info(),
                },
            ),
            LOCKED_SUPPLY,
        )?;

        // 2) Bounty lock: 5_000 BSH -> bounty_token_account (atomic).
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                token::Transfer {
                    from: ctx.accounts.inventory_token_account.to_account_info(),
                    to: ctx.accounts.bounty_token_account.to_account_info(),
                    authority: ctx.accounts.inventory_owner.to_account_info(),
                },
            ),
            bounty::BOUNTY_LOCKED_SUPPLY,
        )?;

        bounty::initialize_bounty_config(
            &mut ctx.accounts.bounty_config,
            ctx.accounts.mint.key(),
            ctx.accounts.bounty_token_account.key(),
            bounty::BountyInitBumps {
                config: bumps.bounty_config,
                authority: bumps.bounty_authority,
            },
        )?;

        ctx.accounts.inventory_token_account.reload()?;
        ctx.accounts.vault_token_account.reload()?;
        ctx.accounts.sale_token_account.reload()?;
        ctx.accounts.bounty_token_account.reload()?;

        require_eq!(
            ctx.accounts.vault_token_account.amount,
            0,
            BshError::VaultBalanceMismatch
        );

        require_eq!(
            ctx.accounts.sale_token_account.amount,
            LOCKED_SUPPLY,
            BshError::SaleBalanceMismatch
        );

        require_eq!(
            ctx.accounts.bounty_token_account.amount,
            bounty::BOUNTY_LOCKED_SUPPLY,
            BshError::BountyBalanceMismatch
        );

        emit!(bounty::BountyInitializedEvent {
            mint: ctx.accounts.mint.key(),
            vault_token_account: ctx.accounts.bounty_token_account.key(),
            locked_supply: bounty::BOUNTY_LOCKED_SUPPLY,
        });

        Ok(())
    }

    /// Purchase locked BSH at the active sale tier.
    ///
    /// Permissionless. `amount` is the number of BSH (decimals = 0) the
    /// payer wants and must be within `[SALE_MIN_PURCHASE, SALE_MAX_PURCHASE]`.
    /// `quoted_lamports_in` is the exact SOL amount that must already have
    /// been transferred into the system-owned payment router by the
    /// immediately preceding top-level `SystemProgram::Transfer`. The handler
    /// recomputes the tiered price from on-chain state and rejects stale
    /// quotes so the wallet preview and final debit stay aligned.
    pub fn buy_locked_bsh(
        ctx: Context<BuyLockedBsh>,
        amount: u64,
        quoted_lamports_in: u64,
    ) -> Result<()> {
        require!(
            (SALE_MIN_PURCHASE..=SALE_MAX_PURCHASE).contains(&amount),
            BshError::SaleAmountOutOfRange
        );
        ensure_system_account(&ctx.accounts.payer.to_account_info())?;

        validate_locked_sale_common(
            &ctx.accounts.state,
            &ctx.accounts.mint,
            &ctx.accounts.sol_vault.to_account_info(),
            &ctx.accounts.sale_token_account,
        )?;
        require_keys_eq!(
            ctx.accounts.payer_token_account.owner,
            ctx.accounts.payer.key(),
            BshError::TokenOwnerMismatch
        );
        require_keys_eq!(
            ctx.accounts.payer_token_account.mint,
            ctx.accounts.mint.key(),
            BshError::WrongMint
        );
        require!(
            ctx.accounts.sale_token_account.amount > 0,
            BshError::SaleExhausted
        );
        require!(
            ctx.accounts.sale_token_account.amount >= amount,
            BshError::InsufficientSaleTokens
        );

        let lamports_in = compute_locked_sale_cost(amount, ctx.accounts.sale_token_account.amount)?;
        require_eq!(
            lamports_in,
            quoted_lamports_in,
            BshError::LockedSaleQuoteMismatch
        );
        validate_locked_sale_prefund(
            &ctx.accounts.instructions,
            &ctx.accounts.payer.key(),
            &ctx.accounts.payment_router.key(),
            quoted_lamports_in,
        )?;
        require_payment_router_reserve(
            &ctx.accounts.payment_router.to_account_info(),
            quoted_lamports_in,
        )?;

        let shared_vsol_share = lamports_in / 2;
        let treasury_share = lamports_in
            .checked_sub(shared_vsol_share)
            .ok_or(BshError::MathOverflow)?;

        route_payment_router_lamports(
            &ctx.accounts.payment_router.to_account_info(),
            &ctx.accounts.sol_vault.to_account_info(),
            &ctx.accounts.system_program,
            ctx.bumps.payment_router,
            shared_vsol_share,
        )?;
        route_payment_router_lamports(
            &ctx.accounts.payment_router.to_account_info(),
            &ctx.accounts.fee_treasury_1.to_account_info(),
            &ctx.accounts.system_program,
            ctx.bumps.payment_router,
            treasury_share,
        )?;

        let signer_seeds: &[&[u8]] = &[STATE_SEED, &[ctx.accounts.state.bumps.state]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.key(),
                token::Transfer {
                    from: ctx.accounts.sale_token_account.to_account_info(),
                    to: ctx.accounts.payer_token_account.to_account_info(),
                    authority: ctx.accounts.state.to_account_info(),
                },
                &[signer_seeds],
            ),
            amount,
        )?;

        ctx.accounts.sale_token_account.reload()?;
        ctx.accounts.payer_token_account.reload()?;

        let remaining_locked_inventory = ctx.accounts.sale_token_account.amount;
        if remaining_locked_inventory == 0 {
            close_sale_vault_account(
                &ctx.accounts.state,
                &ctx.accounts.sale_token_account,
                &ctx.accounts.fee_treasury_1.to_account_info(),
                &ctx.accounts.token_program,
            )?;
        }

        emit!(LockedSaleEvent {
            buyer: ctx.accounts.payer.key(),
            tokens_purchased: amount,
            lamports_paid: lamports_in,
            shared_vsol_deposit: shared_vsol_share,
            beton_treasury_1_deposit: treasury_share,
            remaining_locked_inventory,
            sold_out: remaining_locked_inventory == 0,
        });

        Ok(())
    }

    /// Permissionlessly close the sale ATA once the locked inventory has been
    /// fully sold (`sale_token_account.amount == 0`).
    ///
    /// The reclaimed rent is forwarded to `fee_treasury_1`. This entrypoint
    /// is intentionally callable by anyone so the protocol cannot be locked
    /// out of reclaiming rent if no privileged caller is around.
    pub fn auto_close_sale_vault(ctx: Context<AutoCloseSaleVault>) -> Result<()> {
        validate_locked_sale_common(
            &ctx.accounts.state,
            &ctx.accounts.mint,
            &ctx.accounts.sol_vault.to_account_info(),
            &ctx.accounts.sale_token_account,
        )?;
        require_eq!(
            ctx.accounts.sale_token_account.amount,
            0,
            BshError::SaleVaultNotEmpty
        );

        close_sale_vault_account(
            &ctx.accounts.state,
            &ctx.accounts.sale_token_account,
            &ctx.accounts.fee_treasury_1.to_account_info(),
            &ctx.accounts.token_program,
        )
    }

    /// Swap SOL for BSH against the AMM vault.
    ///
    /// Permissionless. `deposited_lamports` must be > 0 and must already have
    /// been transferred into the system-owned payment router by the
    /// immediately preceding top-level `SystemProgram::Transfer`;
    /// `min_tokens_out` is a caller-provided slippage floor and the call
    /// reverts with `SlippageExceeded` if the AMM would yield fewer tokens.
    /// Swaps are allowed both during and after the fixed-price sale. The
    /// handler re-validates the locked-inventory layout, mint supply/decimals,
    /// and payer/vault ATA invariants on every call.
    pub fn swap_sol_for_bsh(
        ctx: Context<SwapSolForBsh>,
        deposited_lamports: u64,
        min_tokens_out: u64,
    ) -> Result<()> {
        require!(deposited_lamports > 0, BshError::InvalidAmount);
        ensure_system_account(&ctx.accounts.payer.to_account_info())?;

        validate_swap_common(
            &mut ctx.accounts.state,
            &ctx.accounts.mint,
            &ctx.accounts.sol_vault.to_account_info(),
            &ctx.accounts.vault_token_account,
        )?;
        require_keys_eq!(
            ctx.accounts.payer_token_account.owner,
            ctx.accounts.payer.key(),
            BshError::TokenOwnerMismatch
        );
        require_keys_eq!(
            ctx.accounts.payer_token_account.mint,
            ctx.accounts.mint.key(),
            BshError::WrongMint
        );

        let rent_reserve = Rent::get()?.minimum_balance(SOL_VAULT_SPACE);
        let pre_deposit_sol_balance = ctx
            .accounts
            .sol_vault
            .to_account_info()
            .lamports()
            .saturating_sub(rent_reserve);
        require!(pre_deposit_sol_balance > 0, BshError::PriceUnavailable);

        validate_swap_sol_prefund(
            &ctx.accounts.instructions,
            &ctx.accounts.payer.key(),
            &ctx.accounts.payment_router.key(),
            deposited_lamports,
        )?;
        require_payment_router_reserve(
            &ctx.accounts.payment_router.to_account_info(),
            deposited_lamports,
        )?;

        route_payment_router_lamports(
            &ctx.accounts.payment_router.to_account_info(),
            &ctx.accounts.sol_vault.to_account_info(),
            &ctx.accounts.system_program,
            ctx.bumps.payment_router,
            deposited_lamports,
        )?;

        // Use POST-deposit vault balance to price the swap.
        // Prevents atomic buy-sell arbitrage: round-trip returns
        // d * T / (S+d) * (S+d) / T = d  (neutral, minus truncation).
        let sol_balance = ctx
            .accounts
            .sol_vault
            .to_account_info()
            .lamports()
            .saturating_sub(rent_reserve);

        // Audit L-S1: this guard is mathematically dominated by the pre-deposit
        // check + `deposited_lamports > 0` (deposit only adds), but it is the
        // direct div-by-zero precondition for `compute_tokens_out` below. Keeping
        // it makes the safety property locally provable rather than relying on
        // reasoning about a separate function.
        require!(sol_balance > 0, BshError::PriceUnavailable);

        let tokens_out = compute_tokens_out(
            deposited_lamports,
            ctx.accounts.state.total_supply,
            sol_balance,
        )?;

        require!(tokens_out > 0, BshError::ZeroPayout);
        require!(tokens_out >= min_tokens_out, BshError::SlippageExceeded);
        require!(
            ctx.accounts.vault_token_account.amount >= tokens_out,
            BshError::InsufficientVaultTokens
        );

        transfer_bsh_from_swap_vault_for_swap(
            &ctx.accounts.sol_vault.to_account_info(),
            &ctx.accounts.vault_token_account,
            &ctx.accounts.payer_token_account,
            &ctx.accounts.token_program,
            ctx.accounts.state.bumps.vault,
            tokens_out,
        )?;

        ctx.accounts.vault_token_account.reload()?;
        ctx.accounts.payer_token_account.reload()?;

        let sol_after = ctx
            .accounts
            .sol_vault
            .to_account_info()
            .lamports()
            .saturating_sub(rent_reserve);

        emit!(SwapEvent {
            side: SwapSide::SolForBsh,
            actor: ctx.accounts.payer.key(),
            sol_change: deposited_lamports as i128,
            token_change: tokens_out as i128,
            vault_sol_balance: sol_after,
            vault_token_balance: ctx.accounts.vault_token_account.amount,
        });

        Ok(())
    }

    /// Swap BSH for SOL against the AMM vault.
    ///
    /// Permissionless. `amount` is the BSH (decimals = 0) the payer is
    /// burning into the vault; `min_lamports_out` is the slippage floor.
    /// Swaps are allowed both during and after the fixed-price sale. The
    /// handler enforces that the vault holds enough SOL, the user holds enough
    /// BSH, and that AMM math always rounds in the protocol's favor.
    pub fn swap_bsh_for_sol(
        ctx: Context<SwapBshForSol>,
        amount: u64,
        min_lamports_out: u64,
    ) -> Result<()> {
        require!(amount > 0, BshError::InvalidAmount);
        ensure_system_account(&ctx.accounts.payer.to_account_info())?;

        validate_swap_common(
            &mut ctx.accounts.state,
            &ctx.accounts.mint,
            &ctx.accounts.sol_vault.to_account_info(),
            &ctx.accounts.vault_token_account,
        )?;
        require_keys_eq!(
            ctx.accounts.user_token_account.owner,
            ctx.accounts.payer.key(),
            BshError::TokenOwnerMismatch
        );
        require_keys_eq!(
            ctx.accounts.user_token_account.mint,
            ctx.accounts.mint.key(),
            BshError::WrongMint
        );
        require!(
            ctx.accounts.user_token_account.amount >= amount,
            BshError::InsufficientUserTokens
        );

        let rent_reserve = Rent::get()?.minimum_balance(SOL_VAULT_SPACE);
        let sol_balance = ctx
            .accounts
            .sol_vault
            .to_account_info()
            .lamports()
            .saturating_sub(rent_reserve);
        require!(sol_balance > 0, BshError::InsufficientVaultSol);

        // Price is defined strictly as: SOL_vault_balance / total_supply (ignoring vault BSH).
        let lamports_out =
            compute_lamports_out(amount, ctx.accounts.state.total_supply, sol_balance)?;

        require!(lamports_out > 0, BshError::ZeroPayout);
        require!(lamports_out >= min_lamports_out, BshError::SlippageExceeded);
        require!(sol_balance >= lamports_out, BshError::InsufficientVaultSol);

        transfer_bsh_into_swap_vault_for_swap(
            &ctx.accounts.payer.to_account_info(),
            &ctx.accounts.user_token_account,
            &ctx.accounts.vault_token_account,
            &ctx.accounts.token_program,
            amount,
        )?;

        withdraw_sol_from_swap_vault_for_swap(
            &ctx.accounts.sol_vault.to_account_info(),
            &ctx.accounts.payer.to_account_info(),
            lamports_out,
        )?;

        ctx.accounts.vault_token_account.reload()?;
        ctx.accounts.user_token_account.reload()?;

        let sol_after = ctx
            .accounts
            .sol_vault
            .to_account_info()
            .lamports()
            .saturating_sub(rent_reserve);

        emit!(SwapEvent {
            side: SwapSide::BshForSol,
            actor: ctx.accounts.payer.key(),
            sol_change: -(lamports_out as i128),
            token_change: -(amount as i128),
            vault_sol_balance: sol_after,
            vault_token_balance: ctx.accounts.vault_token_account.amount,
        });

        Ok(())
    }

    /// Permissionlessly drain the BSH payment router into the swap SOL vault
    /// and treasury 1. Beton reward and bonus claims send their standard 2%
    /// platform fee here so BSH owns the final vault/treasury split.
    pub fn distribute_payment_router(ctx: Context<DistributePaymentRouter>) -> Result<()> {
        let router_info = ctx.accounts.payment_router.to_account_info();
        // Retain the rent-exempt reserve so the router (a 0-data system PDA)
        // never drops below rent-exempt. Draining it to 0 left it unable to
        // receive the sub-rent-exempt router share of Beton reward/jackpot
        // claims, which aborted those claims with InsufficientFundsForRent.
        // See docs/FOLLOWUP-router-rent-exemption.md.
        let rent_reserve = Rent::get()?.minimum_balance(0);
        let distributable = router_info.lamports().saturating_sub(rent_reserve);
        require!(
            distributable >= MIN_PAYMENT_ROUTER_DISTRIBUTION_LAMPORTS,
            BshError::PaymentRouterEmpty
        );

        let vault_share = distributable / 2;
        let treasury_share = distributable
            .checked_sub(vault_share)
            .ok_or(BshError::MathOverflow)?;

        route_payment_router_lamports(
            &router_info,
            &ctx.accounts.sol_vault.to_account_info(),
            &ctx.accounts.system_program,
            ctx.bumps.payment_router,
            vault_share,
        )?;
        route_payment_router_lamports(
            &router_info,
            &ctx.accounts.fee_treasury_1.to_account_info(),
            &ctx.accounts.system_program,
            ctx.bumps.payment_router,
            treasury_share,
        )?;

        emit!(PaymentRouterDistributedEvent {
            total: distributable,
            sol_vault: vault_share,
            fee_treasury_1: treasury_share,
        });

        Ok(())
    }

    /// Permissionlessly fund the BSH payment router up to rent-exempt reserve.
    /// Safe to call on fresh or already-initialized deployments; if the router
    /// is already rent-exempt the instruction is a no-op.
    pub fn top_up_payment_router(ctx: Context<TopUpPaymentRouter>) -> Result<()> {
        handle_top_up_payment_router(ctx)
    }

    // ---------- Bounty ------------------------------------------------

    /// First-100 wallets to reach 3 matched bets receive 5 BSH from the bounty
    /// vault. Independent of the other two milestones.
    pub fn claim_bounty_matched3(ctx: Context<ClaimBounty>) -> Result<()> {
        bounty::handle_claim_bounty_matched3(ctx)
    }

    /// First-100 wallets to win 3 bets receive 15 BSH.
    pub fn claim_bounty_win3(ctx: Context<ClaimBounty>) -> Result<()> {
        bounty::handle_claim_bounty_win3(ctx)
    }

    /// First-100 wallets to reach a 3-win streak receive 30 BSH.
    pub fn claim_bounty_streak3(ctx: Context<ClaimBounty>) -> Result<()> {
        bounty::handle_claim_bounty_streak3(ctx)
    }

    /// Permissionlessly close the bounty ATA once all three milestone caps
    /// have been reached and the vault is empty. Rent flows back to the
    /// canonical `INVENTORY_WALLET`.
    pub fn auto_close_bounty_vault(ctx: Context<AutoCloseBountyVault>) -> Result<()> {
        bounty::handle_auto_close_bounty_vault(ctx)
    }

    // ---- Referral bounty (v3.5) ----

    /// Upgrade-authority-gated. Creates the referral bounty config + vault ATA
    /// and atomically locks `REF_BOUNTY_LOCKED_SUPPLY` (20_000 BSH) from the
    /// canonical inventory wallet.
    pub fn initialize_referral_bounty(ctx: Context<InitializeReferralBounty>) -> Result<()> {
        referral_bounty::handle_initialize_referral_bounty(ctx)
    }

    /// Referrer claims every milestone tier they are newly eligible for, in a
    /// single instruction. Reads the referrer's beton `UserProfile` for
    /// cumulative volume + distinct active referent count.
    pub fn claim_referral_bounty(ctx: Context<ClaimReferralBounty>) -> Result<()> {
        referral_bounty::handle_claim_referral_bounty(ctx)
    }

    /// Referent claims the one-time 5 BSH welcome bounty after 3 matched bets
    /// and meeting the referred-volume floor.
    pub fn claim_referent_welcome(ctx: Context<ClaimReferentWelcome>) -> Result<()> {
        referral_bounty::handle_claim_referent_welcome(ctx)
    }

    /// Permissionlessly close the referral bounty ATA once every cap is hit and
    /// the vault is empty. Rent flows back to `INVENTORY_WALLET`.
    pub fn auto_close_referral_bounty_vault(
        ctx: Context<AutoCloseReferralBountyVault>,
    ) -> Result<()> {
        referral_bounty::handle_auto_close_referral_bounty_vault(ctx)
    }

    /// Upgrade-only migration path for legacy devnet state accounts that were
    /// initialized before `GlobalState` gained explicit versioning.
    pub fn migrate_legacy_state(ctx: Context<MigrateLegacyState>) -> Result<()> {
        handle_migrate_legacy_state(ctx)
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, InitSpace)]
struct LegacyGlobalState {
    pub mint: Pubkey,
    pub sol_vault: Pubkey,
    pub vault_token_account: Pubkey,
    pub sale_token_account: Pubkey,
    pub total_supply: u64,
    pub bumps: Bumps,
}

const LEGACY_GLOBAL_STATE_ACCOUNT_LEN: usize = 8 + LegacyGlobalState::INIT_SPACE;

fn read_legacy_global_state(account_info: &AccountInfo<'_>) -> Result<LegacyGlobalState> {
    let data = account_info
        .try_borrow_data()
        .map_err(|_| error!(BshError::UnsupportedLegacyStateLayout))?;
    require_eq!(
        data.len(),
        LEGACY_GLOBAL_STATE_ACCOUNT_LEN,
        BshError::UnsupportedLegacyStateLayout
    );
    require!(
        &data[..8] == GlobalState::DISCRIMINATOR,
        BshError::InvalidLegacyStateDiscriminator
    );

    let mut payload: &[u8] = &data[8..];
    let legacy = LegacyGlobalState::deserialize(&mut payload)
        .map_err(|_| error!(BshError::UnsupportedLegacyStateLayout))?;
    require!(
        payload.is_empty(),
        BshError::UnsupportedLegacyStateLayout
    );
    Ok(legacy)
}

fn handle_migrate_legacy_state(ctx: Context<MigrateLegacyState>) -> Result<()> {
    let state_info = ctx.accounts.state.to_account_info();
    let target_len = 8 + GlobalState::INIT_SPACE;
    let current_len = state_info.data_len();

    if current_len == target_len {
        return Ok(());
    }

    require_eq!(
        current_len,
        LEGACY_GLOBAL_STATE_ACCOUNT_LEN,
        BshError::UnsupportedLegacyStateLayout
    );

    let legacy_state = read_legacy_global_state(&state_info)?;
    let required_lamports = Rent::get()?.minimum_balance(target_len);
    let current_lamports = state_info.lamports();
    if required_lamports > current_lamports {
        anchor_lang::system_program::transfer(
            CpiContext::new(
                system_program::ID,
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.authority.to_account_info(),
                    to: state_info.clone(),
                },
            ),
            required_lamports.saturating_sub(current_lamports),
        )?;
    }

    state_info
        .resize(target_len)
        .map_err(|_| error!(BshError::UnsupportedLegacyStateLayout))?;

    let migrated_state = GlobalState {
        version: GLOBAL_STATE_VERSION,
        mint: legacy_state.mint,
        sol_vault: legacy_state.sol_vault,
        vault_token_account: legacy_state.vault_token_account,
        sale_token_account: legacy_state.sale_token_account,
        total_supply: legacy_state.total_supply,
        bumps: legacy_state.bumps,
        last_swap_slot: 0,
        _reserved: [0u8; 23],
    };

    let mut data = state_info
        .try_borrow_mut_data()
        .map_err(|_| error!(BshError::UnsupportedLegacyStateLayout))?;
    data[..8].copy_from_slice(GlobalState::DISCRIMINATOR);
    let mut payload: &mut [u8] = &mut data[8..];
    migrated_state
        .serialize(&mut payload)
        .map_err(|_| error!(BshError::UnsupportedLegacyStateLayout))?;
    Ok(())
}

fn validate_swap_common(
    state: &mut Account<GlobalState>,
    mint: &Account<Mint>,
    sol_vault: &AccountInfo,
    vault_token_account: &Account<TokenAccount>,
) -> Result<()> {
    require_eq!(
        state.version,
        GLOBAL_STATE_VERSION,
        BshError::UnsupportedStateVersion
    );
    // Availability now takes precedence over the retired global slot gate.
    // Keep the latest successful swap slot for telemetry without letting a
    // dust trade block every other wallet in the same block.
    state.last_swap_slot = Clock::get()?.slot;
    validate_locked_inventory_layout(
        state.key(),
        mint.key(),
        sol_vault.key(),
        state.vault_token_account,
        state.sale_token_account,
    )?;
    require_eq!(
        mint.supply,
        state.total_supply,
        BshError::StateSupplyMismatch
    );
    require_eq!(mint.decimals, 0, BshError::InvalidMintDecimals);
    require_keys_eq!(state.mint, mint.key(), BshError::StateMintMismatch);
    require_keys_eq!(
        state.sol_vault,
        sol_vault.key(),
        BshError::StateVaultMismatch
    );
    require_keys_eq!(
        state.vault_token_account,
        vault_token_account.key(),
        BshError::StateVaultAtaMismatch
    );
    require_keys_eq!(
        vault_token_account.owner,
        sol_vault.key(),
        BshError::VaultTokenOwnerMismatch
    );
    require_keys_eq!(vault_token_account.mint, mint.key(), BshError::WrongMint);
    require!(
        vault_token_account.delegate.is_none(),
        BshError::VaultDelegated
    );
    require!(
        vault_token_account.close_authority.is_none(),
        BshError::VaultCloseAuthoritySet
    );
    Ok(())
}

fn validate_locked_sale_common(
    state: &Account<GlobalState>,
    mint: &Account<Mint>,
    sol_vault: &AccountInfo,
    sale_token_account: &Account<TokenAccount>,
) -> Result<()> {
    require_eq!(
        state.version,
        GLOBAL_STATE_VERSION,
        BshError::UnsupportedStateVersion
    );
    validate_locked_inventory_layout(
        state.key(),
        mint.key(),
        sol_vault.key(),
        state.vault_token_account,
        state.sale_token_account,
    )?;
    require_eq!(
        mint.supply,
        state.total_supply,
        BshError::StateSupplyMismatch
    );
    require_eq!(mint.decimals, 0, BshError::InvalidMintDecimals);
    require_keys_eq!(state.mint, mint.key(), BshError::StateMintMismatch);
    require_keys_eq!(
        state.sol_vault,
        sol_vault.key(),
        BshError::StateVaultMismatch
    );
    require_keys_eq!(
        state.sale_token_account,
        sale_token_account.key(),
        BshError::StateSaleAtaMismatch
    );
    require_keys_eq!(
        sale_token_account.owner,
        state.key(),
        BshError::SaleTokenOwnerMismatch
    );
    require_keys_eq!(sale_token_account.mint, mint.key(), BshError::WrongMint);
    require!(
        sale_token_account.delegate.is_none(),
        BshError::SaleDelegated
    );
    require!(
        sale_token_account.close_authority.is_none(),
        BshError::SaleCloseAuthoritySet
    );
    Ok(())
}

fn validate_locked_sale_prefund(
    instructions_sysvar: &AccountInfo,
    payer: &Pubkey,
    payment_router: &Pubkey,
    quoted_lamports_in: u64,
) -> Result<()> {
    let current_index = usize::from(load_current_index_checked(instructions_sysvar)?);
    require!(
        current_index > 0,
        BshError::MissingLockedSaleFundingTransfer
    );

    let funding_ix = load_instruction_at_checked(current_index - 1, instructions_sysvar)
        .map_err(|_| error!(BshError::MissingLockedSaleFundingTransfer))?;

    validate_locked_sale_funding_transfer(&funding_ix, payer, payment_router, quoted_lamports_in)?;

    Ok(())
}

fn validate_swap_sol_prefund(
    instructions_sysvar: &AccountInfo,
    payer: &Pubkey,
    payment_router: &Pubkey,
    deposited_lamports: u64,
) -> Result<()> {
    let current_index = usize::from(load_current_index_checked(instructions_sysvar)?);
    require!(current_index > 0, BshError::MissingSwapFundingTransfer);

    let funding_ix = load_instruction_at_checked(current_index - 1, instructions_sysvar)
        .map_err(|_| error!(BshError::MissingSwapFundingTransfer))?;

    validate_swap_funding_transfer(&funding_ix, payer, payment_router, deposited_lamports)
}

fn validate_locked_sale_funding_transfer(
    funding_ix: &anchor_lang::solana_program::instruction::Instruction,
    payer: &Pubkey,
    recipient: &Pubkey,
    lamports_expected: u64,
) -> Result<()> {
    const SYSTEM_TRANSFER_DISCRIMINATOR: u32 = 2;

    require_keys_eq!(
        funding_ix.program_id,
        system_program::ID,
        BshError::InvalidLockedSaleFundingTransfer
    );
    require!(
        funding_ix.accounts.len() >= 2,
        BshError::InvalidLockedSaleFundingTransfer
    );
    require_keys_eq!(
        funding_ix.accounts[0].pubkey,
        *payer,
        BshError::InvalidLockedSaleFundingTransfer
    );
    require!(
        funding_ix.accounts[0].is_signer,
        BshError::InvalidLockedSaleFundingTransfer
    );
    require_keys_eq!(
        funding_ix.accounts[1].pubkey,
        *recipient,
        BshError::InvalidLockedSaleFundingTransfer
    );

    require!(
        funding_ix.data.len() == 12,
        BshError::InvalidLockedSaleFundingTransfer
    );

    let discriminator = u32::from_le_bytes(
        funding_ix.data[0..4]
            .try_into()
            .map_err(|_| error!(BshError::InvalidLockedSaleFundingTransfer))?,
    );
    require_eq!(
        discriminator,
        SYSTEM_TRANSFER_DISCRIMINATOR,
        BshError::InvalidLockedSaleFundingTransfer
    );

    let lamports = u64::from_le_bytes(
        funding_ix.data[4..12]
            .try_into()
            .map_err(|_| error!(BshError::InvalidLockedSaleFundingTransfer))?,
    );
    require_eq!(
        lamports,
        lamports_expected,
        BshError::InvalidLockedSaleFundingTransfer
    );

    Ok(())
}

fn validate_swap_funding_transfer(
    funding_ix: &anchor_lang::solana_program::instruction::Instruction,
    payer: &Pubkey,
    recipient: &Pubkey,
    lamports_expected: u64,
) -> Result<()> {
    const SYSTEM_TRANSFER_DISCRIMINATOR: u32 = 2;

    require_keys_eq!(
        funding_ix.program_id,
        system_program::ID,
        BshError::InvalidSwapFundingTransfer
    );
    require!(
        funding_ix.accounts.len() >= 2,
        BshError::InvalidSwapFundingTransfer
    );
    require_keys_eq!(
        funding_ix.accounts[0].pubkey,
        *payer,
        BshError::InvalidSwapFundingTransfer
    );
    require!(
        funding_ix.accounts[0].is_signer,
        BshError::InvalidSwapFundingTransfer
    );
    require_keys_eq!(
        funding_ix.accounts[1].pubkey,
        *recipient,
        BshError::InvalidSwapFundingTransfer
    );

    require!(
        funding_ix.data.len() == 12,
        BshError::InvalidSwapFundingTransfer
    );

    let discriminator = u32::from_le_bytes(
        funding_ix.data[0..4]
            .try_into()
            .map_err(|_| error!(BshError::InvalidSwapFundingTransfer))?,
    );
    require_eq!(
        discriminator,
        SYSTEM_TRANSFER_DISCRIMINATOR,
        BshError::InvalidSwapFundingTransfer
    );

    let lamports = u64::from_le_bytes(
        funding_ix.data[4..12]
            .try_into()
            .map_err(|_| error!(BshError::InvalidSwapFundingTransfer))?,
    );
    require_eq!(
        lamports,
        lamports_expected,
        BshError::InvalidSwapFundingTransfer
    );

    Ok(())
}

/// Validate the locked inventory layout (vault ATA, sale ATA, isolation).
///
/// Audit M7: this is invoked from three call sites — `initialize` and the
/// two flow-specific validators (`validate_swap_common`,
/// `validate_locked_sale_common`). The duplication is deliberate
/// defense-in-depth: each call site has independent account inputs and
/// must independently re-derive the canonical ATAs. Consolidating into a
/// single call site would weaken the per-flow guarantees.
fn validate_locked_inventory_layout(
    state: Pubkey,
    mint: Pubkey,
    sol_vault: Pubkey,
    vault_token_account: Pubkey,
    sale_token_account: Pubkey,
) -> Result<()> {
    require!(
        vault_token_account != sale_token_account,
        BshError::SaleInventoryMustRemainIsolated
    );

    let expected_vault_token_account =
        anchor_spl::associated_token::get_associated_token_address(&sol_vault, &mint);
    require_keys_eq!(
        vault_token_account,
        expected_vault_token_account,
        BshError::StateVaultAtaMismatch
    );

    let expected_sale_token_account =
        anchor_spl::associated_token::get_associated_token_address(&state, &mint);
    require_keys_eq!(
        sale_token_account,
        expected_sale_token_account,
        BshError::StateSaleAtaMismatch
    );

    Ok(())
}

// This defines the only swap-vault mutation surface inside the BSH program.
// It cannot prevent third-party inbound SOL or token transfers at the protocol layer.
//
// Audit I-S2 (cross-program contract): the Beton program calls this function
// indirectly via `system_program::transfer` to route the 0.5% protocol fee.
// Beton holds **no** delegated authority over `sol_vault` — the PDA is owned
// by this program and is only mutable by the swap and `auto_close_sale_vault`
// handlers below. From Beton's side, deposits are unconditional pure-SOL
// transfers; trust derives solely from the seed binding
// `seeds = [SOL_VAULT_SEED], seeds::program = BSH_PROGRAM_ID` enforced on
// Beton's `bsh_sol_vault` account meta. Do not add any signer-authority
// surface to the vault that would let an external program move funds.
fn transfer_bsh_from_swap_vault_for_swap<'info>(
    sol_vault: &AccountInfo<'info>,
    vault_token_account: &Account<'info, TokenAccount>,
    destination_token_account: &Account<'info, TokenAccount>,
    token_program: &Program<'info, Token>,
    vault_bump: u8,
    amount: u64,
) -> Result<()> {
    let signer_seeds: &[&[u8]] = &[SOL_VAULT_SEED, &[vault_bump]];

    token::transfer(
        CpiContext::new_with_signer(
            token_program.key(),
            token::Transfer {
                from: vault_token_account.to_account_info(),
                to: destination_token_account.to_account_info(),
                authority: sol_vault.clone(),
            },
            &[signer_seeds],
        ),
        amount,
    )
}

fn route_payment_router_lamports<'info>(
    payment_router: &AccountInfo<'info>,
    destination: &AccountInfo<'info>,
    system_program: &Program<'info, System>,
    payment_router_bump: u8,
    amount: u64,
) -> Result<()> {
    let signer_seeds: &[&[u8]] = &[PAYMENT_ROUTER_SEED, &[payment_router_bump]];

    system_program::transfer(
        CpiContext::new_with_signer(
            system_program.key(),
            system_program::Transfer {
                from: payment_router.clone(),
                to: destination.clone(),
            },
            &[signer_seeds],
        ),
        amount,
    )
}

fn transfer_bsh_into_swap_vault_for_swap<'info>(
    source_authority: &AccountInfo<'info>,
    source_token_account: &Account<'info, TokenAccount>,
    vault_token_account: &Account<'info, TokenAccount>,
    token_program: &Program<'info, Token>,
    amount: u64,
) -> Result<()> {
    token::transfer(
        CpiContext::new(
            token_program.key(),
            token::Transfer {
                from: source_token_account.to_account_info(),
                to: vault_token_account.to_account_info(),
                authority: source_authority.clone(),
            },
        ),
        amount,
    )
}

fn withdraw_sol_from_swap_vault_for_swap<'info>(
    sol_vault: &AccountInfo<'info>,
    recipient: &AccountInfo<'info>,
    amount: u64,
) -> Result<()> {
    let mut vault_lamports = sol_vault.try_borrow_mut_lamports()?;
    let mut recipient_lamports = recipient.try_borrow_mut_lamports()?;
    let new_vault_lamports = (**vault_lamports)
        .checked_sub(amount)
        .ok_or(BshError::MathOverflow)?;
    let new_recipient_lamports = (**recipient_lamports)
        .checked_add(amount)
        .ok_or(BshError::MathOverflow)?;
    **vault_lamports = new_vault_lamports;
    **recipient_lamports = new_recipient_lamports;
    Ok(())
}

fn close_sale_vault_account<'info>(
    state: &Account<'info, GlobalState>,
    sale_token_account: &Account<'info, TokenAccount>,
    destination: &AccountInfo<'info>,
    token_program: &Program<'info, Token>,
) -> Result<()> {
    let signer_seeds: &[&[u8]] = &[STATE_SEED, &[state.bumps.state]];

    token::close_account(CpiContext::new_with_signer(
        token_program.key(),
        token::CloseAccount {
            account: sale_token_account.to_account_info(),
            destination: destination.clone(),
            authority: state.to_account_info(),
        },
        &[signer_seeds],
    ))
}

fn compute_tokens_out(deposited_lamports: u64, total_supply: u64, sol_balance: u64) -> Result<u64> {
    if sol_balance == 0 {
        return err!(BshError::PriceUnavailable);
    }

    let numerator = (deposited_lamports as u128)
        .checked_mul(total_supply as u128)
        .ok_or(BshError::MathOverflow)?;
    let tokens_out_u128 = numerator
        .checked_div(sol_balance as u128)
        .ok_or(BshError::PriceUnavailable)?;
    u64::try_from(tokens_out_u128).map_err(|_| error!(BshError::MathOverflow))
}

fn compute_lamports_out(amount: u64, total_supply: u64, sol_balance: u64) -> Result<u64> {
    let numerator = (amount as u128)
        .checked_mul(sol_balance as u128)
        .ok_or(BshError::MathOverflow)?;
    let lamports_out_u128 = numerator
        .checked_div(total_supply as u128)
        .ok_or(BshError::MathOverflow)?;
    u64::try_from(lamports_out_u128).map_err(|_| error!(BshError::MathOverflow))
}

fn compute_locked_sale_cost(amount: u64, remaining_inventory: u64) -> Result<u64> {
    // Audit (2026-06-08): clamp `remaining_inventory` to `LOCKED_SUPPLY` before
    // deriving `sold_before`. Anyone can donate BSH into the state-owned sale ATA,
    // pushing its balance above `LOCKED_SUPPLY`; without the clamp the
    // `LOCKED_SUPPLY - remaining_inventory` subtraction underflowed and aborted
    // EVERY sale buy (and blocked auto-close) — a free DoS. Clamping treats an
    // over-funded ATA as "nothing sold yet" (tier-1 pricing), which is correct:
    // donated tokens are not legitimate sales.
    let mut sold_before = LOCKED_SUPPLY
        .checked_sub(remaining_inventory.min(LOCKED_SUPPLY))
        .ok_or(BshError::MathOverflow)?;
    let mut remaining_to_price = amount;
    let mut total_cost = 0u128;

    for (tier_amount, tier_price) in SALE_TIERS {
        if remaining_to_price == 0 {
            break;
        }

        if sold_before >= *tier_amount {
            sold_before -= *tier_amount;
            continue;
        }

        let available_in_tier = tier_amount - sold_before;
        let priced_amount = remaining_to_price.min(available_in_tier);
        total_cost = total_cost
            .checked_add((priced_amount as u128) * (*tier_price as u128))
            .ok_or(BshError::MathOverflow)?;
        remaining_to_price -= priced_amount;
        sold_before = 0;
    }

    require!(remaining_to_price == 0, BshError::InsufficientSaleTokens);

    u64::try_from(total_cost).map_err(|_| error!(BshError::MathOverflow))
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        constraint = program.programdata_address()? == Some(program_data.key()) @ BshError::InvalidProgramData
    )]
    pub program: Program<'info, crate::program::Bsh>,
    #[account(
        constraint = program_data.upgrade_authority_address == Some(authority.key()) @ BshError::UnauthorizedInitializer
    )]
    pub program_data: Account<'info, ProgramData>,
    #[account(
        init,
        payer = authority,
        space = 8 + GlobalState::INIT_SPACE,
        seeds = [STATE_SEED],
        bump
    )]
    // Audit H-5/H-7 (production hardening): boxed to keep `try_accounts`
    // stack frame under the 4 KiB BPF limit after the version + reserved
    // bytes were added to `GlobalState`.
    pub state: Box<Account<'info, GlobalState>>,
    #[account(
        init,
        payer = authority,
        space = SOL_VAULT_SPACE,
        seeds = [SOL_VAULT_SEED],
        bump
    )]
    /// CHECK: Vault is a program-owned PDA (validated via seeds)
    pub sol_vault: UncheckedAccount<'info>,
    #[account(
        init,
        payer = authority,
        space = 0,
        owner = system_program::ID,
        seeds = [PAYMENT_ROUTER_SEED],
        bump
    )]
    /// CHECK: System-owned lamports-only PDA used as the SOL payment router.
    pub payment_router: UncheckedAccount<'info>,
    pub inventory_owner: Signer<'info>,
    pub mint: Account<'info, Mint>,
    #[account(
        init,
        payer = authority,
        associated_token::mint = mint,
        associated_token::authority = sol_vault
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(
        init,
        payer = authority,
        associated_token::mint = mint,
        associated_token::authority = state
    )]
    pub sale_token_account: Account<'info, TokenAccount>,

    // ---- Bounty (atomic 5_000 BSH lock) ----
    #[account(
        init,
        payer = authority,
        space = 8 + bounty::BountyConfig::INIT_SPACE,
        seeds = [bounty::BOUNTY_CONFIG_SEED],
        bump
    )]
    pub bounty_config: Account<'info, bounty::BountyConfig>,
    #[account(
        seeds = [bounty::BOUNTY_AUTHORITY_SEED],
        bump
    )]
    /// CHECK: PDA — token authority for the bounty ATA.
    pub bounty_authority: UncheckedAccount<'info>,
    #[account(
        init,
        payer = authority,
        associated_token::mint = mint,
        associated_token::authority = bounty_authority
    )]
    pub bounty_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = inventory_token_account.owner == inventory_owner.key() @ BshError::TokenOwnerMismatch,
        constraint = inventory_token_account.mint == mint.key() @ BshError::WrongMint
    )]
    pub inventory_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MigrateLegacyState<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        constraint = program.programdata_address()? == Some(program_data.key()) @ BshError::InvalidProgramData
    )]
    pub program: Program<'info, crate::program::Bsh>,
    #[account(
        constraint = program_data.upgrade_authority_address == Some(authority.key()) @ BshError::UnauthorizedInitializer
    )]
    pub program_data: Account<'info, ProgramData>,
    #[account(mut, seeds = [STATE_SEED], bump, owner = crate::ID)]
    /// CHECK: legacy state layout is deserialized manually and rewritten in-place.
    pub state: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct BuyLockedBsh<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [STATE_SEED], bump = state.bumps.state)]
    pub state: Account<'info, GlobalState>,
    pub mint: Account<'info, Mint>,
    #[account(
        mut,
        seeds = [SOL_VAULT_SEED],
        bump = state.bumps.vault,
        owner = crate::ID
    )]
    /// CHECK: Vault signer validated against stored bump
    pub sol_vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [PAYMENT_ROUTER_SEED], bump)]
    pub payment_router: SystemAccount<'info>,
    #[account(mut, address = BETON_TREASURY_1)]
    pub fee_treasury_1: SystemAccount<'info>,
    #[account(mut, constraint = sale_token_account.key() == state.sale_token_account)]
    pub sale_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub payer_token_account: Account<'info, TokenAccount>,
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    /// CHECK: Address-constrained instructions sysvar read by `validate_locked_sale_prefund`.
    pub instructions: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AutoCloseSaleVault<'info> {
    #[account(seeds = [STATE_SEED], bump = state.bumps.state)]
    pub state: Account<'info, GlobalState>,
    pub mint: Account<'info, Mint>,
    #[account(
        seeds = [SOL_VAULT_SEED],
        bump = state.bumps.vault,
        owner = crate::ID
    )]
    /// CHECK: Vault signer validated against stored bump
    pub sol_vault: UncheckedAccount<'info>,
    #[account(mut, address = BETON_TREASURY_1)]
    pub fee_treasury_1: SystemAccount<'info>,
    #[account(mut, constraint = sale_token_account.key() == state.sale_token_account)]
    pub sale_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct SwapSolForBsh<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [STATE_SEED], bump = state.bumps.state)]
    pub state: Account<'info, GlobalState>,
    pub mint: Account<'info, Mint>,
    #[account(
        mut,
        seeds = [SOL_VAULT_SEED],
        bump = state.bumps.vault,
        owner = crate::ID
    )]
    /// CHECK: Vault signer validated against stored bump
    pub sol_vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [PAYMENT_ROUTER_SEED], bump)]
    pub payment_router: SystemAccount<'info>,
    #[account(mut, constraint = vault_token_account.key() == state.vault_token_account)]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub payer_token_account: Account<'info, TokenAccount>,
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    /// CHECK: Address-constrained instructions sysvar read by `validate_swap_sol_prefund`.
    pub instructions: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DistributePaymentRouter<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(mut, seeds = [PAYMENT_ROUTER_SEED], bump)]
    pub payment_router: SystemAccount<'info>,
    #[account(
        mut,
        seeds = [SOL_VAULT_SEED],
        bump,
        owner = crate::ID
    )]
    /// CHECK: BSH swap SOL vault PDA.
    pub sol_vault: UncheckedAccount<'info>,
    #[account(mut, address = BETON_TREASURY_1)]
    pub fee_treasury_1: SystemAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TopUpPaymentRouter<'info> {
    #[account(mut)]
    pub funder: Signer<'info>,

    #[account(mut, seeds = [PAYMENT_ROUTER_SEED], bump, owner = system_program::ID)]
    /// CHECK: System-owned lamports-only PDA used as the SOL payment router.
    pub payment_router: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SwapBshForSol<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [STATE_SEED], bump = state.bumps.state)]
    pub state: Account<'info, GlobalState>,
    pub mint: Account<'info, Mint>,
    #[account(
        mut,
        seeds = [SOL_VAULT_SEED],
        bump = state.bumps.vault,
        owner = crate::ID
    )]
    /// CHECK: Vault signer validated against stored bump
    pub sol_vault: UncheckedAccount<'info>,
    #[account(mut, constraint = vault_token_account.key() == state.vault_token_account)]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct GlobalState {
    /// Audit H-7 (production hardening): schema version byte. Initialised
    /// to [`GLOBAL_STATE_VERSION`] on `initialize` and re-asserted on
    /// every read so future deserialisers can trust the layout. While BSH
    /// still retains upgrade authority for audited lifecycle changes, this
    /// version byte remains the migration anchor; reserve room is included
    /// for future compatible fields without breaking layout.
    pub version: u8,
    pub mint: Pubkey,
    pub sol_vault: Pubkey,
    pub vault_token_account: Pubkey,
    pub sale_token_account: Pubkey,
    pub total_supply: u64,
    pub bumps: Bumps,
    /// Slot of the last successful swap (either direction).
    ///
    /// Retained for layout compatibility and swap telemetry. It is no longer
    /// used as a global admission gate because one-swap-per-slot allowed
    /// dust trades to grief every other user at block level.
    pub last_swap_slot: u64,
    /// Reserved compatibility bytes for future non-governance layout needs.
    /// If upgrade authority is intentionally revoked in the final swap-only
    /// state, whatever layout is live at that point becomes frozen.
    pub _reserved: [u8; 23],
}

/// Audit H-7: current `GlobalState` schema version. Bump whenever any
/// field semantics change; readers MUST reject unknown versions.
pub const GLOBAL_STATE_VERSION: u8 = 1;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, InitSpace)]
pub struct Bumps {
    pub state: u8,
    pub mint: u8,
    pub vault: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum SwapSide {
    SolForBsh,
    BshForSol,
}

#[event]
pub struct SwapEvent {
    pub side: SwapSide,
    pub actor: Pubkey,
    pub sol_change: i128,
    pub token_change: i128,
    pub vault_sol_balance: u64,
    pub vault_token_balance: u64,
}

#[event]
pub struct LockedSaleEvent {
    pub buyer: Pubkey,
    pub tokens_purchased: u64,
    pub lamports_paid: u64,
    pub shared_vsol_deposit: u64,
    pub beton_treasury_1_deposit: u64,
    pub remaining_locked_inventory: u64,
    pub sold_out: bool,
}

#[event]
pub struct PaymentRouterDistributedEvent {
    pub total: u64,
    pub sol_vault: u64,
    pub fee_treasury_1: u64,
}

#[event]
pub struct PaymentRouterFundedEvent {
    pub funder: Pubkey,
    pub amount: u64,
    pub balance_after: u64,
}

fn ensure_system_account(account: &AccountInfo) -> Result<()> {
    require_keys_eq!(
        *account.owner,
        system_program::ID,
        BshError::AccountNotSystemOwned
    );
    Ok(())
}

fn payment_router_rent_reserve() -> Result<u64> {
    Ok(Rent::get()?.minimum_balance(0))
}

fn require_payment_router_reserve(payment_router: &AccountInfo, routed_amount: u64) -> Result<()> {
    let reserve = payment_router_rent_reserve()?;
    let remaining = payment_router
        .lamports()
        .checked_sub(routed_amount)
        .ok_or(BshError::PaymentRouterBelowRentReserve)?;
    require!(
        remaining >= reserve,
        BshError::PaymentRouterBelowRentReserve
    );
    Ok(())
}

fn handle_top_up_payment_router(ctx: Context<TopUpPaymentRouter>) -> Result<()> {
    ensure_system_account(&ctx.accounts.funder.to_account_info())?;

    let router_info = ctx.accounts.payment_router.to_account_info();
    let reserve = payment_router_rent_reserve()?;
    let current = router_info.lamports();
    let amount = reserve.saturating_sub(current);

    if amount > 0 {
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                system_program::Transfer {
                    from: ctx.accounts.funder.to_account_info(),
                    to: router_info.clone(),
                },
            ),
            amount,
        )?;
    }

    emit!(PaymentRouterFundedEvent {
        funder: ctx.accounts.funder.key(),
        amount,
        balance_after: current.checked_add(amount).ok_or(BshError::MathOverflow)?,
    });
    Ok(())
}

#[error_code]
pub enum BshError {
    // Audit M-S1: a handful of variants below (`InvalidTreasuryWallet`,
    // `TreasuryDelegated`, `TreasuryCloseAuthoritySet`, `TreasuryBalanceMismatch`)
    // are currently unreferenced. They are intentionally retained as **reserved
    // IDL error codes** — removing them would shift every subsequent variant's
    // numeric discriminant and break clients that have cached error-code -> name
    // mappings. Repurpose them in place if a future treasury‑validation path
    // needs them, but never delete or reorder.
    #[msg("Initializer is not the current program upgrade authority")]
    UnauthorizedInitializer,
    #[msg("ProgramData account does not match this program")]
    InvalidProgramData,
    #[msg("Mint decimals must equal zero")]
    InvalidMintDecimals,
    #[msg("Mint supply does not match fixed total")]
    InvalidInitialSupply,
    #[msg("Treasury wallet account does not match expected hard-coded address")]
    InvalidTreasuryWallet,
    #[msg("Vault token account owner mismatch")]
    VaultTokenOwnerMismatch,
    #[msg("Vault token account must not have a delegate")]
    VaultDelegated,
    #[msg("Vault token account must not have a close authority")]
    VaultCloseAuthoritySet,
    #[msg("State mint mismatch")]
    StateMintMismatch,
    #[msg("State vault mismatch")]
    StateVaultMismatch,
    #[msg("State vault token account mismatch")]
    StateVaultAtaMismatch,
    #[msg("State sale token account mismatch")]
    StateSaleAtaMismatch,
    #[msg("State total_supply does not match mint supply")]
    StateSupplyMismatch,
    #[msg("Token account owner mismatch")]
    TokenOwnerMismatch,
    #[msg("Treasury token account must not have a delegate")]
    TreasuryDelegated,
    #[msg("Treasury token account must not have a close authority")]
    TreasuryCloseAuthoritySet,
    #[msg("Mathematical overflow detected")]
    MathOverflow,
    #[msg("Distribution would result in zero payout")]
    ZeroPayout,
    #[msg("Swap output fell below caller-provided minimum")]
    SlippageExceeded,
    #[msg("Mint mismatch on provided token account")]
    WrongMint,
    #[msg("Vault lacks sufficient BSH to fulfill swap")]
    InsufficientVaultTokens,
    #[msg("Vault lacks sufficient SOL to fulfill swap")]
    InsufficientVaultSol,
    #[msg("Swap price unavailable or undefined")]
    PriceUnavailable,
    #[msg("Vault token balance mismatch after initialization")]
    VaultBalanceMismatch,
    #[msg("Sale token balance mismatch after initialization")]
    SaleBalanceMismatch,
    #[msg("Treasury token balance mismatch after initialization")]
    TreasuryBalanceMismatch,
    #[msg("Mint authority was not fully revoked")]
    MintAuthorityStillSet,
    #[msg("Freeze authority was not fully revoked")]
    FreezeAuthorityStillSet,
    #[msg("Invalid amount provided")]
    InvalidAmount,
    #[msg("User token balance insufficient")]
    InsufficientUserTokens,
    #[msg("Account must be system owned")]
    AccountNotSystemOwned,
    #[msg("Mint account does not match the configured BSH mint")]
    InvalidBshMint,
    #[msg("Inventory wallet account does not match the configured BSH inventory wallet")]
    InvalidInventoryWallet,
    #[msg("Inventory wallet does not hold enough BSH to lock")]
    InsufficientLockedInventory,
    #[msg("Sale token account owner mismatch")]
    SaleTokenOwnerMismatch,
    #[msg("Sale token account must not have a delegate")]
    SaleDelegated,
    #[msg("Sale token account must not have a close authority")]
    SaleCloseAuthoritySet,
    #[msg("Locked sale inventory must remain isolated from the swap vault")]
    SaleInventoryMustRemainIsolated,
    #[msg("Sale amount must be between 1 and 5,000 BSH")]
    SaleAmountOutOfRange,
    #[msg("Sale vault can only be closed once the locked balance is zero")]
    SaleVaultNotEmpty,
    #[msg("Locked sale inventory is fully sold out")]
    SaleExhausted,
    #[msg("Locked sale inventory cannot satisfy the requested amount")]
    InsufficientSaleTokens,
    // ---- Jackpot / Reward (v3) ----
    #[msg("Caller is not the configured authority")]
    InvalidAuthority,
    #[msg("Jackpot threshold not reached")]
    JackpotIneligible,
    #[msg("Jackpot already claimed for this epoch")]
    JackpotAlreadyClaimedForEpoch,
    #[msg("Jackpot pool is empty")]
    JackpotEmpty,
    #[msg("Reward eligibility milestone not met")]
    RewardIneligible,
    #[msg("Reward already claimed by this wallet")]
    RewardAlreadyClaimed,
    #[msg("Reward milestone cap reached for current phase")]
    RewardCapReached,
    #[msg("Reward instruction not allowed in current phase")]
    RewardPhaseClosed,
    #[msg("Reward initial phase budgets are not yet exhausted")]
    RewardInitialNotExhausted,
    #[msg("Reward vault holds insufficient funds for this payout")]
    RewardVaultInsufficient,
    // ---- Reward (v3 — three-vault model, Phase 9) ----
    #[msg("Reward campaign is not active")]
    RewardCampaignInactive,
    #[msg("Reward campaign reservation would exceed payout * max_wallets")]
    RewardCampaignOverFunded,
    // ---- Bounty (v3.2) ----
    #[msg("Bounty token balance mismatch after initialization")]
    BountyBalanceMismatch,
    #[msg("Bounty vault is not yet fully drained or caps not reached")]
    BountyVaultNotEmpty,
    #[msg("Activity record has not been initialized for this wallet")]
    ActivityNotInitialized,
    // ---- Schema versioning (Audit H-7) ----
    #[msg("Account schema version is unsupported by this program build")]
    UnsupportedStateVersion,
    #[msg("Legacy global state account layout is unsupported by this migration path")]
    UnsupportedLegacyStateLayout,
    #[msg("Legacy global state discriminator is invalid")]
    InvalidLegacyStateDiscriminator,
    #[msg("Legacy reserved error code for the retired global swap slot limiter")]
    SwapRateLimited,
    #[msg("Locked-sale quote no longer matches the on-chain tiered price")]
    LockedSaleQuoteMismatch,
    #[msg("Locked-sale buy requires a preceding SOL transfer into the payment router")]
    MissingLockedSaleFundingTransfer,
    #[msg("Locked-sale funding transfer into the payment router is missing or malformed")]
    InvalidLockedSaleFundingTransfer,
    #[msg("SOL to BSH swap requires a preceding SOL transfer into the payment router")]
    MissingSwapFundingTransfer,
    #[msg("SOL to BSH funding transfer into the payment router is missing or malformed")]
    InvalidSwapFundingTransfer,
    #[msg("Payment router has nothing to distribute")]
    PaymentRouterEmpty,
    #[msg("Payment router must retain its rent-exempt reserve after routing")]
    PaymentRouterBelowRentReserve,
    // ---- Referral bounty (v3.5) ----
    #[msg("Referral bounty config / vault account mismatch")]
    ReferralBountyConfigMismatch,
    #[msg("No referral bounty tier is currently claimable for this wallet")]
    NoReferralBountyClaimable,
    #[msg("Referral account is not owned by the beton program or fails seed derivation")]
    ReferralAccountInvalid,
}

#[cfg(test)]
mod mollusk_tests;
#[cfg(test)]
mod program_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::{program_option::COption, program_pack::Pack};
    use anchor_lang::{AccountSerialize, InstructionData, ToAccountMetas};
    use anchor_spl::token::spl_token::{
        self,
        state::{Account as SplTokenAccount, AccountState as SplAccountState, Mint as SplMint},
    };
    use mollusk_svm::{result::Check, Mollusk, MolluskContext};
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction, InstructionError},
        native_token::LAMPORTS_PER_SOL,
        pubkey::Pubkey as Address,
    };
    use std::{collections::HashMap, path::Path};

    const DEFAULT_SIGNER_FUNDS: u64 = 10 * LAMPORTS_PER_SOL;

    fn to_address(key: Pubkey) -> Address {
        Address::new_from_array(key.to_bytes())
    }

    fn to_sdk_account_metas(metas: Vec<anchor_lang::prelude::AccountMeta>) -> Vec<AccountMeta> {
        metas
            .into_iter()
            .map(|meta| AccountMeta {
                pubkey: to_address(meta.pubkey),
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            })
            .collect()
    }

    fn serialize_anchor_account<T: AccountSerialize>(account: &T) -> Vec<u8> {
        let mut data = Vec::new();
        account
            .try_serialize(&mut data)
            .expect("failed to serialize anchor account");
        data
    }

    fn funded_system_account(lamports: u64) -> Account {
        Account {
            lamports,
            data: Vec::new(),
            owner: to_address(system_program::ID),
            executable: false,
            rent_epoch: 0,
        }
    }

    fn executable_program_account() -> Account {
        Account {
            lamports: 1,
            data: Vec::new(),
            owner: to_address(anchor_lang::solana_program::bpf_loader_upgradeable::ID),
            executable: true,
            rent_epoch: 0,
        }
    }

    fn packed_mint_account(mint: SplMint, lamports: u64) -> Account {
        let mut data = vec![0u8; SplMint::LEN];
        SplMint::pack(mint, &mut data).expect("failed to pack mint account");
        Account {
            lamports,
            data,
            owner: to_address(spl_token::ID),
            executable: false,
            rent_epoch: 0,
        }
    }

    fn packed_token_account(token_account: SplTokenAccount, lamports: u64) -> Account {
        let mut data = vec![0u8; SplTokenAccount::LEN];
        SplTokenAccount::pack(token_account, &mut data).expect("failed to pack token account");
        Account {
            lamports,
            data,
            owner: to_address(spl_token::ID),
            executable: false,
            rent_epoch: 0,
        }
    }

    struct BshTestHarness {
        context: MolluskContext<HashMap<Address, Account>>,
    }

    impl BshTestHarness {
        fn new() -> Self {
            let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            let artifact_stem = manifest_dir.join("../../target/deploy/bsh");
            let artifact_path = artifact_stem.with_extension("so");
            assert!(
                artifact_path.exists(),
                "BPF artifact missing at {}. Run `anchor build` before executing Mollusk tests.",
                artifact_path.display()
            );

            let artifact_stem_str = artifact_stem
                .to_str()
                .expect("artifact stem contains invalid UTF-8 characters");

            let mollusk = Mollusk::new(&to_address(crate::ID), artifact_stem_str);
            let context = mollusk.with_context(HashMap::<Address, Account>::new());

            Self { context }
        }

        fn process(&self, instruction: &Instruction, checks: &[Check]) {
            self.context
                .process_and_validate_instruction(instruction, checks);
        }

        fn store_account(&self, key: Pubkey, account: Account) {
            self.context
                .account_store
                .borrow_mut()
                .insert(to_address(key), account);
        }

        fn rent_exempt_lamports(&self, data_len: usize) -> u64 {
            self.context.mollusk.sysvars.rent.minimum_balance(data_len)
        }
    }

    struct SwapFixture {
        payer: Pubkey,
        state: Pubkey,
        mint: Pubkey,
        sol_vault: Pubkey,
        payment_router: Pubkey,
        vault_token_account: Pubkey,
        user_token_account: Pubkey,
    }

    fn setup_swap_fixture(
        harness: &BshTestHarness,
        initial_vault_tokens: u64,
        initial_user_tokens: u64,
        initial_vault_net_sol: u64,
    ) -> SwapFixture {
        let payer = Pubkey::new_unique();
        let (state, state_bump) = Pubkey::find_program_address(&[STATE_SEED], &crate::ID);
        let mint = BSH_MINT;
        let (sol_vault, vault_bump) = Pubkey::find_program_address(&[SOL_VAULT_SEED], &crate::ID);
        let (payment_router, _) = Pubkey::find_program_address(&[PAYMENT_ROUTER_SEED], &crate::ID);
        let vault_token_account =
            anchor_spl::associated_token::get_associated_token_address(&sol_vault, &mint);
        let sale_token_account =
            anchor_spl::associated_token::get_associated_token_address(&state, &mint);
        let user_token_account =
            anchor_spl::associated_token::get_associated_token_address(&payer, &mint);
        let total_supply = TOTAL_SUPPLY;

        let state_data = serialize_anchor_account(&GlobalState {
            version: GLOBAL_STATE_VERSION,
            mint,
            sol_vault,
            vault_token_account,
            sale_token_account,
            total_supply,
            bumps: Bumps {
                state: state_bump,
                mint: 0,
                vault: vault_bump,
            },
            last_swap_slot: 0,
            _reserved: [0u8; 23],
        });

        harness.store_account(payer, funded_system_account(DEFAULT_SIGNER_FUNDS));
        harness.store_account(spl_token::ID, executable_program_account());
        harness.store_account(
            state,
            Account {
                lamports: harness.rent_exempt_lamports(state_data.len()),
                data: state_data,
                owner: to_address(crate::ID),
                executable: false,
                rent_epoch: 0,
            },
        );

        harness.store_account(
            mint,
            packed_mint_account(
                SplMint {
                    mint_authority: COption::None,
                    supply: total_supply,
                    decimals: 0,
                    is_initialized: true,
                    freeze_authority: COption::None,
                },
                harness.rent_exempt_lamports(SplMint::LEN),
            ),
        );

        harness.store_account(
            sol_vault,
            Account {
                lamports: harness.rent_exempt_lamports(SOL_VAULT_SPACE) + initial_vault_net_sol,
                data: vec![0u8; SOL_VAULT_SPACE],
                owner: to_address(crate::ID),
                executable: false,
                rent_epoch: 0,
            },
        );

        harness.store_account(
            payment_router,
            funded_system_account(harness.rent_exempt_lamports(0)),
        );

        harness.store_account(
            vault_token_account,
            packed_token_account(
                SplTokenAccount {
                    mint,
                    owner: sol_vault,
                    amount: initial_vault_tokens,
                    delegate: COption::None,
                    state: SplAccountState::Initialized,
                    is_native: COption::None,
                    delegated_amount: 0,
                    close_authority: COption::None,
                },
                harness.rent_exempt_lamports(SplTokenAccount::LEN),
            ),
        );

        harness.store_account(
            user_token_account,
            packed_token_account(
                SplTokenAccount {
                    mint,
                    owner: payer,
                    amount: initial_user_tokens,
                    delegate: COption::None,
                    state: SplAccountState::Initialized,
                    is_native: COption::None,
                    delegated_amount: 0,
                    close_authority: COption::None,
                },
                harness.rent_exempt_lamports(SplTokenAccount::LEN),
            ),
        );

        SwapFixture {
            payer,
            state,
            mint,
            sol_vault,
            payment_router,
            vault_token_account,
            user_token_account,
        }
    }

    #[test]
    fn test_id() {
        assert_eq!(crate::id(), ID);
    }

    #[test]
    fn compute_tokens_out_returns_expected_value() {
        let tokens_out = compute_tokens_out(2_000_000, 100_000, 10_000_000)
            .expect("tokens out should compute successfully");
        assert_eq!(tokens_out, 20_000);
    }

    #[test]
    fn compute_tokens_out_errors_when_price_unavailable() {
        let err = compute_tokens_out(1_000, 100_000, 0)
            .expect_err("should fail when sol balance is zero");
        assert_eq!(err, error!(BshError::PriceUnavailable));
    }

    #[test]
    fn compute_tokens_out_errors_when_result_exceeds_u64() {
        let err = compute_tokens_out(u64::MAX, u64::MAX, 1)
            .expect_err("should fail when token payout exceeds u64");
        assert_eq!(err, error!(BshError::MathOverflow));
    }

    #[test]
    fn compute_lamports_out_returns_expected_value() {
        let lamports_out = compute_lamports_out(20_000, 100_000, 10_000_000)
            .expect("lamports out should compute successfully");
        assert_eq!(lamports_out, 2_000_000);
    }

    #[test]
    fn compute_lamports_out_errors_with_zero_total_supply() {
        let err = compute_lamports_out(1_000, 0, 10_000_000)
            .expect_err("should fail when total supply is zero");
        assert_eq!(err, error!(BshError::MathOverflow));
    }

    #[test]
    fn compute_lamports_out_errors_when_result_exceeds_u64() {
        let err = compute_lamports_out(u64::MAX, 1, u64::MAX)
            .expect_err("should fail when lamport payout exceeds u64");
        assert_eq!(err, error!(BshError::MathOverflow));
    }

    #[test]
    fn compute_locked_sale_cost_prices_across_tiers() {
        // Tier schedule: 30_000 @ 0.1 SOL, 20_000 @ 0.5 SOL, 10_000 @ 1.0 SOL.
        let tier_one =
            compute_locked_sale_cost(1, LOCKED_SUPPLY).expect("tier one pricing should succeed");
        assert_eq!(tier_one, 100_000_000);

        // sold_before = 60_000 - 30_001 = 29_999 → 1 token left in tier 0
        // (0.1 SOL) and 1 token from tier 1 (0.5 SOL) = 0.6 SOL.
        let across_boundary =
            compute_locked_sale_cost(2, 30_001).expect("cross-tier pricing should succeed");
        assert_eq!(across_boundary, 600_000_000);

        // Final-tier pricing: only 1 token left → tier 2 @ 1.0 SOL.
        let final_tier = compute_locked_sale_cost(1, 1).expect("final tier pricing should succeed");
        assert_eq!(final_tier, 1_000_000_000);
    }

    #[test]
    fn compute_locked_sale_cost_errors_when_inventory_is_short() {
        let err = compute_locked_sale_cost(2, 1)
            .expect_err("should fail when sale inventory cannot satisfy the purchase");
        assert_eq!(err, error!(BshError::InsufficientSaleTokens));
    }

    #[test]
    fn compute_locked_sale_cost_tolerates_donated_over_balance() {
        // Audit regression: a donated over-balance (remaining_inventory above
        // LOCKED_SUPPLY) must NOT underflow/abort. It is clamped to "nothing
        // sold yet" → tier-1 pricing, identical to remaining_inventory == LOCKED_SUPPLY.
        let donated =
            compute_locked_sale_cost(1, LOCKED_SUPPLY + 5_000).expect("donated over-balance must price, not abort");
        assert_eq!(donated, 100_000_000); // tier one @ 0.1 SOL
        let baseline =
            compute_locked_sale_cost(1, LOCKED_SUPPLY).expect("baseline tier one");
        assert_eq!(donated, baseline);
    }

    #[test]
    fn validate_locked_inventory_layout_accepts_canonical_accounts() {
        let state_key = Pubkey::new_unique();
        let sol_vault = Pubkey::new_unique();
        let result = validate_locked_inventory_layout(
            state_key,
            BSH_MINT,
            sol_vault,
            anchor_spl::associated_token::get_associated_token_address(&sol_vault, &BSH_MINT),
            anchor_spl::associated_token::get_associated_token_address(&state_key, &BSH_MINT),
        );

        assert!(
            result.is_ok(),
            "canonical sale and swap accounts should validate"
        );
    }

    #[test]
    fn validate_locked_inventory_layout_rejects_colliding_accounts() {
        let state_key = Pubkey::new_unique();
        let sol_vault = Pubkey::new_unique();
        let shared_account = Pubkey::new_unique();

        let err = validate_locked_inventory_layout(
            state_key,
            BSH_MINT,
            sol_vault,
            shared_account,
            shared_account,
        )
        .expect_err("shared sale and swap accounts must be rejected");

        assert_eq!(err, error!(BshError::SaleInventoryMustRemainIsolated));
    }

    #[test]
    fn mollusk_swap_sol_for_bsh_requires_prefunding_transfer() {
        let harness = BshTestHarness::new();
        let fixture = setup_swap_fixture(&harness, 90_000, 10_000, 5_000_000);
        let deposited_lamports = 1_000_000u64;

        let instruction = Instruction {
            program_id: to_address(crate::ID),
            accounts: to_sdk_account_metas(
                crate::accounts::SwapSolForBsh {
                    payer: fixture.payer,
                    state: fixture.state,
                    mint: fixture.mint,
                    sol_vault: fixture.sol_vault,
                    payment_router: fixture.payment_router,
                    vault_token_account: fixture.vault_token_account,
                    payer_token_account: fixture.user_token_account,
                    instructions: solana_instructions_sysvar::ID,
                    token_program: spl_token::ID,
                    system_program: system_program::ID,
                }
                .to_account_metas(None),
            ),
            data: crate::instruction::SwapSolForBsh {
                deposited_lamports,
                min_tokens_out: 1,
            }
            .data(),
        };

        harness.process(
            &instruction,
            &[Check::err(solana_sdk::program_error::ProgramError::Custom(
                anchor_lang::error::ERROR_CODE_OFFSET + BshError::MissingSwapFundingTransfer as u32,
            ))],
        );
    }

    #[test]
    fn mollusk_swap_bsh_for_sol_reaches_token_cpi_boundary() {
        let harness = BshTestHarness::new();
        let fixture = setup_swap_fixture(&harness, 80_000, 20_000, 5_000_000);
        let amount = 20_000u64;

        let instruction = Instruction {
            program_id: to_address(crate::ID),
            accounts: to_sdk_account_metas(
                crate::accounts::SwapBshForSol {
                    payer: fixture.payer,
                    state: fixture.state,
                    mint: fixture.mint,
                    sol_vault: fixture.sol_vault,
                    vault_token_account: fixture.vault_token_account,
                    user_token_account: fixture.user_token_account,
                    token_program: spl_token::ID,
                    system_program: system_program::ID,
                }
                .to_account_metas(None),
            ),
            data: crate::instruction::SwapBshForSol {
                amount,
                min_lamports_out: 1,
            }
            .data(),
        };

        harness.process(
            &instruction,
            &[Check::instruction_err(
                InstructionError::UnsupportedProgramId,
            )],
        );
    }
}
