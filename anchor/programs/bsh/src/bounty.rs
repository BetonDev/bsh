//! Bounty module — preload-style milestone payouts in BSH.
//!
//! Replaces the legacy "reward preload" lane that lived under the old
//! reward module. The bounty PDA + ATA are created and atomically funded
//! in `initialize`; once the milestone counters are exhausted (or the
//! protocol authority calls `auto_close_bounty_vault`) the vault ATA
//! closes itself and rent flows back to the inventory wallet.
//!
//! Funding model:
//!   * Bounty ATA holds **5_000 BSH** locked at `initialize` time, sourced
//!     from the canonical inventory wallet `INVENTORY_WALLET`.
//!   * Three independent milestones, each with a per-wallet payout and a
//!     hard cap on the number of wallets that may claim:
//!       - bets_created  ≥ 5  → 10 BSH × 100 wallets = 1_000 BSH
//!       - bets_accepted ≥ 5  → 10 BSH × 100 wallets = 1_000 BSH
//!       - wins_total    ≥ 5  → 30 BSH × 100 wallets = 3_000 BSH
//!   * Total locked = 1_000 + 1_000 + 3_000 = 5_000 BSH.
//!
//! Eligibility data lives in beton's `Activity` PDA. We re-derive that PDA
//! cross-program (`seeds::program = BETON_PROGRAM_ID`) so BSH never has
//! write authority over beton accounts; we only read counters.

use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Mint, Token, TokenAccount},
};

use beton_shared_types::{Activity, ACTIVITY_SEED, BETON_PROGRAM_ID};

use crate::{BshError, CompatibleGlobalState, INVENTORY_WALLET, STATE_SEED};

// =========================================================================
// Seeds & constants
// =========================================================================

pub const BOUNTY_CONFIG_SEED: &[u8] = b"bounty_cfg";
pub const BOUNTY_AUTHORITY_SEED: &[u8] = b"bounty_auth";
pub const BOUNTY_CLAIM_SEED: &[u8] = b"bounty_claim";

/// Total BSH locked into the bounty vault ATA at `initialize` time.
pub const BOUNTY_LOCKED_SUPPLY: u64 = 5_000;

/// Eligibility thresholds (read against the wallet's `Activity` PDA).
pub const BOUNTY_CREATE_THRESHOLD: u32 = 5;
pub const BOUNTY_ACCEPT_THRESHOLD: u32 = 5;
pub const BOUNTY_WIN_THRESHOLD: u32 = 5;

/// Per-wallet payouts (BSH, decimals = 0).
pub const BOUNTY_CREATE_PAYOUT: u64 = 10;
pub const BOUNTY_ACCEPT_PAYOUT: u64 = 10;
pub const BOUNTY_WIN_PAYOUT: u64 = 30;

/// Per-milestone wallet caps. 100 × (10 + 10 + 30) = 5 000 BSH ≡ BOUNTY_LOCKED_SUPPLY.
pub const BOUNTY_CREATE_MAX_WALLETS: u16 = 100;
pub const BOUNTY_ACCEPT_MAX_WALLETS: u16 = 100;
pub const BOUNTY_WIN_MAX_WALLETS: u16 = 100;

// =========================================================================
// Accounts
// =========================================================================

#[account]
#[derive(InitSpace, Debug)]
pub struct BountyConfig {
    pub mint: Pubkey,
    pub vault_token_account: Pubkey,
    pub create_claimed: u16,
    pub accept_claimed: u16,
    pub win_claimed: u16,
    pub total_lock: u64,
    pub config_bump: u8,
    pub authority_bump: u8,
    pub _reserved: [u8; 32],
}

#[account]
#[derive(InitSpace, Debug)]
pub struct BountyClaim {
    pub claimed_create: bool,
    pub claimed_accept: bool,
    pub claimed_win: bool,
    pub bump: u8,
    pub _reserved: [u8; 8],
}

// =========================================================================
// Events
// =========================================================================

#[event]
pub struct BountyInitializedEvent {
    pub mint: Pubkey,
    pub vault_token_account: Pubkey,
    pub locked_supply: u64,
}

#[event]
pub struct BountyClaimedEvent {
    pub wallet: Pubkey,
    pub milestone: u8, // 0=create, 1=accept, 2=win
    pub payout: u64,
    pub claimed_count: u16,
    pub max_wallets: u16,
}

#[event]
pub struct BountyVaultAutoClosedEvent {
    pub vault_token_account: Pubkey,
}

// =========================================================================
// Internal helpers (called from crate::initialize)
// =========================================================================

/// Initialise the `BountyConfig` PDA. Called inline from `crate::initialize`
/// before transferring tokens into the bounty ATA. Requires the bounty ATA
/// to already exist (created by the same `initialize` `Accounts` context).
pub(crate) fn initialize_bounty_config(
    config: &mut Account<BountyConfig>,
    mint: Pubkey,
    vault_token_account: Pubkey,
    bumps: BountyInitBumps,
) -> Result<()> {
    config.mint = mint;
    config.vault_token_account = vault_token_account;
    config.create_claimed = 0;
    config.accept_claimed = 0;
    config.win_claimed = 0;
    config.total_lock = BOUNTY_LOCKED_SUPPLY;
    config.config_bump = bumps.config;
    config.authority_bump = bumps.authority;
    config._reserved = [0u8; 32];
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct BountyInitBumps {
    pub config: u8,
    pub authority: u8,
}

// =========================================================================
// claim_bounty_create3 / accept3 / win5
// =========================================================================

#[derive(Clone, Copy)]
enum BountyMilestone {
    Create,
    Accept,
    Win,
}

impl BountyMilestone {
    fn payout(&self) -> u64 {
        match self {
            BountyMilestone::Create => BOUNTY_CREATE_PAYOUT,
            BountyMilestone::Accept => BOUNTY_ACCEPT_PAYOUT,
            BountyMilestone::Win => BOUNTY_WIN_PAYOUT,
        }
    }
    fn max_wallets(&self) -> u16 {
        match self {
            BountyMilestone::Create => BOUNTY_CREATE_MAX_WALLETS,
            BountyMilestone::Accept => BOUNTY_ACCEPT_MAX_WALLETS,
            BountyMilestone::Win => BOUNTY_WIN_MAX_WALLETS,
        }
    }
    fn discriminant(&self) -> u8 {
        match self {
            BountyMilestone::Create => 0,
            BountyMilestone::Accept => 1,
            BountyMilestone::Win => 2,
        }
    }
}

fn process_bounty_claim(
    ctx: &mut ClaimBounty<'_>,
    milestone: BountyMilestone,
    bumps: ClaimBountyLocalBumps,
) -> Result<()> {
    let activity = &ctx.activity;
    let satisfies = match milestone {
        BountyMilestone::Create => activity.bets_created >= BOUNTY_CREATE_THRESHOLD,
        BountyMilestone::Accept => activity.bets_accepted >= BOUNTY_ACCEPT_THRESHOLD,
        BountyMilestone::Win => activity.wins_total >= BOUNTY_WIN_THRESHOLD,
    };
    require!(satisfies, BshError::RewardIneligible);

    let claim = &mut ctx.claim;
    if claim.bump == 0 {
        claim.bump = bumps.claim;
        claim._reserved = [0u8; 8];
    }
    let already = match milestone {
        BountyMilestone::Create => claim.claimed_create,
        BountyMilestone::Accept => claim.claimed_accept,
        BountyMilestone::Win => claim.claimed_win,
    };
    require!(!already, BshError::RewardAlreadyClaimed);

    let cfg = &mut ctx.bounty_config;
    let claimed_so_far = match milestone {
        BountyMilestone::Create => cfg.create_claimed,
        BountyMilestone::Accept => cfg.accept_claimed,
        BountyMilestone::Win => cfg.win_claimed,
    };
    require!(
        claimed_so_far < milestone.max_wallets(),
        BshError::RewardCapReached
    );

    let payout = milestone.payout();
    require!(
        ctx.bounty_token_account.amount >= payout,
        BshError::RewardVaultInsufficient
    );

    // Transfer BSH from bounty ATA → wallet ATA, signed by the bounty authority PDA.
    let auth_bump = cfg.authority_bump;
    let signer_seeds: &[&[u8]] = &[BOUNTY_AUTHORITY_SEED, &[auth_bump]];
    token::transfer(
        CpiContext::new_with_signer(
            ctx.token_program.key(),
            token::Transfer {
                from: ctx.bounty_token_account.to_account_info(),
                to: ctx.wallet_token_account.to_account_info(),
                authority: ctx.bounty_authority.to_account_info(),
            },
            &[signer_seeds],
        ),
        payout,
    )?;

    match milestone {
        BountyMilestone::Create => {
            cfg.create_claimed = cfg.create_claimed.saturating_add(1);
            claim.claimed_create = true;
        }
        BountyMilestone::Accept => {
            cfg.accept_claimed = cfg.accept_claimed.saturating_add(1);
            claim.claimed_accept = true;
        }
        BountyMilestone::Win => {
            cfg.win_claimed = cfg.win_claimed.saturating_add(1);
            claim.claimed_win = true;
        }
    }

    cfg.total_lock = cfg
        .total_lock
        .checked_sub(payout)
        .ok_or(BshError::MathOverflow)?;

    let new_count = match milestone {
        BountyMilestone::Create => cfg.create_claimed,
        BountyMilestone::Accept => cfg.accept_claimed,
        BountyMilestone::Win => cfg.win_claimed,
    };

    emit!(BountyClaimedEvent {
        wallet: ctx.wallet.key(),
        milestone: milestone.discriminant(),
        payout,
        claimed_count: new_count,
        max_wallets: milestone.max_wallets(),
    });
    Ok(())
}

pub fn handle_claim_bounty_create3(ctx: Context<ClaimBounty>) -> Result<()> {
    let bumps = ClaimBountyLocalBumps { claim: ctx.bumps.claim };
    process_bounty_claim(ctx.accounts, BountyMilestone::Create, bumps)
}

pub fn handle_claim_bounty_accept3(ctx: Context<ClaimBounty>) -> Result<()> {
    let bumps = ClaimBountyLocalBumps { claim: ctx.bumps.claim };
    process_bounty_claim(ctx.accounts, BountyMilestone::Accept, bumps)
}

pub fn handle_claim_bounty_win5(ctx: Context<ClaimBounty>) -> Result<()> {
    let bumps = ClaimBountyLocalBumps { claim: ctx.bumps.claim };
    process_bounty_claim(ctx.accounts, BountyMilestone::Win, bumps)
}

#[derive(Clone, Copy)]
struct ClaimBountyLocalBumps {
    claim: u8,
}

#[derive(Accounts)]
pub struct ClaimBounty<'info> {
    #[account(mut)]
    pub wallet: Signer<'info>,

    #[account(
        seeds = [ACTIVITY_SEED, wallet.key().as_ref()],
        bump = activity.bump,
        seeds::program = BETON_PROGRAM_ID,
        constraint = activity.wallet == wallet.key() @ BshError::ActivityNotInitialized,
    )]
    pub activity: Account<'info, Activity>,

    #[account(
        mut,
        seeds = [BOUNTY_CONFIG_SEED],
        bump = bounty_config.config_bump,
    )]
    pub bounty_config: Account<'info, BountyConfig>,

    #[account(
        seeds = [BOUNTY_AUTHORITY_SEED],
        bump = bounty_config.authority_bump,
    )]
    /// CHECK: PDA — token authority for the bounty ATA.
    pub bounty_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        constraint = bounty_token_account.key() == bounty_config.vault_token_account @ BshError::StateVaultAtaMismatch,
        constraint = bounty_token_account.mint == bounty_config.mint @ BshError::WrongMint,
    )]
    pub bounty_token_account: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    #[account(
        init_if_needed,
        payer = wallet,
        associated_token::mint = mint,
        associated_token::authority = wallet,
    )]
    pub wallet_token_account: Account<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = wallet,
        space = 8 + BountyClaim::INIT_SPACE,
        seeds = [BOUNTY_CLAIM_SEED, wallet.key().as_ref()],
        bump,
    )]
    pub claim: Account<'info, BountyClaim>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

// =========================================================================
// auto_close_bounty_vault
// =========================================================================
//
// Permissionless. Closes the bounty ATA once all three milestone caps have
// been hit (5 000 BSH fully drained). Rent flows to INVENTORY_WALLET.

pub fn handle_auto_close_bounty_vault(ctx: Context<AutoCloseBountyVault>) -> Result<()> {
    let cfg = &ctx.accounts.bounty_config;
    require!(
        cfg.create_claimed >= BOUNTY_CREATE_MAX_WALLETS
            && cfg.accept_claimed >= BOUNTY_ACCEPT_MAX_WALLETS
            && cfg.win_claimed >= BOUNTY_WIN_MAX_WALLETS,
        BshError::BountyVaultNotEmpty
    );
    require_eq!(
        ctx.accounts.bounty_token_account.amount,
        0,
        BshError::BountyVaultNotEmpty
    );

    let auth_bump = cfg.authority_bump;
    let signer_seeds: &[&[u8]] = &[BOUNTY_AUTHORITY_SEED, &[auth_bump]];
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.key(),
        token::CloseAccount {
            account: ctx.accounts.bounty_token_account.to_account_info(),
            destination: ctx.accounts.inventory_wallet.to_account_info(),
            authority: ctx.accounts.bounty_authority.to_account_info(),
        },
        &[signer_seeds],
    ))?;

    emit!(BountyVaultAutoClosedEvent {
        vault_token_account: ctx.accounts.bounty_token_account.key(),
    });
    Ok(())
}

#[derive(Accounts)]
pub struct AutoCloseBountyVault<'info> {
    #[account(seeds = [STATE_SEED], bump = state.bumps.state)]
    pub state: Account<'info, CompatibleGlobalState>,

    #[account(
        seeds = [BOUNTY_CONFIG_SEED],
        bump = bounty_config.config_bump,
    )]
    pub bounty_config: Account<'info, BountyConfig>,

    #[account(
        seeds = [BOUNTY_AUTHORITY_SEED],
        bump = bounty_config.authority_bump,
    )]
    /// CHECK: PDA — token authority for the bounty ATA.
    pub bounty_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        constraint = bounty_token_account.key() == bounty_config.vault_token_account @ BshError::StateVaultAtaMismatch,
    )]
    pub bounty_token_account: Account<'info, TokenAccount>,

    #[account(mut, address = INVENTORY_WALLET @ BshError::InvalidInventoryWallet)]
    /// CHECK: rent recipient — pinned address.
    pub inventory_wallet: SystemAccount<'info>,

    pub token_program: Program<'info, Token>,
}
