//! Referral bounty module (v3.5) — capped BSH milestone payouts to referrers
//! plus a one-time welcome bounty to referents.
//!
//! Funding model (separate from the activity `bounty` module's 5_000 BSH):
//!   * Referrer milestones, cumulative, first-come-first-served, gated on BOTH
//!     referred volume AND distinct active referents (anti-Sybil breadth-gate):
//!       - ≥   100 SOL & ≥ 3  active referents →    10 BSH × 500 wallets = 5_000
//!       - ≥ 1_000 SOL & ≥ 10 active referents →   100 BSH ×  50 wallets = 5_000
//!       - ≥10_000 SOL & ≥ 25 active referents → 1_000 BSH ×   5 wallets = 5_000
//!   * Welcome bounty: first 1_000 referents with ≥3 matched bets and ≥1 SOL of
//!     referred-through volume → 5 BSH each = 5_000 BSH.
//!   * Total locked = 15_000 + 5_000 = 20_000 BSH.
//!
//! Tokens are **permanently locked**: the only exit is a met condition. There
//! is no authority drain or timed sweep — residual BSH that no one qualifies
//! for stays locked forever (deliberate no-rug guarantee). The vault ATA can be
//! closed only once every cap is reached and the balance is zero.
//!
//! Eligibility data lives in beton: the referrer's `UserProfile`
//! (cumulative volume + qualified referent count) and the referent's `Activity`
//! (matched bets) + `ReferralLink` (proves referral + referred volume). All are
//! deserialized cross-program with strict owner + seed checks.

use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Mint, Token, TokenAccount},
};

use beton_shared_types::{
    Activity, ReferralLink, UserProfile, ACTIVITY_SEED, BETON_PROGRAM_ID, REFERRAL_LINK_SEED,
    REF_TIER_1_VOLUME, REF_TIER_2_VOLUME, REF_TIER_3_VOLUME, USER_PROFILE_SEED,
};

use crate::{BshError, GlobalState, INVENTORY_WALLET, STATE_SEED};

// =========================================================================
// Seeds & constants
// =========================================================================

pub const REF_BOUNTY_CONFIG_SEED: &[u8] = b"ref_bounty_cfg";
pub const REF_BOUNTY_AUTHORITY_SEED: &[u8] = b"ref_bounty_auth";
pub const REF_BOUNTY_CLAIM_SEED: &[u8] = b"ref_bounty_claim"; // [referrer]
pub const REFERENT_WELCOME_SEED: &[u8] = b"referent_welcome"; // [referent]

// Referrer milestone payouts / caps / breadth-gate (distinct active referents).
pub const REF_TIER_1_PAYOUT: u64 = 10;
pub const REF_TIER_2_PAYOUT: u64 = 100;
pub const REF_TIER_3_PAYOUT: u64 = 1_000;
pub const REF_TIER_1_MAX: u16 = 500;
pub const REF_TIER_2_MAX: u16 = 50;
pub const REF_TIER_3_MAX: u16 = 5;
pub const REF_TIER_1_MIN_REFERENTS: u32 = 3;
pub const REF_TIER_2_MIN_REFERENTS: u32 = 10;
pub const REF_TIER_3_MIN_REFERENTS: u32 = 25;

// Welcome bounty.
pub const WELCOME_PAYOUT: u64 = 5;
pub const WELCOME_MAX: u16 = 1_000;
pub const WELCOME_MIN_VOLUME: u64 = 1_000_000_000; // 1 SOL referred-through
pub const WELCOME_MIN_MATCHED_BETS: u32 = 3;

/// Total BSH locked at `initialize_referral_bounty`.
pub const REF_BOUNTY_LOCKED_SUPPLY: u64 = 20_000;

const _: () = assert!(
    REF_TIER_1_PAYOUT * REF_TIER_1_MAX as u64
        + REF_TIER_2_PAYOUT * REF_TIER_2_MAX as u64
        + REF_TIER_3_PAYOUT * REF_TIER_3_MAX as u64
        + WELCOME_PAYOUT * WELCOME_MAX as u64
        == REF_BOUNTY_LOCKED_SUPPLY,
    "referral bounty caps must sum to REF_BOUNTY_LOCKED_SUPPLY"
);

// =========================================================================
// Accounts
// =========================================================================

#[account]
#[derive(InitSpace, Debug)]
pub struct ReferralBountyConfig {
    pub mint: Pubkey,
    pub vault_token_account: Pubkey,
    pub tier1_claimed: u16,
    pub tier2_claimed: u16,
    pub tier3_claimed: u16,
    pub welcome_claimed: u16,
    pub total_lock: u64,
    pub config_bump: u8,
    pub authority_bump: u8,
    pub _reserved: [u8; 32],
}

/// Per-referrer milestone claim record (one PDA per referrer; per-tier bools).
#[account]
#[derive(InitSpace, Debug)]
pub struct ReferralBountyClaim {
    pub claimed_t1: bool,
    pub claimed_t2: bool,
    pub claimed_t3: bool,
    pub bump: u8,
    // Audit M1: explicit init flag instead of the unsound `bump == 0` sentinel.
    // Carved from `_reserved` so the account layout/size is unchanged.
    pub initialized: bool,
    pub _reserved: [u8; 7],
}

/// Per-referent welcome claim record.
#[account]
#[derive(InitSpace, Debug)]
pub struct ReferentWelcomeClaim {
    pub claimed: bool,
    pub bump: u8,
    // Audit M1: explicit init flag instead of the unsound `bump == 0` sentinel.
    // Carved from `_reserved` so the account layout/size is unchanged.
    pub initialized: bool,
    pub _reserved: [u8; 7],
}

// =========================================================================
// Events
// =========================================================================

#[event]
pub struct ReferralBountyInitializedEvent {
    pub mint: Pubkey,
    pub vault_token_account: Pubkey,
    pub locked_supply: u64,
}

#[event]
pub struct ReferralBountyClaimedEvent {
    pub referrer: Pubkey,
    pub tier: u8, // 1, 2 or 3
    pub bsh_amount: u64,
    pub claimed_count: u16,
    pub max_wallets: u16,
}

#[event]
pub struct ReferentWelcomeClaimedEvent {
    pub referent: Pubkey,
    pub bsh_amount: u64,
    pub claimed_count: u16,
}

#[event]
pub struct ReferralBountyVaultAutoClosedEvent {
    pub vault_token_account: Pubkey,
}

// =========================================================================
// initialize_referral_bounty
// =========================================================================

pub fn handle_initialize_referral_bounty(ctx: Context<InitializeReferralBounty>) -> Result<()> {
    #[cfg(not(feature = "test-mode"))]
    {
        require_keys_eq!(
            ctx.accounts.mint.key(),
            crate::BSH_MINT,
            BshError::InvalidBshMint
        );
        require_keys_eq!(
            ctx.accounts.inventory_owner.key(),
            INVENTORY_WALLET,
            BshError::InvalidInventoryWallet
        );
    }

    require_eq!(ctx.accounts.mint.decimals, 0, BshError::InvalidMintDecimals);
    require!(
        ctx.accounts.inventory_token_account.amount >= REF_BOUNTY_LOCKED_SUPPLY,
        BshError::InsufficientLockedInventory
    );

    {
        let cfg = &mut ctx.accounts.ref_bounty_config;
        cfg.mint = ctx.accounts.mint.key();
        cfg.vault_token_account = ctx.accounts.ref_bounty_token_account.key();
        cfg.tier1_claimed = 0;
        cfg.tier2_claimed = 0;
        cfg.tier3_claimed = 0;
        cfg.welcome_claimed = 0;
        cfg.total_lock = REF_BOUNTY_LOCKED_SUPPLY;
        cfg.config_bump = ctx.bumps.ref_bounty_config;
        cfg.authority_bump = ctx.bumps.ref_bounty_authority;
        cfg._reserved = [0u8; 32];
    }

    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            token::Transfer {
                from: ctx.accounts.inventory_token_account.to_account_info(),
                to: ctx.accounts.ref_bounty_token_account.to_account_info(),
                authority: ctx.accounts.inventory_owner.to_account_info(),
            },
        ),
        REF_BOUNTY_LOCKED_SUPPLY,
    )?;

    ctx.accounts.ref_bounty_token_account.reload()?;
    require_eq!(
        ctx.accounts.ref_bounty_token_account.amount,
        REF_BOUNTY_LOCKED_SUPPLY,
        BshError::BountyBalanceMismatch
    );

    emit!(ReferralBountyInitializedEvent {
        mint: ctx.accounts.mint.key(),
        vault_token_account: ctx.accounts.ref_bounty_token_account.key(),
        locked_supply: REF_BOUNTY_LOCKED_SUPPLY,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeReferralBounty<'info> {
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

    pub inventory_owner: Signer<'info>,
    pub mint: Account<'info, Mint>,

    #[account(
        init,
        payer = authority,
        space = 8 + ReferralBountyConfig::INIT_SPACE,
        seeds = [REF_BOUNTY_CONFIG_SEED],
        bump
    )]
    pub ref_bounty_config: Account<'info, ReferralBountyConfig>,

    #[account(seeds = [REF_BOUNTY_AUTHORITY_SEED], bump)]
    /// CHECK: PDA — token authority for the referral bounty ATA.
    pub ref_bounty_authority: UncheckedAccount<'info>,

    #[account(
        init,
        payer = authority,
        associated_token::mint = mint,
        associated_token::authority = ref_bounty_authority
    )]
    pub ref_bounty_token_account: Account<'info, TokenAccount>,

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

// =========================================================================
// claim_referral_bounty
// =========================================================================

struct TierEval {
    tier: u8,
    payout: u64,
    claimed_count: u16,
    max: u16,
}

pub fn handle_claim_referral_bounty(ctx: Context<ClaimReferralBounty>) -> Result<()> {
    let vol = ctx.accounts.referrer_profile.cumulative_referred_volume_lamports;
    let refs = ctx.accounts.referrer_profile.qualified_referrals;

    let claim = &mut ctx.accounts.claim;
    if !claim.initialized {
        claim.initialized = true;
        claim.bump = ctx.bumps.claim;
        claim._reserved = [0u8; 7];
    }

    let cfg = &mut ctx.accounts.ref_bounty_config;

    // Evaluate each tier independently: threshold met (volume AND breadth),
    // not already claimed by this referrer, and a slot still available.
    let mut total_payout: u64 = 0;
    let mut paid: Vec<TierEval> = Vec::new();

    if !claim.claimed_t1
        && vol >= REF_TIER_1_VOLUME
        && refs >= REF_TIER_1_MIN_REFERENTS
        && cfg.tier1_claimed < REF_TIER_1_MAX
    {
        claim.claimed_t1 = true;
        cfg.tier1_claimed += 1;
        total_payout += REF_TIER_1_PAYOUT;
        paid.push(TierEval {
            tier: 1,
            payout: REF_TIER_1_PAYOUT,
            claimed_count: cfg.tier1_claimed,
            max: REF_TIER_1_MAX,
        });
    }
    if !claim.claimed_t2
        && vol >= REF_TIER_2_VOLUME
        && refs >= REF_TIER_2_MIN_REFERENTS
        && cfg.tier2_claimed < REF_TIER_2_MAX
    {
        claim.claimed_t2 = true;
        cfg.tier2_claimed += 1;
        total_payout += REF_TIER_2_PAYOUT;
        paid.push(TierEval {
            tier: 2,
            payout: REF_TIER_2_PAYOUT,
            claimed_count: cfg.tier2_claimed,
            max: REF_TIER_2_MAX,
        });
    }
    if !claim.claimed_t3
        && vol >= REF_TIER_3_VOLUME
        && refs >= REF_TIER_3_MIN_REFERENTS
        && cfg.tier3_claimed < REF_TIER_3_MAX
    {
        claim.claimed_t3 = true;
        cfg.tier3_claimed += 1;
        total_payout += REF_TIER_3_PAYOUT;
        paid.push(TierEval {
            tier: 3,
            payout: REF_TIER_3_PAYOUT,
            claimed_count: cfg.tier3_claimed,
            max: REF_TIER_3_MAX,
        });
    }

    require!(total_payout > 0, BshError::NoReferralBountyClaimable);
    require!(
        ctx.accounts.ref_bounty_token_account.amount >= total_payout,
        BshError::RewardVaultInsufficient
    );

    // Single transfer of the summed payout, signed by the bounty authority PDA.
    let auth_bump = cfg.authority_bump;
    let signer_seeds: &[&[u8]] = &[REF_BOUNTY_AUTHORITY_SEED, &[auth_bump]];
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            token::Transfer {
                from: ctx.accounts.ref_bounty_token_account.to_account_info(),
                to: ctx.accounts.referrer_token_account.to_account_info(),
                authority: ctx.accounts.ref_bounty_authority.to_account_info(),
            },
            &[signer_seeds],
        ),
        total_payout,
    )?;

    cfg.total_lock = cfg
        .total_lock
        .checked_sub(total_payout)
        .ok_or(BshError::MathOverflow)?;

    for p in paid {
        emit!(ReferralBountyClaimedEvent {
            referrer: ctx.accounts.referrer.key(),
            tier: p.tier,
            bsh_amount: p.payout,
            claimed_count: p.claimed_count,
            max_wallets: p.max,
        });
    }
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimReferralBounty<'info> {
    #[account(mut)]
    pub referrer: Signer<'info>,

    /// Referrer's beton profile — owner + seed enforced cross-program.
    #[account(
        seeds = [USER_PROFILE_SEED, referrer.key().as_ref()],
        bump = referrer_profile.bump,
        seeds::program = BETON_PROGRAM_ID,
        constraint = referrer_profile.wallet == referrer.key() @ BshError::ReferralAccountInvalid,
    )]
    pub referrer_profile: Box<Account<'info, UserProfile>>,

    #[account(
        mut,
        seeds = [REF_BOUNTY_CONFIG_SEED],
        bump = ref_bounty_config.config_bump,
    )]
    pub ref_bounty_config: Box<Account<'info, ReferralBountyConfig>>,

    #[account(
        seeds = [REF_BOUNTY_AUTHORITY_SEED],
        bump = ref_bounty_config.authority_bump,
    )]
    /// CHECK: PDA — token authority for the referral bounty ATA.
    pub ref_bounty_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        constraint = ref_bounty_token_account.key() == ref_bounty_config.vault_token_account @ BshError::ReferralBountyConfigMismatch,
        constraint = ref_bounty_token_account.mint == ref_bounty_config.mint @ BshError::WrongMint,
    )]
    pub ref_bounty_token_account: Box<Account<'info, TokenAccount>>,

    #[account(constraint = mint.key() == ref_bounty_config.mint @ BshError::WrongMint)]
    pub mint: Box<Account<'info, Mint>>,

    #[account(
        init_if_needed,
        payer = referrer,
        associated_token::mint = mint,
        associated_token::authority = referrer,
    )]
    pub referrer_token_account: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = referrer,
        space = 8 + ReferralBountyClaim::INIT_SPACE,
        seeds = [REF_BOUNTY_CLAIM_SEED, referrer.key().as_ref()],
        bump,
    )]
    pub claim: Box<Account<'info, ReferralBountyClaim>>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

// =========================================================================
// claim_referent_welcome
// =========================================================================

pub fn handle_claim_referent_welcome(ctx: Context<ClaimReferentWelcome>) -> Result<()> {
    require!(
        ctx.accounts.activity.bets_matched >= WELCOME_MIN_MATCHED_BETS,
        BshError::RewardIneligible
    );
    require!(
        ctx.accounts.referral_link.cumulative_settled_volume_lamports >= WELCOME_MIN_VOLUME,
        BshError::RewardIneligible
    );

    let welcome = &mut ctx.accounts.welcome_claim;
    if !welcome.initialized {
        welcome.initialized = true;
        welcome.bump = ctx.bumps.welcome_claim;
        welcome._reserved = [0u8; 7];
    }
    require!(!welcome.claimed, BshError::RewardAlreadyClaimed);

    let cfg = &mut ctx.accounts.ref_bounty_config;
    require!(cfg.welcome_claimed < WELCOME_MAX, BshError::RewardCapReached);
    require!(
        ctx.accounts.ref_bounty_token_account.amount >= WELCOME_PAYOUT,
        BshError::RewardVaultInsufficient
    );

    let auth_bump = cfg.authority_bump;
    let signer_seeds: &[&[u8]] = &[REF_BOUNTY_AUTHORITY_SEED, &[auth_bump]];
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            token::Transfer {
                from: ctx.accounts.ref_bounty_token_account.to_account_info(),
                to: ctx.accounts.referent_token_account.to_account_info(),
                authority: ctx.accounts.ref_bounty_authority.to_account_info(),
            },
            &[signer_seeds],
        ),
        WELCOME_PAYOUT,
    )?;

    welcome.claimed = true;
    cfg.welcome_claimed = cfg.welcome_claimed.saturating_add(1);
    cfg.total_lock = cfg
        .total_lock
        .checked_sub(WELCOME_PAYOUT)
        .ok_or(BshError::MathOverflow)?;

    emit!(ReferentWelcomeClaimedEvent {
        referent: ctx.accounts.referent.key(),
        bsh_amount: WELCOME_PAYOUT,
        claimed_count: cfg.welcome_claimed,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimReferentWelcome<'info> {
    #[account(mut)]
    pub referent: Signer<'info>,

    /// Referent's beton activity — proves ≥3 matched bets.
    #[account(
        seeds = [ACTIVITY_SEED, referent.key().as_ref()],
        bump = activity.bump,
        seeds::program = BETON_PROGRAM_ID,
        constraint = activity.wallet == referent.key() @ BshError::ActivityNotInitialized,
    )]
    pub activity: Box<Account<'info, Activity>>,

    /// Referent's beton link — proves they were referred + carries volume.
    #[account(
        seeds = [REFERRAL_LINK_SEED, referent.key().as_ref()],
        bump = referral_link.bump,
        seeds::program = BETON_PROGRAM_ID,
        constraint = referral_link.referent == referent.key() @ BshError::ReferralAccountInvalid,
    )]
    pub referral_link: Box<Account<'info, ReferralLink>>,

    #[account(
        mut,
        seeds = [REF_BOUNTY_CONFIG_SEED],
        bump = ref_bounty_config.config_bump,
    )]
    pub ref_bounty_config: Box<Account<'info, ReferralBountyConfig>>,

    #[account(
        seeds = [REF_BOUNTY_AUTHORITY_SEED],
        bump = ref_bounty_config.authority_bump,
    )]
    /// CHECK: PDA — token authority for the referral bounty ATA.
    pub ref_bounty_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        constraint = ref_bounty_token_account.key() == ref_bounty_config.vault_token_account @ BshError::ReferralBountyConfigMismatch,
        constraint = ref_bounty_token_account.mint == ref_bounty_config.mint @ BshError::WrongMint,
    )]
    pub ref_bounty_token_account: Box<Account<'info, TokenAccount>>,

    #[account(constraint = mint.key() == ref_bounty_config.mint @ BshError::WrongMint)]
    pub mint: Box<Account<'info, Mint>>,

    #[account(
        init_if_needed,
        payer = referent,
        associated_token::mint = mint,
        associated_token::authority = referent,
    )]
    pub referent_token_account: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = referent,
        space = 8 + ReferentWelcomeClaim::INIT_SPACE,
        seeds = [REFERENT_WELCOME_SEED, referent.key().as_ref()],
        bump,
    )]
    pub welcome_claim: Box<Account<'info, ReferentWelcomeClaim>>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

// =========================================================================
// auto_close_referral_bounty_vault
// =========================================================================

pub fn handle_auto_close_referral_bounty_vault(
    ctx: Context<AutoCloseReferralBountyVault>,
) -> Result<()> {
    let cfg = &ctx.accounts.ref_bounty_config;
    require!(
        cfg.tier1_claimed >= REF_TIER_1_MAX
            && cfg.tier2_claimed >= REF_TIER_2_MAX
            && cfg.tier3_claimed >= REF_TIER_3_MAX
            && cfg.welcome_claimed >= WELCOME_MAX,
        BshError::BountyVaultNotEmpty
    );
    require_eq!(
        ctx.accounts.ref_bounty_token_account.amount,
        0,
        BshError::BountyVaultNotEmpty
    );

    let auth_bump = cfg.authority_bump;
    let signer_seeds: &[&[u8]] = &[REF_BOUNTY_AUTHORITY_SEED, &[auth_bump]];
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.key(),
        token::CloseAccount {
            account: ctx.accounts.ref_bounty_token_account.to_account_info(),
            destination: ctx.accounts.inventory_wallet.to_account_info(),
            authority: ctx.accounts.ref_bounty_authority.to_account_info(),
        },
        &[signer_seeds],
    ))?;

    emit!(ReferralBountyVaultAutoClosedEvent {
        vault_token_account: ctx.accounts.ref_bounty_token_account.key(),
    });
    Ok(())
}

#[derive(Accounts)]
pub struct AutoCloseReferralBountyVault<'info> {
    #[account(seeds = [STATE_SEED], bump = state.bumps.state)]
    pub state: Account<'info, GlobalState>,

    #[account(
        seeds = [REF_BOUNTY_CONFIG_SEED],
        bump = ref_bounty_config.config_bump,
    )]
    pub ref_bounty_config: Account<'info, ReferralBountyConfig>,

    #[account(
        seeds = [REF_BOUNTY_AUTHORITY_SEED],
        bump = ref_bounty_config.authority_bump,
    )]
    /// CHECK: PDA — token authority for the referral bounty ATA.
    pub ref_bounty_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        constraint = ref_bounty_token_account.key() == ref_bounty_config.vault_token_account @ BshError::ReferralBountyConfigMismatch,
    )]
    pub ref_bounty_token_account: Account<'info, TokenAccount>,

    #[account(mut, address = INVENTORY_WALLET @ BshError::InvalidInventoryWallet)]
    /// CHECK: rent recipient — pinned address.
    pub inventory_wallet: SystemAccount<'info>,

    pub token_program: Program<'info, Token>,
}
