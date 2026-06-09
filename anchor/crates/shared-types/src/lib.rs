//! Shared on-chain types & PDA seeds for the beton + bsh programs.
//!
//! `bsh` is intended to be deployed with its upgrade authority revoked. Any
//! data layout that bsh reads from beton (such as `Activity`) is therefore
//! **frozen forever**. Beton must never reorder, resize or repurpose the
//! fields below; if extra per-wallet state is ever required, beton must
//! introduce a new sibling PDA rather than mutate this struct.
//!
//! The trailing `_reserved` bytes give beton a safety margin for fields that
//! bsh does not need to read. The prefix consumed by bsh must remain
//! bit-for-bit aligned with beton's `Activity` account.
#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

// ---------- Program IDs ---------------------------------------------------

#[cfg(feature = "mainnet")]
pub const BETON_PROGRAM_ID: Pubkey = pubkey!("HSVohDX9Y2AHwsixSU6wMR29nwyYZgYKuKqrwaeQfLaz");
#[cfg(not(feature = "mainnet"))]
pub const BETON_PROGRAM_ID: Pubkey = pubkey!("GjLSqm1bT4D9RZPNLWhjZkNgH9BhqYnARZDjfn8WFDnq");

#[cfg(feature = "mainnet")]
pub const BSH_PROGRAM_ID: Pubkey = pubkey!("91ahrFntCbnRAcJhsSQGd4j2QNdiUZTbESA6cJYKeovn");
#[cfg(not(feature = "mainnet"))]
pub const BSH_PROGRAM_ID: Pubkey = pubkey!("7bSkdiZXEUtDT37RwefCJqCZRW9pviUPAAKFHqStkVzw");

/// Anchor's `#[account]` macro emits an `Owner` impl that reads `crate::ID`.
/// We pin it here to **beton**, because the only `#[account]`-derived structs
/// in this crate (`Activity`, `RegistryCounter`) are owned by beton on chain.
/// `bsh` deserialises `Activity` cross-program with strict owner + seed checks.
pub const ID: Pubkey = BETON_PROGRAM_ID;

// ---------- PDA seeds (beton) --------------------------------------------

pub const ACTIVITY_SEED: &[u8] = b"activity";
pub const REGISTRY_SEED: &[u8] = b"registry";
pub const BONUS_POOL_SEED: &[u8] = b"bonus_pool";
pub const FEE_ROUTER_SEED: &[u8] = b"fee_router";
pub const RENT_ROUTER_SEED: &[u8] = b"rent_router";
pub const BET_ESCROW_SEED: &[u8] = b"escrow"; // reserved; bet account itself holds escrow lamports

// ---------- Referral PDA seeds (beton) — referenced cross-program by bsh ----
//
// bsh reads beton's `UserProfile` (referrer milestone volume + qualified
// referent count) and `ReferralLink` (referent welcome eligibility) when
// paying referral bounties. These seeds + the mirror structs below MUST stay
// bit-for-bit aligned with beton; beton re-exports these seeds from here.
pub const USER_PROFILE_SEED: &[u8] = b"user_profile";
pub const REFERRAL_LINK_SEED: &[u8] = b"referral_link";
pub const REFERENT_REWARDS_SEED: &[u8] = b"referent_rewards";

// ---------- Referral tier / milestone volume thresholds ------------------
//
// Single source of truth for BOTH the beton SOL slice ladder and the bsh
// milestone bounty. One ladder drives both rewards.
pub const REF_TIER_1_VOLUME: u64 = 100_000_000_000; //   100 SOL
pub const REF_TIER_2_VOLUME: u64 = 1_000_000_000_000; // 1 000 SOL
pub const REF_TIER_3_VOLUME: u64 = 10_000_000_000_000; //10 000 SOL

// ---------- PDA seeds (bsh) — referenced cross-program by beton ----------
//
// Beton credits the BSH swap vault through its protocol-fee drain, and sends
// reward/bonus payout platform fees into BSH's payment router for BSH-side
// routing into the vault and treasury 1.
pub const BSH_STATE_SEED: &[u8] = b"state";
pub const BSH_SWAP_SOL_VAULT: &[u8] = b"sol_vault";
pub const BSH_PAYMENT_ROUTER: &[u8] = b"payment_router";

// ---------- Constants shared by both programs ----------------------------

/// Maximum bets per rate-limit window. Frozen because it sets the on-chain
/// length of `Activity::rate_limit_timestamps`.
pub const MAX_BETS_PER_WINDOW: usize = 4;

// ---------- Activity (canonical layout) ----------------------------------

/// Per-wallet activity record owned by the **beton** program.
///
/// Layout MUST stay aligned with beton's `Activity` account — bsh
/// deserializes this account from a foreign program.
#[account]
#[derive(InitSpace, Debug)]
pub struct Activity {
    /// Owning wallet (also the seed component).
    pub wallet: Pubkey,
    /// Monotonic ordinal stamped at `init_activity` time.
    pub registration_id: u32,
    /// Lifetime counts (saturating; `u32::MAX` is unreachable in practice).
    ///
    /// Audit L-2 (production note): the saturating semantics mean that at
    /// `u32::MAX` (~4.29 billion events for a single wallet) the counters
    /// silently freeze. This is mathematically unreachable for any human or
    /// reasonable bot operator (4.29 B bets at 0.1 SOL each = 429 M SOL
    /// turnover), and freezing is preferable to overflow-panic on this
    /// non-critical metric. Sprint baseline rebases land at the same
    /// frozen value and become no-ops, which is the correct degraded mode.
    pub bets_created: u32,
    pub bets_accepted: u32,
    pub bets_total: u32,
    /// Lifetime count of accepted (matched) bets. This is the bet-count stat
    /// used by BSH bounty incentives.
    pub bets_matched: u32,
    pub wins_total: u32,
    /// Current consecutive-win streak. Reset on any loss, no-op on tie,
    /// reset to 0 by beton's `claim_streak_reward` after payout.
    pub win_streak: u32,
    /// Rate-limit circular buffer.
    pub rate_limit_timestamps: [i64; MAX_BETS_PER_WINDOW],
    pub rate_limit_count: u8,
    pub rate_limit_next: u8,
    pub bump: u8,
    /// Set to true by `init_activity` after the wallet passes the front-end
    /// registration acknowledgments.
    pub registered: bool,
    /// Reserved space for future fields.
    pub _reserved: [u8; 27],
}

/// Per-wallet `RegistryCounter` (singleton) owned by beton.
#[account]
#[derive(InitSpace, Debug)]
pub struct RegistryCounter {
    pub next_id: u32,
    pub bump: u8,
    pub _reserved: [u8; 16],
}

/// Per-wallet referral profile owned by **beton**. Layout MUST stay aligned
/// with beton's `registry::UserProfile`; bsh reads
/// `cumulative_referred_volume_lamports` + `qualified_referrals` for milestone
/// bounty eligibility. beton enforces alignment with a compile-time size
/// assertion.
#[account]
#[derive(InitSpace, Debug)]
pub struct UserProfile {
    pub wallet: Pubkey,
    pub user_id: u32,
    pub referrer: Pubkey,
    pub referrer_user_id: u32,
    pub referral_code_checksum: u16,
    pub direct_referrals: u32,
    /// Distinct referents who have passed the 3-bet activation gate. Drives the
    /// bsh milestone breadth-gate so raw volume alone cannot be farmed.
    pub qualified_referrals: u32,
    pub cumulative_referred_volume_lamports: u64,
    pub pending_referral_rewards_lamports: u64,
    pub claimed_referral_rewards_lamports: u64,
    pub has_referrer: bool,
    /// Referrer-controlled payout split for new links (0 = 80/20, 1 = 50/50).
    pub referral_mode: u8,
    pub bump: u8,
    pub _reserved: [u8; 63],
}

/// Per-referent referral link owned by **beton**. Layout MUST stay aligned
/// with beton's `registry::ReferralLink`; bsh reads
/// `cumulative_settled_volume_lamports` for the welcome bounty volume floor.
#[account]
#[derive(InitSpace, Debug)]
pub struct ReferralLink {
    pub referrer: Pubkey,
    pub referent: Pubkey,
    pub referrer_user_id: u32,
    pub referent_user_id: u32,
    pub cumulative_settled_volume_lamports: u64,
    pub mode: u8,
    pub bump: u8,
    pub _reserved: [u8; 15],
}
