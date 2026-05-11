//! Shared on-chain types & PDA seeds for the beton + bsh programs.
//!
//! `bsh` is intended to be deployed with its upgrade authority revoked. Any
//! data layout that bsh reads from beton (such as `Activity`) is therefore
//! **frozen forever**. Beton must never reorder, resize or repurpose the
//! fields below; if extra per-wallet state is ever required, beton must
//! introduce a new sibling PDA rather than mutate this struct.
//!
//! The trailing `_reserved` bytes give beton a safety margin for fields that
//! bsh does not need to read (the prefix that bsh consumes —
//! `wallet..win_streak` — must remain bit-for-bit stable).
#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

// ---------- Program IDs ---------------------------------------------------

pub const BETON_PROGRAM_ID: Pubkey = pubkey!("BpwBgBZ8WFDk7BswjJNoepmisZS1KfuoKbybCLaF5Hj6");

pub const BSH_PROGRAM_ID: Pubkey = pubkey!("91ahrFntCbnRAcJhsSQGd4j2QNdiUZTbESA6cJYKeovn");

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
pub const BET_ESCROW_SEED: &[u8] = b"escrow"; // reserved; bet account itself holds escrow lamports

// ---------- PDA seeds (bsh) — referenced cross-program by beton ----------
//
// `BSH_SWAP_SOL_VAULT` is the only bsh-side PDA that beton's
// `distribute_protocol_fee` still credits cross-program (0.5% feed). All
// other bsh seeds (sale, bounty) are bsh-internal and live in
// `programs/bsh/src/constants.rs`.
pub const BSH_STATE_SEED: &[u8] = b"state";
pub const BSH_SWAP_SOL_VAULT: &[u8] = b"sol_vault";

// ---------- Constants shared by both programs ----------------------------

/// Maximum bets per rate-limit window. Frozen because it sets the on-chain
/// length of `Activity::rate_limit_timestamps`.
pub const MAX_BETS_PER_WINDOW: usize = 4;

// ---------- Activity (canonical layout) ----------------------------------

/// Per-wallet activity record owned by the **beton** program.
///
/// Layout MUST stay frozen — bsh deserializes this account from a foreign
/// program. New beton-only state should live in a separate PDA.
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
    /// Reserved space for future *beton-only* fields. **Never** touched by bsh.
    pub _reserved: [u8; 31],
}

/// Per-wallet `RegistryCounter` (singleton) owned by beton.
#[account]
#[derive(InitSpace, Debug)]
pub struct RegistryCounter {
    pub next_id: u32,
    pub bump: u8,
    pub _reserved: [u8; 16],
}
