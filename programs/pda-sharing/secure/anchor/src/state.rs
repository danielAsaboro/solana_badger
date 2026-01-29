use anchor_lang::prelude::*;

/// Token pool state with user-specific ownership
///
/// SECURITY FIX: This pool uses BOTH user pubkey AND mint in PDA derivation:
/// seeds = [b"pool", user.key().as_ref(), mint.key().as_ref()]
///
/// This ensures:
/// - Each user gets their own unique pool PDA
/// - Alice's pool: [b"pool", ALICE_PUBKEY, USDC_MINT]
/// - Bob's pool: [b"pool", BOB_PUBKEY, USDC_MINT]
/// - No cross-user contamination possible
#[account]
pub struct TokenPool {
    /// The user who owns this pool
    /// CRITICAL: Used in PDA derivation to ensure uniqueness
    pub owner: Pubkey,

    /// The depositor (same as owner, used for has_one constraints)
    pub depositor: Pubkey,

    /// The token mint this pool manages
    pub mint: Pubkey,

    /// The token account (vault) holding deposited tokens
    /// Each user has their own vault
    pub vault: Pubkey,

    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl TokenPool {
    pub const LEN: usize = 8 + // discriminator
        32 + // owner
        32 + // depositor
        32 + // mint
        32 + // vault
        1; // bump
}
