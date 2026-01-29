use anchor_lang::prelude::*;

/// Token pool state tracking vault and mint
///
/// VULNERABILITY: This pool uses only the mint address in its PDA derivation,
/// meaning ALL users depositing the same token type share the SAME pool PDA.
/// This creates a dangerous shared authority that any user can exploit.
#[account]
pub struct TokenPool {
    /// The token mint this pool manages
    pub mint: Pubkey,

    /// The token account (vault) holding deposited tokens
    /// ISSUE: Single vault per mint means funds from different users are mixed
    pub vault: Pubkey,

    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl TokenPool {
    pub const LEN: usize = 8 + // discriminator
        32 + // mint
        32 + // vault
        1; // bump
}
