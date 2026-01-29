use anchor_lang::prelude::*;

/// Vault state tracking authority and token account
#[account]
pub struct Vault {
    /// Authority that can approve transfers from the vault
    pub authority: Pubkey,

    /// Token account holding the vault's tokens
    pub token_account: Pubkey,

    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl Vault {
    pub const LEN: usize = 8 + // discriminator
        32 + // authority
        32 + // token_account
        1; // bump
}
