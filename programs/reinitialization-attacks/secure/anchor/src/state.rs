use anchor_lang::prelude::*;

/// Vault account that holds SOL and has an authority
///
/// This account stores:
/// - authority: The public key that controls this vault
/// - balance: The amount of SOL deposited (tracked separately from lamports)
///
/// SECURITY: When properly initialized using the `init` constraint, Anchor
/// automatically adds a discriminator at the start of the account data.
/// This discriminator prevents reinitialization because:
/// 1. The `init` constraint checks that discriminator is zero
/// 2. After initialization, discriminator is set to a non-zero value
/// 3. Subsequent initialization attempts fail the discriminator check
#[account]
pub struct Vault {
    /// The authority that controls this vault
    pub authority: Pubkey,
    /// Amount of SOL deposited (for tracking purposes)
    pub balance: u64,
}

impl Vault {
    /// Space required for this account
    /// 8 bytes discriminator + 32 bytes pubkey + 8 bytes u64
    pub const LEN: usize = 8 + 32 + 8;
}
