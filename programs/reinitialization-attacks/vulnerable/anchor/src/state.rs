use anchor_lang::prelude::*;

/// Vault account that holds SOL and has an authority
///
/// This account stores:
/// - authority: The public key that controls this vault
/// - balance: The amount of SOL deposited (tracked separately from lamports)
///
/// VULNERABILITY: Without proper initialization checks, an attacker can
/// call the initialization function again on an existing vault, overwriting
/// the authority field and stealing control of the funds.
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
