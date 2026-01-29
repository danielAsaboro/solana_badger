use anchor_lang::prelude::*;

/// Account that stores program data
#[account]
pub struct ProgramAccount {
    /// Arbitrary data field that will be validated against
    pub data: u64,
    /// Additional field for demonstration
    pub authority: Pubkey,
}

impl ProgramAccount {
    /// Space required for this account
    /// 8 bytes discriminator + 8 bytes u64 + 32 bytes pubkey
    pub const LEN: usize = 8 + 8 + 32;
}
