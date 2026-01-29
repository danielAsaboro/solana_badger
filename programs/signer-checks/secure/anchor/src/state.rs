use anchor_lang::prelude::*;

/// Account that stores owner information
#[account]
pub struct ProgramAccount {
    /// The current owner of this account
    pub owner: Pubkey,
    /// Arbitrary data field for demonstration
    pub data: u64,
}

impl ProgramAccount {
    /// Space required for this account
    /// 8 bytes discriminator + 32 bytes pubkey + 8 bytes u64
    pub const LEN: usize = 8 + 32 + 8;
}
