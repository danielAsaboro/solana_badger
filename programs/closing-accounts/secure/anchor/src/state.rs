use anchor_lang::prelude::*;

#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub balance: u64,
    pub is_active: bool,
}

impl VaultState {
    pub const LEN: usize = 8 + 32 + 8 + 1; // discriminator + pubkey + u64 + bool
}
