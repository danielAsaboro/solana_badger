use anchor_lang::prelude::*;

#[account]
pub struct VaultState {
    pub user: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

impl VaultState {
    pub const LEN: usize = 8 + 32 + 8 + 1; // discriminator + pubkey + u64 + u8
}
