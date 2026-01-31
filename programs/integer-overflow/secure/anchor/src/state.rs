use anchor_lang::prelude::*;

#[account]
pub struct VaultState {
    pub owner: Pubkey,
    pub balance: u64,
}

impl VaultState {
    pub const LEN: usize = 8 + 32 + 8; // discriminator + pubkey + u64
}
