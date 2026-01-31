use anchor_lang::prelude::*;

#[account]
pub struct DataStore {
    pub authority: Pubkey,
    pub value: u64,
    pub label: [u8; 32], // Fixed-size label
    pub is_initialized: bool,
}

impl DataStore {
    pub const LEN: usize = 8 + 32 + 8 + 32 + 1; // discriminator + pubkey + u64 + label + bool
}
