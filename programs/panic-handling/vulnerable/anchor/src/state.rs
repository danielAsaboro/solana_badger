use anchor_lang::prelude::*;

#[account]
pub struct ProcessorState {
    pub authority: Pubkey,
    pub data: Vec<u64>,
    pub total: u64,
}

impl ProcessorState {
    pub const LEN: usize = 8 + 32 + 4 + (10 * 8) + 8; // discriminator + pubkey + vec_prefix + max 10 u64s + total
}
