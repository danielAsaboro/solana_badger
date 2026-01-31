use anchor_lang::prelude::*;

declare_id!("UuU4HvUCKQj4d6a2bxWHtsAhoZEw22i9iSunCtYLsHf");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod secure_unsafe_rust {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, value: u64, label: [u8; 32]) -> Result<()> {
        instructions::initialize(ctx, value, label)
    }

    pub fn read_data(ctx: Context<ReadData>) -> Result<()> {
        instructions::read_data(ctx)
    }
}
