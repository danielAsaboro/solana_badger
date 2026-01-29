use anchor_lang::prelude::*;

declare_id!("6vXq3U6ezSy1yBzFc1nqTdPgXSxkE7vpdEUHUNiYurSN");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod secure_owner_checks {
    use super::*;

    /// Initialize a new program account with data
    pub fn initialize(ctx: Context<Initialize>, data: u64) -> Result<()> {
        instructions::initialize(ctx, data)
    }

    /// SECURE: Update account data with proper owner validation
    /// Uses Account<'info, T> type which automatically verifies ownership
    pub fn update_data(ctx: Context<UpdateData>, new_data: u64) -> Result<()> {
        instructions::update_data(ctx, new_data)
    }
}
