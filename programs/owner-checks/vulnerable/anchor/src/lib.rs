use anchor_lang::prelude::*;

declare_id!("5rezfTZ6Hk5RK8gxPLvBC3nsWgcbC7qHB2nr5TioZ9aT");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod vulnerable_owner_checks {
    use super::*;

    /// Initialize a new program account with data
    pub fn initialize(ctx: Context<Initialize>, data: u64) -> Result<()> {
        instructions::initialize(ctx, data)
    }

    /// VULNERABLE: Update account data without verifying account ownership
    /// This allows attackers to pass fake accounts with malicious data!
    pub fn update_data(ctx: Context<UpdateData>, new_data: u64) -> Result<()> {
        instructions::update_data(ctx, new_data)
    }
}
