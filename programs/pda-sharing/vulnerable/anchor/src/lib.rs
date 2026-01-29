use anchor_lang::prelude::*;

declare_id!("4AYMT1uUswxPRdYNxg586mo2gdYrZeEcyx6FunqpZZzR");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod vulnerable_pda_sharing {
    use super::*;

    /// Initialize a token pool for a specific mint
    /// VULNERABLE: Uses only mint as seed, creating shared PDA across users
    pub fn initialize_pool(ctx: Context<InitializePool>) -> Result<()> {
        instructions::initialize_pool(ctx)
    }

    /// Deposit tokens into the user's pool
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        instructions::deposit(ctx, amount)
    }

    /// VULNERABLE: Withdraw tokens from pool without user-specific validation
    /// Anyone can withdraw from the shared pool to any destination
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        instructions::withdraw(ctx, amount)
    }
}
