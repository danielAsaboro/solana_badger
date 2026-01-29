use anchor_lang::prelude::*;

declare_id!("6dKVUQcDpeq4Sh6a7QkKwW1dBR2BiJPSUFYdYQmPDHJe");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod secure_pda_sharing {
    use super::*;

    /// Initialize a user-specific token pool
    /// SECURE: Uses user pubkey + mint in seeds for unique per-user PDAs
    pub fn initialize_pool(ctx: Context<InitializePool>) -> Result<()> {
        instructions::initialize_pool(ctx)
    }

    /// Deposit tokens into the user's personal pool
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        instructions::deposit(ctx, amount)
    }

    /// SECURE: Withdraw tokens with user-specific validation
    /// Only the pool owner can withdraw their own tokens
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        instructions::withdraw(ctx, amount)
    }
}
