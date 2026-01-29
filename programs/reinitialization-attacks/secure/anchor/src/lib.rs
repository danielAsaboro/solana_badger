use anchor_lang::prelude::*;

declare_id!("FRauohhzqgjegAosW6SUNHhPfZFSCHLDfNjVUUBG5ebk");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod secure_reinitialization_attacks {
    use super::*;

    /// SECURE: Initialize a vault account with proper initialization checks
    ///
    /// This instruction is protected against reinitialization attacks by using
    /// Anchor's `init` constraint, which:
    /// 1. Automatically checks the discriminator is zero (uninitialized)
    /// 2. Creates the account with the correct size
    /// 3. Sets the discriminator to prevent reinitialization
    /// 4. Pays for rent from the specified payer
    ///
    /// Attempting to call this on an already-initialized account will fail
    /// with an error, preventing authority theft.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize(ctx)
    }

    /// Deposit SOL into a vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        instructions::deposit(ctx, amount)
    }

    /// Withdraw SOL from a vault (only authority can call)
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        instructions::withdraw(ctx, amount)
    }
}
