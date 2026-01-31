use anchor_lang::prelude::*;

declare_id!("5tnoXzXyE4q84XSKmfuR6ZU1hWEXUHhbwyvhkNjyAxGH");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod secure_integer_overflow {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize(ctx)
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        instructions::deposit(ctx, amount)
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        instructions::withdraw(ctx, amount)
    }
}

#[error_code]
pub enum ErrorCode {
    #[msg("Integer overflow detected")]
    Overflow,
    #[msg("Integer underflow detected")]
    Underflow,
    #[msg("Invalid amount")]
    InvalidAmount,
}
