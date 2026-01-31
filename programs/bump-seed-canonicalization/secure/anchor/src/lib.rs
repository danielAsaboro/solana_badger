use anchor_lang::prelude::*;

declare_id!("5RmCKP8aNEDVdDPJwJXUn4icVzq4jti72kSfiBiJj9CJ");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod secure_bump_seed_canonicalization {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize(ctx)
    }

    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        instructions::withdraw(ctx)
    }
}
