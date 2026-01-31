use anchor_lang::prelude::*;

declare_id!("EhLoKK5wYMoU95ibhc6ErhmAb9ELkLTWvqyeJBMAmpx2");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod vulnerable_bump_seed_canonicalization {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize(ctx)
    }

    pub fn withdraw(ctx: Context<Withdraw>, bump: u8) -> Result<()> {
        instructions::withdraw(ctx, bump)
    }
}
