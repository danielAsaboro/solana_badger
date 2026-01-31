use anchor_lang::prelude::*;

pub mod state;
pub mod instructions;

use instructions::*;

declare_id!("3k6fBqaWzqPmvHWjLrgpHqJx6BbKZ65zksZjAx24oGLz");

#[program]
pub mod vulnerable_closing_accounts {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, deposit_amount: u64) -> Result<()> {
        instructions::initialize(ctx, deposit_amount)
    }

    pub fn force_close(ctx: Context<ForceClose>) -> Result<()> {
        instructions::force_close(ctx)
    }
}
