use anchor_lang::prelude::*;

pub mod state;
pub mod instructions;

use instructions::*;

declare_id!("FtwjVwEqhZXjbMgii9D2EYkTjXyi3xYiejqmzhYDgZM3");

#[program]
pub mod secure_closing_accounts {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, deposit_amount: u64) -> Result<()> {
        instructions::initialize(ctx, deposit_amount)
    }

    pub fn force_close(ctx: Context<ForceClose>) -> Result<()> {
        instructions::force_close(ctx)
    }
}
