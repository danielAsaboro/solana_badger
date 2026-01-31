use anchor_lang::prelude::*;
use crate::state::VaultState;
use crate::ErrorCode;

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump,
        has_one = owner
    )]
    pub vault: Account<'info, VaultState>,

    pub owner: Signer<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // Validate amount is greater than 0
    require!(amount > 0, ErrorCode::InvalidAmount);

    // SECURE: Using checked_sub to prevent underflow
    // Returns None on underflow (when amount > balance)
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::Underflow)?;

    Ok(())
}
