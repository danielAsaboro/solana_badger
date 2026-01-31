use anchor_lang::prelude::*;
use crate::state::VaultState;
use crate::ErrorCode;

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump,
        has_one = owner
    )]
    pub vault: Account<'info, VaultState>,

    pub owner: Signer<'info>,
}

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // SECURE: Using checked_add to prevent overflow
    // Returns None on overflow, which we convert to an error
    vault.balance = vault.balance
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;

    Ok(())
}
