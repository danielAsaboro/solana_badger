use anchor_lang::prelude::*;
use crate::state::VaultState;

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

    // VULNERABLE: Using wrapping subtraction that silently underflows
    // Example: balance=100, amount=200 -> balance wraps to u64::MAX - 99
    vault.balance = vault.balance.wrapping_sub(amount);

    Ok(())
}
