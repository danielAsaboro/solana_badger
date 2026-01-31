use anchor_lang::prelude::*;
use crate::state::VaultState;

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

    // VULNERABLE: Using wrapping addition that silently overflows
    // When balance + amount > u64::MAX, it wraps around to a small number
    vault.balance = vault.balance.wrapping_add(amount);

    Ok(())
}
