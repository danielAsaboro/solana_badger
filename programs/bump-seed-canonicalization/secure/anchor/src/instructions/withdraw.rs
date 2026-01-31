use anchor_lang::prelude::*;
use crate::state::VaultState;

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump = vault.bump  // SECURE: Only accepts the stored canonical bump
    )]
    pub vault: Account<'info, VaultState>,

    #[account(mut)]
    pub user: Signer<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // SECURE: The bump constraint ensures only the canonical PDA can be used
    // The stored bump from initialization is the only valid bump accepted

    msg!("Withdrawing from vault with canonical bump: {}", vault.bump);
    msg!("Vault balance: {}", vault.balance);

    // Withdrawal logic would go here
    // Only the canonical PDA with the stored bump can be accessed

    Ok(())
}
