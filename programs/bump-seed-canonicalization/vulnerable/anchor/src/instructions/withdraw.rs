use anchor_lang::prelude::*;
use crate::state::VaultState;

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump  // VULNERABILITY: accepts any valid bump, not just the canonical one
    )]
    pub vault: Account<'info, VaultState>,

    #[account(mut)]
    pub user: Signer<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>, bump: u8) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // VULNERABILITY: No verification that the provided bump matches the stored canonical bump
    // An attacker could provide a different valid bump to access a non-canonical PDA

    msg!("Withdrawing from vault with bump: {}", bump);
    msg!("Vault balance: {}", vault.balance);

    // Withdrawal logic would go here
    // This demonstrates that any valid bump can be used to interact with the vault

    Ok(())
}
