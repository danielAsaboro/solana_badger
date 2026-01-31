use anchor_lang::prelude::*;
use crate::state::VaultState;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = user,
        space = VaultState::LEN,
        seeds = [b"vault", user.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, VaultState>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    vault.user = ctx.accounts.user.key();
    vault.balance = 0;
    vault.bump = ctx.bumps.vault;

    msg!("Vault initialized for user: {}", vault.user);
    msg!("Canonical bump stored: {}", vault.bump);

    Ok(())
}
