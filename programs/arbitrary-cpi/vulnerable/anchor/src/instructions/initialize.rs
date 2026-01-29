use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, TokenAccount};
use crate::state::Vault;

/// Initialize a vault with authority
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    vault.authority = ctx.accounts.authority.key();
    vault.token_account = ctx.accounts.vault_token_account.key();
    vault.bump = ctx.bumps.vault;

    msg!("Vault initialized with authority: {}", vault.authority);
    msg!("Vault token account: {}", vault.token_account);

    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = Vault::LEN,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,

    /// Token account owned by the authority (so authority can sign transfers)
    #[account(
        constraint = vault_token_account.owner == authority.key() @ ErrorCode::InvalidTokenAccount,
        constraint = vault_token_account.mint == mint.key() @ ErrorCode::InvalidTokenAccount
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid token account configuration")]
    InvalidTokenAccount,
}
