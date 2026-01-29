use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use crate::state::TokenPool;

/// Deposit tokens into the pool
///
/// This instruction appears safe but contributes to the vulnerability:
/// - User deposits tokens into the shared vault
/// - Their tokens mix with other users' deposits
/// - No per-user accounting exists
/// - The shared PDA can be used to withdraw ANY user's tokens
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    msg!("Depositing {} tokens into shared pool", amount);
    msg!("Depositor: {}", ctx.accounts.depositor.key());
    msg!("WARNING: Depositing into a shared pool - funds can be withdrawn by others!");

    // Transfer tokens from user to vault
    let cpi_accounts = Transfer {
        from: ctx.accounts.user_token_account.to_account_info(),
        to: ctx.accounts.vault.to_account_info(),
        authority: ctx.accounts.depositor.to_account_info(),
    };

    let cpi_program = ctx.accounts.token_program.to_account_info();
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

    token::transfer(cpi_ctx, amount)?;

    msg!("Deposit successful - tokens now in shared vault");
    Ok(())
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// VULNERABILITY: Pool derived from mint only
    /// Multiple users share this same PDA
    #[account(
        seeds = [b"pool", pool.mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, TokenPool>,

    /// User's token account (source of deposit)
    #[account(
        mut,
        constraint = user_token_account.owner == depositor.key() @ ErrorCode::InvalidTokenAccountOwner,
        constraint = user_token_account.mint == pool.mint @ ErrorCode::InvalidTokenMint
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    /// Vault where tokens are deposited (shared across users)
    #[account(
        mut,
        constraint = vault.key() == pool.vault @ ErrorCode::InvalidVault,
        constraint = vault.mint == pool.mint @ ErrorCode::InvalidVaultMint
    )]
    pub vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Token account must be owned by the depositor")]
    InvalidTokenAccountOwner,

    #[msg("Token mint must match pool mint")]
    InvalidTokenMint,

    #[msg("Vault must match pool's vault address")]
    InvalidVault,

    #[msg("Vault mint must match pool mint")]
    InvalidVaultMint,
}
