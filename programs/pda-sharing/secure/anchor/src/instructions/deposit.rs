use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use crate::state::TokenPool;

/// Deposit tokens into the user's personal pool
///
/// SECURITY: User deposits into their own isolated vault
/// - Pool PDA is user-specific
/// - Tokens cannot mix with other users' deposits
/// - Each user maintains their own balance
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    msg!("Depositing {} tokens into personal pool", amount);
    msg!("Owner: {}", ctx.accounts.pool.owner);
    msg!("SECURE: Depositing into user-specific isolated vault");

    // Transfer tokens from user to their personal vault
    let cpi_accounts = Transfer {
        from: ctx.accounts.user_token_account.to_account_info(),
        to: ctx.accounts.vault.to_account_info(),
        authority: ctx.accounts.depositor.to_account_info(),
    };

    let cpi_program = ctx.accounts.token_program.to_account_info();
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

    token::transfer(cpi_ctx, amount)?;

    msg!("Deposit successful - tokens in user-specific vault");
    Ok(())
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    /// The depositor who must be the pool owner
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// SECURITY: Pool derived from owner + mint
    /// This ensures we're depositing into the correct user's pool
    #[account(
        seeds = [b"pool", pool.owner.as_ref(), pool.mint.as_ref()],
        bump = pool.bump,
        has_one = depositor @ ErrorCode::UnauthorizedDepositor
    )]
    pub pool: Account<'info, TokenPool>,

    /// User's token account (source of deposit)
    #[account(
        mut,
        constraint = user_token_account.owner == depositor.key() @ ErrorCode::InvalidTokenAccountOwner,
        constraint = user_token_account.mint == pool.mint @ ErrorCode::InvalidTokenMint
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    /// User's personal vault (not shared)
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
    #[msg("Only the pool owner can deposit")]
    UnauthorizedDepositor,

    #[msg("Token account must be owned by the depositor")]
    InvalidTokenAccountOwner,

    #[msg("Token mint must match pool mint")]
    InvalidTokenMint,

    #[msg("Vault must match pool's vault address")]
    InvalidVault,

    #[msg("Vault mint must match pool mint")]
    InvalidVaultMint,
}
