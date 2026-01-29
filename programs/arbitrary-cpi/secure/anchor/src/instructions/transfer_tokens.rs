use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use crate::state::Vault;

/// SECURE: Transfer tokens with proper program validation
///
/// This instruction fixes the Arbitrary CPI vulnerability by:
/// 1. Using Program<'info, Token> instead of UncheckedAccount
/// 2. Anchor automatically validates the program ID matches spl_token::ID
/// 3. The CPI can only call the legitimate Token program
///
/// SECURITY IMPROVEMENTS:
/// - Program<'info, Token> ensures token_program.key() == spl_token::ID
/// - Attacker cannot substitute a malicious program
/// - Even if attacker passes fake program, validation fails before CPI
/// - The transfer will always use the real SPL Token program logic
///
/// COMPARISON WITH VULNERABLE VERSION:
/// Vulnerable:  pub token_program: UncheckedAccount<'info>
/// Secure:      pub token_program: Program<'info, Token>
///
/// This single type change provides automatic protection against arbitrary CPI attacks
pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
    msg!("Transferring {} tokens from vault", amount);
    msg!("Using validated Token program: {}", ctx.accounts.token_program.key());

    // SECURE: Use anchor_spl's CPI wrapper which validates program ID automatically
    let cpi_accounts = Transfer {
        from: ctx.accounts.source.to_account_info(),
        to: ctx.accounts.destination.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    let cpi_program = ctx.accounts.token_program.to_account_info();
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

    token::transfer(cpi_ctx, amount)?;

    msg!("Transfer completed successfully");
    Ok(())
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    /// Authority that must sign for the transfer
    pub authority: Signer<'info>,

    /// Vault state account
    #[account(
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
        constraint = vault.authority == authority.key() @ ErrorCode::UnauthorizedAuthority
    )]
    pub vault: Account<'info, Vault>,

    /// Source token account (should be vault's token account)
    #[account(
        mut,
        constraint = source.key() == vault.token_account @ ErrorCode::InvalidSourceAccount
    )]
    pub source: Account<'info, TokenAccount>,

    /// Destination token account
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,

    /// FIX: Using Program<'info, Token> instead of UncheckedAccount
    /// Anchor automatically validates that token_program.key() == spl_token::ID
    /// This prevents attackers from passing malicious programs
    ///
    /// The Program type:
    /// - Checks the program ID matches the expected program (Token in this case)
    /// - Fails transaction if a different program is provided
    /// - Ensures CPIs always call the correct program
    pub token_program: Program<'info, Token>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Only the vault authority can authorize transfers")]
    UnauthorizedAuthority,

    #[msg("Source must be the vault's token account")]
    InvalidSourceAccount,
}
