use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use crate::state::Vault;

/// SECURE: Transfer tokens using Anchor's CPI helper (RECOMMENDED APPROACH)
///
/// This is the best practice for making CPIs in Anchor programs:
/// 1. Use Anchor's generated CPI helpers (anchor_spl::token::transfer)
/// 2. CpiContext automatically validates program IDs
/// 3. Type-safe account passing through structs
/// 4. Cleaner, more maintainable code
///
/// BENEFITS OVER MANUAL CPI:
/// - No need to manually construct instruction
/// - No risk of passing wrong program ID
/// - Type safety ensures correct accounts are passed
/// - Less boilerplate code
/// - Automatically handles program validation
///
/// This is the recommended pattern for all Anchor CPI calls
pub fn transfer_tokens_with_cpi_helper(
    ctx: Context<TransferTokensWithHelper>,
    amount: u64,
) -> Result<()> {
    msg!("Transferring {} tokens using CPI helper", amount);

    // SECURE: Using Anchor's CPI helper function
    // The transfer function and CpiContext handle all validation automatically
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.source.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        ),
        amount,
    )?;

    msg!("Transfer completed successfully with CPI helper");
    Ok(())
}

#[derive(Accounts)]
pub struct TransferTokensWithHelper<'info> {
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

    /// Token program - validated by Program<'info, Token> type
    /// The CPI helper automatically uses this validated program
    pub token_program: Program<'info, Token>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Only the vault authority can authorize transfers")]
    UnauthorizedAuthority,

    #[msg("Source must be the vault's token account")]
    InvalidSourceAccount,
}
