use anchor_lang::prelude::*;
use anchor_lang::solana_program::{self, instruction::{AccountMeta, Instruction}};
use anchor_spl::token::TokenAccount;
use crate::state::Vault;

/// VULNERABLE: Transfer tokens using arbitrary program without validation
///
/// This instruction demonstrates the Arbitrary CPI vulnerability by:
/// 1. Accepting any program account via UncheckedAccount
/// 2. Performing CPI to that program without validating its program ID
/// 3. Trusting the caller to provide the legitimate Token program
///
/// ATTACK SCENARIO:
/// 1. Attacker creates a malicious "fake-token" program with same interface as SPL Token
/// 2. Fake program's transfer instruction does the OPPOSITE: transfers from destination to source
/// 3. Attacker calls this instruction but passes their fake program instead of real Token program
/// 4. The vault authority signs, thinking tokens will be sent to destination
/// 5. Fake program reverses the transfer, draining the destination account instead!
/// 6. Attacker can also make the fake program transfer to their own wallet
///
/// WHY IT WORKS:
/// - The source and destination accounts are validated as TokenAccounts (correct ownership)
/// - The authority signature is properly checked
/// - BUT: The program performing the actual transfer is never validated
/// - The CPI just calls whatever program ID is provided in token_program
/// - An attacker controls which program executes the sensitive operation
pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
    msg!("Transferring {} tokens from vault", amount);
    msg!("WARNING: Using arbitrary program without validation!");

    // VULNERABILITY: Using solana_program::program::invoke with an unchecked program
    // The token_program account could be ANY program, including malicious ones

    // Manually construct SPL Token transfer instruction
    // Instruction index 3 = Transfer in SPL Token program
    let mut data = vec![3u8]; // Transfer instruction discriminator
    data.extend_from_slice(&amount.to_le_bytes());

    let transfer_ix = Instruction {
        program_id: ctx.accounts.token_program.key(), // This could be a fake program!
        accounts: vec![
            AccountMeta::new(ctx.accounts.source.key(), false),
            AccountMeta::new(ctx.accounts.destination.key(), false),
            AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
        ],
        data,
    };

    solana_program::program::invoke(
        &transfer_ix,
        &[
            ctx.accounts.source.to_account_info(),
            ctx.accounts.destination.to_account_info(),
            ctx.accounts.authority.to_account_info(),
            ctx.accounts.token_program.to_account_info(),  // Unchecked!
        ],
    )?;

    msg!("Transfer completed (or was it?)");
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

    /// VULNERABILITY: UncheckedAccount instead of Program<'info, Token>
    /// This allows ANY program to be passed, including malicious ones
    /// The program receives full authority over the CPI operation
    ///
    /// CHECK: This account is NOT checked - that's the vulnerability!
    /// An attacker can pass a malicious program that:
    /// - Reverses transfer direction (destination -> source instead)
    /// - Transfers to attacker's wallet instead of intended destination
    /// - Executes arbitrary malicious logic with vault's authority
    pub token_program: UncheckedAccount<'info>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Only the vault authority can authorize transfers")]
    UnauthorizedAuthority,

    #[msg("Source must be the vault's token account")]
    InvalidSourceAccount,
}
