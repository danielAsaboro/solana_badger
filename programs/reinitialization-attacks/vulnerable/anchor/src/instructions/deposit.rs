use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::state::Vault;

/// Deposit SOL into a vault
///
/// This instruction allows anyone to deposit SOL into a vault.
/// The vault's balance tracking is updated, and lamports are transferred.
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // Transfer lamports from depositor to vault first (before mutable borrow)
    let cpi_context = CpiContext::new(
        ctx.accounts.system_program.to_account_info(),
        system_program::Transfer {
            from: ctx.accounts.depositor.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
        },
    );
    system_program::transfer(cpi_context, amount)?;

    // Now take mutable reference and update tracked balance
    let vault = &mut ctx.accounts.vault;
    vault.balance = vault.balance.checked_add(amount)
        .ok_or(DepositError::ArithmeticOverflow)?;

    msg!("Deposited {} lamports. New balance: {}", amount, vault.balance);
    Ok(())
}

#[error_code]
pub enum DepositError {
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    /// The account depositing SOL
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// The vault receiving the deposit
    #[account(mut)]
    pub vault: Account<'info, Vault>,

    /// System program for transferring SOL
    pub system_program: Program<'info, System>,
}
