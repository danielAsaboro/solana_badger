use anchor_lang::prelude::*;
use crate::state::Vault;

/// Withdraw SOL from a vault
///
/// Only the vault's authority can withdraw funds.
/// Because the vault cannot be reinitialized, the authority
/// field is protected and only the legitimate owner can withdraw.
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // Verify sufficient balance (read-only check first)
    require!(
        ctx.accounts.vault.balance >= amount,
        WithdrawError::InsufficientFunds
    );

    // Transfer lamports from vault to authority
    **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
    **ctx.accounts.authority.to_account_info().try_borrow_mut_lamports()? += amount;

    // Now take mutable reference and update tracked balance
    let vault = &mut ctx.accounts.vault;
    vault.balance = vault.balance.checked_sub(amount)
        .ok_or(WithdrawError::ArithmeticOverflow)?;

    msg!("Withdrawn {} lamports. Remaining balance: {}", amount, vault.balance);
    Ok(())
}

#[error_code]
pub enum WithdrawError {
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// The authority withdrawing SOL (must match vault.authority)
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The vault being withdrawn from
    ///
    /// The has_one constraint ensures only the stored authority can withdraw.
    /// Because reinitialization is prevented, this authority field cannot be
    /// overwritten by an attacker, keeping funds secure.
    #[account(
        mut,
        has_one = authority
    )]
    pub vault: Account<'info, Vault>,

    /// System program
    pub system_program: Program<'info, System>,
}
