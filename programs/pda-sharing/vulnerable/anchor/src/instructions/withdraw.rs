use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use crate::state::TokenPool;

/// VULNERABLE: Withdraw tokens from pool
///
/// THE VULNERABILITY:
/// This instruction allows ANYONE to withdraw tokens from the shared vault
/// to ANY destination they choose. Here's why:
///
/// 1. Pool PDA is derived from mint only: seeds = [b"pool", mint]
/// 2. All users depositing the same token share this PDA
/// 3. The PDA has signing authority over the vault
/// 4. No validation exists to ensure the withdrawer owns the tokens
/// 5. No per-user balance tracking exists
///
/// ATTACK SCENARIO:
/// 1. Alice deposits 100 USDC → vault now has 100 USDC
/// 2. Bob creates his own token account for USDC
/// 3. Bob calls withdraw with:
///    - pool: [b"pool", USDC_MINT] (shared PDA)
///    - destination: Bob's token account
///    - amount: 100 (Alice's tokens!)
/// 4. Pool PDA signs the transfer (it has authority)
/// 5. Bob successfully steals Alice's 100 USDC
///
/// The shared PDA acts as a master key that unlocks everyone's funds!
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    msg!("=== VULNERABLE WITHDRAWAL ===");
    msg!("Withdrawing {} tokens from shared pool", amount);
    msg!("Destination: {}", ctx.accounts.destination.key());
    msg!("WARNING: No validation of token ownership!");

    // VULNERABILITY: The pool PDA can sign transfers to ANY destination
    // There's no check that the withdrawer actually deposited these tokens
    // The shared PDA has authority over ALL users' deposits
    let seeds = &[
        b"pool",
        ctx.accounts.pool.mint.as_ref(),
        &[ctx.accounts.pool.bump],
    ];
    let signer = &[&seeds[..]];

    let cpi_accounts = Transfer {
        from: ctx.accounts.vault.to_account_info(),
        to: ctx.accounts.destination.to_account_info(),
        authority: ctx.accounts.pool.to_account_info(),
    };

    let cpi_program = ctx.accounts.token_program.to_account_info();
    let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);

    token::transfer(cpi_ctx, amount)?;

    msg!("Withdrawal successful - attacker may have stolen other users' funds!");
    Ok(())
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// MISSING: No validation that this signer actually owns the tokens!
    /// Any signer can call this with any destination
    pub withdrawer: Signer<'info>,

    /// VULNERABILITY: Pool PDA derived from mint only
    /// This shared PDA has authority over ALL users' tokens
    #[account(
        seeds = [b"pool", pool.mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, TokenPool>,

    /// Vault holding all users' tokens (shared)
    #[account(
        mut,
        constraint = vault.key() == pool.vault @ ErrorCode::InvalidVault
    )]
    pub vault: Account<'info, TokenAccount>,

    /// VULNERABILITY: ANY token account can be the destination
    /// No validation that it belongs to someone who deposited tokens
    /// Attacker can withdraw to their own account!
    #[account(
        mut,
        constraint = destination.mint == pool.mint @ ErrorCode::InvalidDestinationMint
    )]
    pub destination: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Vault must match pool's vault address")]
    InvalidVault,

    #[msg("Destination mint must match pool mint")]
    InvalidDestinationMint,
}
