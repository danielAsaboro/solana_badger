use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use crate::state::TokenPool;

/// SECURE: Withdraw tokens with proper validation
///
/// THE FIX:
/// This instruction prevents PDA sharing attacks through multiple layers:
///
/// 1. User-Specific PDA: seeds = [b"pool", owner, mint]
///    - Each user has their own unique pool PDA
///    - Bob cannot derive Alice's pool PDA
///
/// 2. Owner Validation: has_one = owner
///    - Pool.owner must match the signer
///    - Only the true owner can sign for withdrawals
///
/// 3. Destination Validation: Optional constraint for extra security
///    - Can enforce destination ownership
///
/// ATTACK PREVENTION:
/// 1. Alice deposits 100 USDC → vault at [b"pool", ALICE, USDC_MINT]
/// 2. Bob tries to withdraw:
///    - pool: [b"pool", ALICE, USDC_MINT]
///    - But pool.owner = ALICE
///    - has_one = owner constraint fails (BOB != ALICE)
/// 3. Bob's transaction is rejected ❌
///
/// Bob CANNOT access Alice's funds because:
/// - He cannot provide Alice's pool PDA (it requires her pubkey)
/// - Even if he derives it, has_one = owner prevents unauthorized withdrawal
/// - The pool PDA will only sign for the legitimate owner
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    msg!("=== SECURE WITHDRAWAL ===");
    msg!("Withdrawing {} tokens from personal pool", amount);
    msg!("Owner: {}", ctx.accounts.pool.owner);
    msg!("Destination: {}", ctx.accounts.destination.key());
    msg!("SECURE: Owner validation prevents unauthorized withdrawals");

    // SECURITY: User-specific PDA seeds ensure isolated authority
    let seeds = &[
        b"pool",
        ctx.accounts.pool.owner.as_ref(),
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

    msg!("Withdrawal successful - only owner can withdraw their tokens");
    Ok(())
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// SECURITY: Must be the pool owner
    pub owner: Signer<'info>,

    /// SECURITY FIX 1: Pool PDA derived from owner + mint
    /// This creates a unique PDA per user
    ///
    /// SECURITY FIX 2: has_one = owner constraint
    /// Ensures only the pool owner can withdraw
    #[account(
        seeds = [b"pool", pool.owner.as_ref(), pool.mint.as_ref()],
        bump = pool.bump,
        has_one = owner @ ErrorCode::UnauthorizedWithdrawal
    )]
    pub pool: Account<'info, TokenPool>,

    /// User's personal vault (isolated per user)
    #[account(
        mut,
        constraint = vault.key() == pool.vault @ ErrorCode::InvalidVault
    )]
    pub vault: Account<'info, TokenAccount>,

    /// Destination for withdrawn tokens
    /// OPTIONAL: Can add owner check for extra security
    #[account(
        mut,
        constraint = destination.mint == pool.mint @ ErrorCode::InvalidDestinationMint,
        // OPTIONAL: Enforce owner matches:
        // constraint = destination.owner == owner.key() @ ErrorCode::InvalidDestinationOwner
    )]
    pub destination: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Only the pool owner can withdraw")]
    UnauthorizedWithdrawal,

    #[msg("Vault must match pool's vault address")]
    InvalidVault,

    #[msg("Destination mint must match pool mint")]
    InvalidDestinationMint,

    #[msg("Destination must be owned by the pool owner")]
    InvalidDestinationOwner,
}
