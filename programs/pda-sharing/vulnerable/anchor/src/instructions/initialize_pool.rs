use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, TokenAccount};
use crate::state::TokenPool;

/// Initialize a token pool for a specific mint
///
/// VULNERABILITY: The pool PDA is derived using ONLY the mint address:
/// seeds = [b"pool", mint.key().as_ref()]
///
/// This means:
/// - Alice deposits tokens → creates pool with seeds [b"pool", USDC_MINT]
/// - Bob deposits same token → uses SAME pool PDA [b"pool", USDC_MINT]
/// - Charlie deposits same token → uses SAME pool PDA [b"pool", USDC_MINT]
///
/// All three users share the SAME PDA authority, allowing cross-user exploitation!
pub fn initialize_pool(ctx: Context<InitializePool>) -> Result<()> {
    let pool = &mut ctx.accounts.pool;

    pool.mint = ctx.accounts.mint.key();
    pool.vault = ctx.accounts.vault.key();
    pool.bump = ctx.bumps.pool;

    msg!("Pool initialized for mint: {}", pool.mint);
    msg!("Vault address: {}", pool.vault);
    msg!("WARNING: Pool PDA derived from mint only - VULNERABLE to PDA sharing attacks!");

    Ok(())
}

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(mut)]
    pub initializer: Signer<'info>,

    /// VULNERABILITY: Pool PDA uses only mint as seed
    /// This creates a SHARED PDA across all users depositing this mint!
    ///
    /// Problem: seeds = [b"pool", mint.key().as_ref()]
    /// - Missing user-specific identifier
    /// - All users share the same PDA
    /// - Pool becomes a master key for all user funds
    #[account(
        init,
        payer = initializer,
        space = TokenPool::LEN,
        seeds = [b"pool", mint.key().as_ref()],
        bump
    )]
    pub pool: Account<'info, TokenPool>,

    /// Token account that will hold deposited tokens
    /// Owned by the pool PDA for signing authority
    #[account(
        constraint = vault.owner == pool.key() @ ErrorCode::InvalidVaultOwner,
        constraint = vault.mint == mint.key() @ ErrorCode::InvalidVaultMint
    )]
    pub vault: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Vault must be owned by the pool PDA")]
    InvalidVaultOwner,

    #[msg("Vault mint must match pool mint")]
    InvalidVaultMint,
}
