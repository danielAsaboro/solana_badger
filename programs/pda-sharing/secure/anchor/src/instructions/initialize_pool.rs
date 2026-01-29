use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, TokenAccount};
use crate::state::TokenPool;

/// Initialize a user-specific token pool
///
/// SECURITY FIX: The pool PDA is derived using BOTH user AND mint:
/// seeds = [b"pool", owner.key().as_ref(), mint.key().as_ref()]
///
/// This creates unique PDAs per user:
/// - Alice's pool: [b"pool", ALICE_PUBKEY, USDC_MINT]
/// - Bob's pool: [b"pool", BOB_PUBKEY, USDC_MINT]
/// - Charlie's pool: [b"pool", CHARLIE_PUBKEY, USDC_MINT]
///
/// Each user has isolated authority over only their own tokens!
pub fn initialize_pool(ctx: Context<InitializePool>) -> Result<()> {
    let pool = &mut ctx.accounts.pool;

    pool.owner = ctx.accounts.owner.key();
    pool.depositor = ctx.accounts.owner.key();
    pool.mint = ctx.accounts.mint.key();
    pool.vault = ctx.accounts.vault.key();
    pool.bump = ctx.bumps.pool;

    msg!("Pool initialized for owner: {}", pool.owner);
    msg!("Mint: {}", pool.mint);
    msg!("Vault address: {}", pool.vault);
    msg!("SECURE: Pool PDA includes user pubkey - isolated per user");

    Ok(())
}

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    /// SECURITY FIX: Pool PDA uses BOTH owner AND mint as seeds
    /// This creates a unique PDA for each user-mint combination
    ///
    /// Seeds: [b"pool", owner.key().as_ref(), mint.key().as_ref()]
    /// - Includes user-specific identifier (owner pubkey)
    /// - Each user has their own isolated pool
    /// - Cross-user attacks are impossible
    #[account(
        init,
        payer = owner,
        space = TokenPool::LEN,
        seeds = [b"pool", owner.key().as_ref(), mint.key().as_ref()],
        bump
    )]
    pub pool: Account<'info, TokenPool>,

    /// Token account that will hold this user's deposited tokens
    /// Owned by the user-specific pool PDA
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
