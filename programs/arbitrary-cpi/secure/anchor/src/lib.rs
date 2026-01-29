use anchor_lang::prelude::*;

declare_id!("BvjL8mMCaXZ54EnfaFJLPcnx2jFgvtnpCb9XmKoDx3eu");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod secure_arbitrary_cpi {
    use super::*;

    /// Initialize a token vault with authority
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize(ctx)
    }

    /// SECURE: Transfer tokens with proper program validation
    /// Uses Program<'info, Token> to automatically validate the program ID
    /// This prevents attackers from passing malicious programs
    pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
        instructions::transfer_tokens(ctx, amount)
    }

    /// Alternative secure implementation using Anchor's CPI helpers
    /// This is the recommended approach for Anchor programs
    pub fn transfer_tokens_with_cpi_helper(
        ctx: Context<TransferTokensWithHelper>,
        amount: u64,
    ) -> Result<()> {
        instructions::transfer_tokens_with_cpi_helper(ctx, amount)
    }
}
