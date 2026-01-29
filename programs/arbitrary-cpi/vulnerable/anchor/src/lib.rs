use anchor_lang::prelude::*;

declare_id!("J9nJgXQ2pckccZdRb6zuRXJiupqF7AJN7yFzzJTHepkz");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod vulnerable_arbitrary_cpi {
    use super::*;

    /// Initialize a token vault with authority
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize(ctx)
    }

    /// VULNERABLE: Transfer tokens using an arbitrary program without validation
    /// This allows attackers to pass malicious programs that can:
    /// - Reverse the transfer direction
    /// - Drain tokens to attacker's wallet
    /// - Execute arbitrary malicious logic
    pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
        instructions::transfer_tokens(ctx, amount)
    }
}
