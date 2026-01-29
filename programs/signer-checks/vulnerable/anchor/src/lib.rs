use anchor_lang::prelude::*;

declare_id!("6aMtrYT8eeCbtvtfcAEiUfkQAZ9MHVgRipAFKgddC3TD");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod vulnerable_signer_checks {
    use super::*;

    /// Initialize a new program account with an owner
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize(ctx)
    }

    /// VULNERABLE: Update owner without verifying the current owner signed the transaction
    /// This allows anyone to change the owner of any account!
    pub fn update_owner(ctx: Context<UpdateOwnership>) -> Result<()> {
        instructions::update_owner(ctx)
    }
}
