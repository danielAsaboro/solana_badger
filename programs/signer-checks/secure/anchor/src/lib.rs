use anchor_lang::prelude::*;

declare_id!("9KLc9xT6Ub25gpr5QvJbcJC2kEH6zCWSEF9s1ZDj7pPb");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod secure_signer_checks {
    use super::*;

    /// Initialize a new program account with an owner
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize(ctx)
    }

    /// SECURE: Update owner with proper signer validation
    /// This ensures only the current owner can transfer ownership
    pub fn update_owner(ctx: Context<UpdateOwnership>) -> Result<()> {
        instructions::update_owner(ctx)
    }
}
