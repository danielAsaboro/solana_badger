use anchor_lang::prelude::*;

declare_id!("2nRRf2TAjrMenoDDPcmMpsuFc2ithWwYXAm9cg2UUCdx");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod vulnerable_type_cosplay {
    use super::*;

    /// Initialize an Admin account with elevated privileges
    pub fn initialize_admin(ctx: Context<InitializeAdmin>) -> Result<()> {
        instructions::initialize_admin(ctx)
    }

    /// Initialize a regular User account with basic privileges
    pub fn initialize_user(ctx: Context<InitializeUser>) -> Result<()> {
        instructions::initialize_user(ctx)
    }

    /// VULNERABLE: Perform admin operation without proper type validation
    /// This accepts UncheckedAccount, allowing type cosplay attacks where
    /// a User account can be passed as an Admin account!
    pub fn admin_operation(ctx: Context<AdminOperation>) -> Result<()> {
        instructions::admin_operation(ctx)
    }
}
