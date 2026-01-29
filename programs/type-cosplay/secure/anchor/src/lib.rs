use anchor_lang::prelude::*;

declare_id!("2aVdRcZRWcmttBdWJR7z9dt47UkSrrdB3Fco1F8yLmcj");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod secure_type_cosplay {
    use super::*;

    /// Initialize an Admin account with elevated privileges
    pub fn initialize_admin(ctx: Context<InitializeAdmin>) -> Result<()> {
        instructions::initialize_admin(ctx)
    }

    /// Initialize a regular User account with basic privileges
    pub fn initialize_user(ctx: Context<InitializeUser>) -> Result<()> {
        instructions::initialize_user(ctx)
    }

    /// SECURE: Perform admin operation with proper type validation
    /// Uses Account<'info, Admin> which automatically validates discriminator
    pub fn admin_operation(ctx: Context<AdminOperation>) -> Result<()> {
        instructions::admin_operation(ctx)
    }
}
