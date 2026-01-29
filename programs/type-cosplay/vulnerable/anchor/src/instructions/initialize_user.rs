use anchor_lang::prelude::*;
use crate::state::User;

/// Initialize a new User account
pub fn initialize_user(ctx: Context<InitializeUser>) -> Result<()> {
    let user = &mut ctx.accounts.user_account;

    user.authority = ctx.accounts.authority.key();
    user.privilege_level = User::PRIVILEGE_LEVEL;
    user.operation_count = 0;

    msg!("User account initialized for authority: {}", user.authority);
    msg!("Privilege level: {}", user.privilege_level);

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeUser<'info> {
    /// Authority who will control the user account
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The User account being initialized
    /// This will have the User discriminator automatically added by Anchor
    #[account(
        init,
        payer = authority,
        space = 8 + User::LEN,
        seeds = [b"user", authority.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, User>,

    pub system_program: Program<'info, System>,
}
