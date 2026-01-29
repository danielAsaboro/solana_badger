use anchor_lang::prelude::*;
use crate::state::Admin;

/// Initialize a new Admin account
pub fn initialize_admin(ctx: Context<InitializeAdmin>) -> Result<()> {
    let admin = &mut ctx.accounts.admin_account;

    admin.authority = ctx.accounts.authority.key();
    admin.privilege_level = Admin::PRIVILEGE_LEVEL;
    admin.operation_count = 0;

    msg!("Admin account initialized for authority: {}", admin.authority);
    msg!("Privilege level: {}", admin.privilege_level);

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeAdmin<'info> {
    /// Authority who will control the admin account
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The Admin account being initialized
    /// This will have the Admin discriminator automatically added by Anchor
    #[account(
        init,
        payer = authority,
        space = 8 + Admin::LEN,
        seeds = [b"admin", authority.key().as_ref()],
        bump
    )]
    pub admin_account: Account<'info, Admin>,

    pub system_program: Program<'info, System>,
}
