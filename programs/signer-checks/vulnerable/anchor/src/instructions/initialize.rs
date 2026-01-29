use anchor_lang::prelude::*;
use crate::state::ProgramAccount;

/// Initialize a new program account
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let program_account = &mut ctx.accounts.program_account;

    // Set the owner to the initializer
    program_account.owner = ctx.accounts.owner.key();
    program_account.data = 0;

    msg!("Program account initialized with owner: {}", program_account.owner);
    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The signer who will become the owner (properly validated with Signer type)
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The program account being initialized
    #[account(
        init,
        payer = owner,
        space = ProgramAccount::LEN,
        seeds = [b"program-account", owner.key().as_ref()],
        bump
    )]
    pub program_account: Account<'info, ProgramAccount>,

    /// System program for account creation
    pub system_program: Program<'info, System>,
}
