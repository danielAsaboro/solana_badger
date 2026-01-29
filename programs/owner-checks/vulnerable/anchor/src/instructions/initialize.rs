use anchor_lang::prelude::*;
use crate::state::ProgramAccount;

/// Initialize a new program account
pub fn initialize(ctx: Context<Initialize>, data: u64) -> Result<()> {
    let program_account = &mut ctx.accounts.program_account;

    // Set initial data
    program_account.data = data;
    program_account.authority = ctx.accounts.authority.key();

    msg!("Program account initialized with data: {}", program_account.data);
    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The authority who will control this account (properly validated with Signer type)
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The program account being initialized
    #[account(
        init,
        payer = authority,
        space = ProgramAccount::LEN,
        seeds = [b"program-account", authority.key().as_ref()],
        bump
    )]
    pub program_account: Account<'info, ProgramAccount>,

    /// System program for account creation
    pub system_program: Program<'info, System>,
}
