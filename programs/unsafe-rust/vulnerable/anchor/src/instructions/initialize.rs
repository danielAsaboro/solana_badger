use anchor_lang::prelude::*;
use crate::state::DataStore;

pub fn initialize(ctx: Context<Initialize>, value: u64, label: [u8; 32]) -> Result<()> {
    let store = &mut ctx.accounts.store;
    store.authority = ctx.accounts.authority.key();
    store.value = value;
    store.label = label;
    store.is_initialized = true;
    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = DataStore::LEN,
        seeds = [b"store", authority.key().as_ref()],
        bump
    )]
    pub store: Account<'info, DataStore>,

    pub system_program: Program<'info, System>,
}
