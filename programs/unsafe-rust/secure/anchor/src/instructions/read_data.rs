use anchor_lang::prelude::*;
use crate::state::DataStore;

pub fn read_data(ctx: Context<ReadData>) -> Result<()> {
    let store = &ctx.accounts.store;

    // SECURE: Anchor automatically validates:
    // 1. Account discriminator (type check)
    // 2. Account ownership (program owns it)
    // 3. Proper deserialization with bounds checking

    require!(store.is_initialized, ErrorCode::NotInitialized);
    require!(store.authority == ctx.accounts.authority.key(), ErrorCode::Unauthorized);

    msg!("Authority: {}", store.authority);
    msg!("Value: {}", store.value);

    Ok(())
}

#[derive(Accounts)]
pub struct ReadData<'info> {
    pub authority: Signer<'info>,

    // SECURE: Typed Account validates discriminator, ownership, deserialization
    #[account(
        seeds = [b"store", authority.key().as_ref()],
        bump,
        has_one = authority,
    )]
    pub store: Account<'info, DataStore>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Account not initialized")]
    NotInitialized,
    #[msg("Unauthorized access")]
    Unauthorized,
}
