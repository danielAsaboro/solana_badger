use anchor_lang::prelude::*;
use crate::state::VaultState;

pub fn force_close(_ctx: Context<ForceClose>) -> Result<()> {
    // Anchor's close constraint handles everything:
    // 1. Transfers lamports to authority
    // 2. Zeros all account data (prevents revival)
    // 3. Sets account owner to System Program
    msg!("Account properly closed with data zeroed");
    Ok(())
}

#[derive(Accounts)]
pub struct ForceClose<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump,
        has_one = authority,
        close = authority  // SECURE: Anchor's close constraint zeros data!
    )]
    pub vault: Account<'info, VaultState>,
}
