use anchor_lang::prelude::*;
use crate::state::VaultState;

pub fn force_close(ctx: Context<ForceClose>) -> Result<()> {
    let vault = &ctx.accounts.vault;

    // VULNERABILITY: Only drain lamports, don't zero data!
    // After this, the account data still contains valid-looking state
    // within the same transaction slot
    let vault_lamports = vault.to_account_info().lamports();

    **vault.to_account_info().try_borrow_mut_lamports()? = 0;
    **ctx.accounts.authority.to_account_info().try_borrow_mut_lamports()? += vault_lamports;

    // MISSING: Should zero out account data!
    // MISSING: Should use Anchor's close constraint instead!

    msg!("Account closed but data NOT zeroed - vulnerable to revival!");
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
    )]
    pub vault: Account<'info, VaultState>,
}
