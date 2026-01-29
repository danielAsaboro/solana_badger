use anchor_lang::prelude::*;
use crate::state::Vault;

/// SECURE: Initialize a vault with proper protection against reinitialization
///
/// This instruction demonstrates THREE ways to prevent reinitialization attacks:
///
/// METHOD 1 (Recommended - shown here): Use the `init` constraint
/// - Anchor automatically validates discriminator is zero before initializing
/// - Sets discriminator after initialization to prevent future reinit
/// - Most idiomatic and safest approach
///
/// METHOD 2 (Alternative - shown in comments below): Manual discriminator check
/// - Check that the first 8 bytes (discriminator) are all zeros
/// - Only initialize if discriminator is zero
///
/// METHOD 3 (Alternative - for custom init flags): Check initialization flag
/// - Use a custom flag in your account struct
/// - Verify flag is false before initializing
///
/// SECURITY GUARANTEES:
/// - Account can only be initialized once
/// - Discriminator prevents reinitialization attempts
/// - Authority cannot be overwritten after initialization
/// - Funds are protected from takeover attacks
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // METHOD 2 (Alternative): Manual discriminator check
    // If not using `init` constraint, you could manually check:
    // let discriminator = &ctx.accounts.vault.to_account_info().data.borrow()[..8];
    // if discriminator != [0u8; 8] {
    //     return Err(ProgramError::AccountAlreadyInitialized.into());
    // }

    // Set the authority to the signer
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;

    msg!("Vault securely initialized with authority: {}", vault.authority);
    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The signer who will become the authority
    #[account(mut)]
    pub authority: Signer<'info>,

    /// FIX #1 (Recommended): Use the `init` constraint
    ///
    /// The `init` constraint provides complete protection by:
    /// 1. Checking discriminator is zero (account not initialized)
    /// 2. Creating account with correct size
    /// 3. Setting discriminator to prevent future reinitialization
    /// 4. Handling rent payment automatically
    ///
    /// This makes reinitialization attacks impossible because any attempt
    /// to initialize an already-initialized account will fail the
    /// discriminator check before any data is written.
    #[account(
        init,
        payer = authority,
        space = Vault::LEN
    )]
    pub vault: Account<'info, Vault>,

    /// System program for account creation
    pub system_program: Program<'info, System>,
}
