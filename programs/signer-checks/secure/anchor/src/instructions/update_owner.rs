use anchor_lang::prelude::*;
use crate::state::ProgramAccount;

/// SECURE: Updates the owner with proper signer validation
///
/// This implementation demonstrates THREE different ways to fix the vulnerability:
/// 1. Using the Signer type (primary method shown here)
/// 2. Using the #[account(signer)] constraint (alternative shown in comments)
/// 3. Manual is_signer check in the instruction logic (alternative shown in comments)
///
/// SECURITY GUARANTEES:
/// - The Signer type forces Anchor to verify:
///   1. The account signed the transaction
///   2. The signature is cryptographically valid
///   3. The signature matches the public key
/// - Attackers CANNOT pass someone else's public key without their actual signature
/// - This prevents unauthorized ownership transfers
pub fn update_owner(ctx: Context<UpdateOwnership>) -> Result<()> {
    let program_account = &mut ctx.accounts.program_account;
    let old_owner = program_account.owner;

    // FIX #3 (Alternative): Manual signer check in instruction logic
    // Uncomment this to use manual validation instead of Signer type:
    // if !ctx.accounts.owner.is_signer {
    //     return Err(ProgramError::MissingRequiredSignature.into());
    // }

    // Safe to update owner now - we've verified the current owner signed
    program_account.owner = ctx.accounts.new_owner.key();

    msg!("Owner updated from {} to {}", old_owner, program_account.owner);
    Ok(())
}

#[derive(Accounts)]
pub struct UpdateOwnership<'info> {
    // FIX #1 (Recommended): Use Signer type for automatic signature validation
    // The Signer<'info> type ensures this account signed the transaction.
    // Anchor automatically checks is_signer and returns an error if false.
    pub owner: Signer<'info>,

    // FIX #2 (Alternative): Use signer constraint with UncheckedAccount
    // This is equivalent to using Signer type but more explicit:
    // #[account(signer)]
    // pub owner: UncheckedAccount<'info>,

    /// The program account to update
    ///
    /// Now that owner is a Signer, the has_one constraint provides dual protection:
    /// 1. Data validation: program_account.owner == owner.key() (prevents wrong account)
    /// 2. Signature validation: owner.is_signer == true (prevents unauthorized access)
    #[account(
        mut,
        has_one = owner,
        seeds = [b"program-account", owner.key().as_ref()],
        bump
    )]
    pub program_account: Account<'info, ProgramAccount>,

    /// The new owner to set
    /// CHECK: This is the new owner being set, no validation needed
    pub new_owner: UncheckedAccount<'info>,
}
