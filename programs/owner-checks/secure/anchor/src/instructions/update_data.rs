use anchor_lang::prelude::*;
use crate::state::ProgramAccount;

/// SECURE: Updates account data with proper owner validation
///
/// This implementation demonstrates THREE ways to fix the owner check vulnerability:
/// 1. Using Account<'info, T> type (primary method shown here)
/// 2. Using the #[account(owner = ID)] constraint (alternative shown in comments)
/// 3. Manual owner check in instruction logic (alternative shown in comments)
///
/// SECURITY GUARANTEES:
/// - The Account<'info, ProgramAccount> type forces Anchor to verify:
///   1. The account is owned by this program (crate::ID)
///   2. The discriminator matches ProgramAccount
///   3. The data deserializes correctly to ProgramAccount
/// - Attackers CANNOT pass fake accounts owned by other programs
/// - The program will only process data from accounts it actually controls
/// - This prevents malicious data injection through lookalike accounts
///
/// WHY THIS IS SECURE:
/// - Anchor checks: account.owner == crate::ID before deserializing
/// - Even if an attacker creates an account with identical structure, it will be rejected
/// - The type system enforces security at compile time
/// - It's like checking both the ID content AND the issuing authority
pub fn update_data(ctx: Context<UpdateData>, new_data: u64) -> Result<()> {
    // FIX #3 (Alternative): Manual owner check in instruction logic
    // Uncomment this to use manual validation instead of Account type:
    // if ctx.accounts.program_account.owner != &crate::ID {
    //     return Err(ProgramError::IncorrectProgramId.into());
    // }

    let program_account = &ctx.accounts.program_account;

    // Now it's safe to trust this data - we've verified the account is owned by our program!
    msg!("Current data from account: {}", program_account.data);
    msg!("Authority from account: {}", program_account.authority);

    // Business logic based on validated data
    if program_account.data < 100 {
        msg!("Data validation passed, allowing update");
    }

    // Safe to update - we know this is a legitimate account
    msg!("Updating data from {} to {}", program_account.data, new_data);

    // Note: We're not actually modifying the account here for demonstration,
    // but if we did, it would be safe because we verified ownership
    // let program_account = &mut ctx.accounts.program_account;
    // program_account.data = new_data;

    Ok(())
}

#[derive(Accounts)]
pub struct UpdateData<'info> {
    /// The authority making the update
    pub authority: Signer<'info>,

    // FIX #1 (Recommended): Use Account<'info, T> type for automatic owner validation
    // The Account<'info, ProgramAccount> type ensures this account:
    // - Is owned by this program (crate::ID)
    // - Has the correct discriminator
    // - Deserializes correctly to ProgramAccount
    // Anchor automatically performs all checks before the instruction runs.
    #[account(mut)]
    pub program_account: Account<'info, ProgramAccount>,

    // FIX #2 (Alternative): Use owner constraint with UncheckedAccount
    // This is less common but equally secure:
    // #[account(mut, owner = crate::ID)]
    // /// CHECK: Owner validation enforced by constraint
    // pub program_account: UncheckedAccount<'info>,
    //
    // Or you can be more explicit and use the declare_id macro:
    // #[account(mut, owner = ID)]
    // /// CHECK: Owner validation enforced by constraint
    // pub program_account: UncheckedAccount<'info>,
}
