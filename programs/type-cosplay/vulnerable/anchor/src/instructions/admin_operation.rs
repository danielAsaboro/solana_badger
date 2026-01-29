use anchor_lang::prelude::*;
use crate::state::Admin;

/// VULNERABLE: Admin operation that doesn't validate account discriminator
///
/// THE VULNERABILITY:
/// This instruction uses UncheckedAccount instead of Account<'info, Admin>.
/// This means Anchor will NOT verify the discriminator, allowing an attacker
/// to pass a User account where an Admin account is expected!
///
/// ATTACK SCENARIO:
/// 1. Attacker creates a User account (privilege_level = 1)
/// 2. Attacker calls admin_operation, passing their User account as admin_account
/// 3. The program only checks program ownership (line below)
/// 4. Deserialization succeeds because User and Admin have identical layouts
/// 5. The attacker's User account is treated as Admin, gaining privilege escalation!
/// 6. Operation executes with elevated privileges despite using a User account
///
/// WHY IT WORKS:
/// - Both Admin and User have the same memory layout (Pubkey + u8 + u64)
/// - UncheckedAccount skips discriminator validation
/// - Manual deserialization doesn't check the discriminator
/// - Only the authority signature and program ownership are verified
pub fn admin_operation(ctx: Context<AdminOperation>) -> Result<()> {
    let admin_account_info = ctx.accounts.admin_account.to_account_info();

    // Check 1: Verify the account is owned by our program
    // This check PASSES for both Admin and User accounts!
    if admin_account_info.owner != ctx.program_id {
        return Err(ProgramError::IllegalOwner.into());
    }

    // MISSING CHECK: Should verify discriminator here!
    // Without this, we can't distinguish Admin from User accounts

    // Manually deserialize the account data
    let data = admin_account_info.data.borrow();

    // Skip the first 8 bytes (discriminator) and deserialize the rest
    // VULNERABILITY: We skip the discriminator without checking it!
    let admin: Admin = Admin::try_from_slice(&data[8..])?;

    // Check 2: Verify the authority signed the transaction
    // This check PASSES because the attacker is signing with their own key
    if admin.authority != ctx.accounts.authority.key() {
        return Err(ProgramError::InvalidAccountData.into());
    }

    // At this point, the "admin" could actually be a User account!
    // The attacker has successfully performed a type cosplay attack

    msg!("=== ADMIN OPERATION EXECUTED ===");
    msg!("Authority: {}", admin.authority);
    msg!("Privilege Level: {}", admin.privilege_level);
    msg!("Operation Count: {}", admin.operation_count);

    // In a real scenario, this would perform privileged operations
    // like transferring funds, updating critical state, etc.
    msg!("Performing privileged admin operation...");
    msg!("WARNING: This operation executed without proper type validation!");

    // Update operation count
    let mut data = admin_account_info.data.borrow_mut();
    let mut updated_admin: Admin = Admin::try_from_slice(&data[8..])?;
    updated_admin.operation_count += 1;

    // Serialize back to account
    let mut writer = &mut data[8..];
    updated_admin.serialize(&mut writer)?;

    Ok(())
}

#[derive(Accounts)]
pub struct AdminOperation<'info> {
    /// Authority attempting to perform admin operation
    pub authority: Signer<'info>,

    /// VULNERABILITY: Using UncheckedAccount instead of Account<'info, Admin>
    ///
    /// Account<'info, Admin> would automatically:
    /// 1. Verify the discriminator matches Admin
    /// 2. Ensure type safety at compile time
    /// 3. Prevent type cosplay attacks
    ///
    /// But UncheckedAccount:
    /// 1. Skips ALL Anchor validation
    /// 2. Allows any account to be passed
    /// 3. Enables type confusion attacks
    #[account(mut)]
    /// CHECK: DANGEROUS - This account is not validated by Anchor!
    /// An attacker can pass a User account here and it will be treated as Admin!
    pub admin_account: UncheckedAccount<'info>,
}
