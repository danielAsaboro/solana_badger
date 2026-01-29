use anchor_lang::prelude::*;
use crate::state::Admin;

/// SECURE: Admin operation with proper type validation
///
/// THE FIX:
/// This instruction uses Account<'info, Admin> instead of UncheckedAccount.
/// Anchor automatically validates the discriminator, preventing type cosplay attacks!
///
/// HOW IT PREVENTS THE ATTACK:
/// 1. When Anchor deserializes Account<'info, Admin>, it checks the discriminator
/// 2. Admin discriminator = hash("account:Admin")[..8]
/// 3. User discriminator = hash("account:User")[..8]
/// 4. These are different, so User accounts will be REJECTED
/// 5. The attack fails at the deserialization stage before any logic executes
///
/// ATTACK SCENARIO (PREVENTED):
/// 1. Attacker creates a User account (privilege_level = 1)
/// 2. Attacker calls admin_operation, passing their User account as admin_account
/// 3. Anchor checks the discriminator in the account data
/// 4. User discriminator != Admin discriminator
/// 5. Transaction FAILS with "AccountDiscriminatorMismatch" error
/// 6. No privilege escalation occurs!
pub fn admin_operation(ctx: Context<AdminOperation>) -> Result<()> {
    let admin = &mut ctx.accounts.admin_account;

    // At this point, we are GUARANTEED that admin_account is actually an Admin
    // because Anchor has already validated the discriminator

    msg!("=== SECURE ADMIN OPERATION EXECUTED ===");
    msg!("Authority: {}", admin.authority);
    msg!("Privilege Level: {}", admin.privilege_level);
    msg!("Operation Count: {}", admin.operation_count);

    // Perform privileged operations safely
    msg!("Performing privileged admin operation...");
    msg!("Type validation passed: This is a verified Admin account");

    // Update operation count
    admin.operation_count += 1;

    Ok(())
}

#[derive(Accounts)]
pub struct AdminOperation<'info> {
    /// Authority attempting to perform admin operation
    pub authority: Signer<'info>,

    /// SECURITY: Using Account<'info, Admin> for automatic type validation
    ///
    /// Account<'info, Admin> provides:
    /// 1. Automatic discriminator verification (Admin vs User)
    /// 2. Type safety at compile time
    /// 3. Protection against type cosplay attacks
    /// 4. Automatic deserialization with validation
    ///
    /// The constraint ensures the authority matches:
    #[account(
        mut,
        constraint = admin_account.authority == authority.key() @ ErrorCode::Unauthorized
    )]
    pub admin_account: Account<'info, Admin>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized: You are not the authority of this admin account")]
    Unauthorized,
}
