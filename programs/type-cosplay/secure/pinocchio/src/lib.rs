#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub mod state;
use state::{Admin, User, discriminators};

const ID: Pubkey = pinocchio::pubkey!("SecuTypePino1111111111111111111111111111");

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if program_id != &ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Instruction dispatch based on first byte
    match instruction_data.first() {
        Some(&0) => initialize_admin(accounts),
        Some(&1) => initialize_user(accounts),
        Some(&2) => admin_operation(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a new Admin account
fn initialize_admin(accounts: &[AccountInfo]) -> ProgramResult {
    let [authority_info, admin_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if admin_account_info.owner() != &ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Initialize the account
    let mut data = admin_account_info.try_borrow_mut_data()?;

    if data.len() < Admin::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Serialize Admin account with discriminator
    Admin::serialize(authority_info.key().as_ref(), 0, &mut data);

    msg!("Admin account initialized for authority: {}", authority_info.key());
    msg!("Privilege level: {}", Admin::PRIVILEGE_LEVEL);

    Ok(())
}

/// Initialize a new User account
fn initialize_user(accounts: &[AccountInfo]) -> ProgramResult {
    let [authority_info, user_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if user_account_info.owner() != &ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Initialize the account
    let mut data = user_account_info.try_borrow_mut_data()?;

    if data.len() < User::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Serialize User account with discriminator
    User::serialize(authority_info.key().as_ref(), 0, &mut data);

    msg!("User account initialized for authority: {}", authority_info.key());
    msg!("Privilege level: {}", User::PRIVILEGE_LEVEL);

    Ok(())
}

/// SECURE: Admin operation with discriminator validation
///
/// THE FIX:
/// Before deserializing, we validate that the discriminator matches Admin.
/// This prevents User accounts from being treated as Admin accounts!
///
/// HOW IT PREVENTS THE ATTACK:
/// 1. Attacker creates a User account with discriminator = 2
/// 2. Attacker calls admin_operation with their User account
/// 3. Program checks program ownership (passes)
/// 4. Program checks discriminator: data[0] == Admin::DISCRIMINATOR?
/// 5. data[0] = 2 (User), Admin::DISCRIMINATOR = 1
/// 6. Discriminator check FAILS
/// 7. Transaction aborts with "Invalid discriminator" error
/// 8. No privilege escalation occurs!
///
/// ATTACK SCENARIO (PREVENTED):
/// Before: Attacker could pass User account as Admin
/// After: Discriminator check catches the type mismatch immediately
fn admin_operation(accounts: &[AccountInfo]) -> ProgramResult {
    let [authority_info, admin_account_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if admin_account_info.owner() != &ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // SECURITY: Validate discriminator BEFORE deserializing
    let data = admin_account_info.try_borrow_data()?;

    if data.len() < Admin::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Method 1: Explicit discriminator check before deserialization
    if data[0] != Admin::DISCRIMINATOR {
        msg!("ERROR: Invalid account type!");
        msg!("Expected Admin (discriminator={}), got discriminator={}",
             Admin::DISCRIMINATOR, data[0]);
        return Err(ProgramError::InvalidAccountData);
    }

    // Method 2: Use the secure deserialize function that checks internally
    // The Admin::deserialize function now validates the discriminator
    let admin = Admin::deserialize(&data)
        .map_err(|e| {
            msg!("Deserialization failed: {}", e);
            ProgramError::InvalidAccountData
        })?;

    // Verify the authority matches
    if admin.authority != *authority_info.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // At this point, we are GUARANTEED to have a valid Admin account
    // User accounts will have been rejected at the discriminator check

    msg!("=== SECURE ADMIN OPERATION EXECUTED ===");
    msg!("Authority: {}", authority_info.key());
    msg!("Privilege Level: {}", admin.privilege_level);
    msg!("Operation Count: {}", admin.operation_count);
    msg!("Type validation passed: This is a verified Admin account");

    // Perform privileged operations safely
    msg!("Performing privileged admin operation...");

    // Update operation count
    drop(data); // Release borrow
    let mut data = admin_account_info.try_borrow_mut_data()?;

    // Validate discriminator again before updating
    if data[0] != Admin::DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }

    let admin = Admin::deserialize(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    let new_count = admin.operation_count + 1;

    // Update operation count
    data[34..42].copy_from_slice(&new_count.to_le_bytes());

    msg!("Operation count updated to: {}", new_count);

    Ok(())
}
