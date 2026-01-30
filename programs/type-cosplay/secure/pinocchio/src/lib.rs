#![no_std]

use pinocchio::{
    entrypoint,
    AccountView,
    Address,
    ProgramResult,
};
use solana_program_error::ProgramError;

pub mod state;
use state::{Admin, User};

const ID: Address = Address::new_from_array([
    0x53, 0x65, 0x63, 0x75, 0x54, 0x79, 0x70, 0x65,
    0x50, 0x69, 0x6e, 0x6f, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x02,
]);

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
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
fn initialize_admin(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, admin_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if !admin_account_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Initialize the account
    let mut data = admin_account_info.try_borrow_mut()?;

    if data.len() < Admin::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Serialize Admin account with discriminator
    let authority_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    Admin::serialize(&authority_bytes, 0, &mut data);

    Ok(())
}

/// Initialize a new User account
fn initialize_user(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, user_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if !user_account_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Initialize the account
    let mut data = user_account_info.try_borrow_mut()?;

    if data.len() < User::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Serialize User account with discriminator
    let authority_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    User::serialize(&authority_bytes, 0, &mut data);

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
fn admin_operation(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, admin_account_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if !admin_account_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // SECURITY: Validate discriminator BEFORE deserializing
    let data = admin_account_info.try_borrow()?;

    if data.len() < Admin::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Method 1: Explicit discriminator check before deserialization
    if data[0] != Admin::DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }

    // Method 2: Use the secure deserialize function that checks internally
    // The Admin::deserialize function now validates the discriminator
    let admin = Admin::deserialize(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Verify the authority matches
    let authority_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    if admin.authority != authority_bytes {
        return Err(ProgramError::InvalidAccountData);
    }

    // At this point, we are GUARANTEED to have a valid Admin account
    // User accounts will have been rejected at the discriminator check

    // Perform privileged operations safely

    // Update operation count
    drop(data); // Release borrow
    let mut data = admin_account_info.try_borrow_mut()?;

    // Validate discriminator again before updating
    if data[0] != Admin::DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }

    let admin = Admin::deserialize(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    let new_count = admin.operation_count + 1;

    // Update operation count
    data[34..42].copy_from_slice(&new_count.to_le_bytes());

    Ok(())
}
