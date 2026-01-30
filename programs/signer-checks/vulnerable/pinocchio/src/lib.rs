#![no_std]

use pinocchio::{
    entrypoint,
    AccountView,
    Address,
    ProgramResult,
};
use solana_program_error::ProgramError;

pub mod state;
use state::ProgramAccount;

const ID: Address = Address::new_from_array([
    0xd1, 0x6c, 0x7e, 0x1f, 0x8a, 0xb3, 0x4c, 0x5d,
    0xe9, 0x2a, 0x1b, 0xf6, 0xc3, 0x7d, 0x4e, 0x8f,
    0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa, 0x0b, 0x1c,
    0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x01,
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

    // Simple instruction dispatch based on first byte
    match instruction_data.first() {
        Some(&0) => initialize(accounts),
        Some(&1) => update_owner(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a new program account
fn initialize(accounts: &[AccountView]) -> ProgramResult {
    let [owner_info, program_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify owner is a signer (this is correct)
    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if !program_account_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Write initial data
    let mut data = program_account_info.try_borrow_mut()?;

    // Check account has enough space
    if data.len() < ProgramAccount::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Initialize the account
    data[0] = 1; // Initialized flag
    data[1..33].copy_from_slice(owner_info.address().as_ref());

    // Zero out the data field (8 bytes)
    data[33..41].fill(0);

    Ok(())
}

/// VULNERABLE: Update owner without verifying the current owner signed
///
/// This function demonstrates the vulnerability at the low level:
/// 1. It accepts an owner AccountView without checking is_signer()
/// 2. It only validates that the data MATCHES the provided key
/// 3. An attacker can pass any public key without having the signature
///
/// ATTACK SCENARIO:
/// 1. Alice initializes an account, becoming the owner
/// 2. Bob (attacker) reads Alice's public key from the account data
/// 3. Bob calls update_owner, passing Alice's public key in the accounts
/// 4. The data validation passes (stored key == provided key)
/// 5. Bob successfully changes ownership to himself WITHOUT Alice's signature!
fn update_owner(accounts: &[AccountView]) -> ProgramResult {
    let [owner_info, program_account_info, new_owner_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify the account is owned by our program
    if !program_account_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Read current account data
    let mut data = program_account_info.try_borrow_mut()?;

    if data.len() < ProgramAccount::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Check account is initialized
    if data[0] != 1 {
        return Err(ProgramError::UninitializedAccount);
    }

    // Read stored owner key from account data
    let stored_owner = Address::new_from_array(<[u8; 32]>::try_from(&data[1..33]).unwrap());

    // VULNERABILITY: We verify the data matches, but NOT that owner_info signed!
    // This is checking stored_owner == owner_info.address, but NOT checking owner_info.is_signer()
    if stored_owner != *owner_info.address() {
        return Err(ProgramError::InvalidAccountData);
    }

    // MISSING CHECK: Should verify owner_info.is_signer() here!
    // Without this check, anyone can pass the correct key without signing

    // Update owner in account data
    data[1..33].copy_from_slice(new_owner_info.address().as_ref());

    Ok(())
}
