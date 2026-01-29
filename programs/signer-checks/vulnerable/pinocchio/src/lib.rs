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
use state::ProgramAccount;

const ID: Pubkey = pinocchio::pubkey!("VuLnPino111111111111111111111111111111111");

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
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
fn initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let [owner_info, program_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify owner is a signer (this is correct)
    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if program_account_info.owner() != &ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Write initial data
    let mut data = program_account_info.try_borrow_mut_data()?;

    // Check account has enough space
    if data.len() < ProgramAccount::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Initialize the account
    data[0] = 1; // Initialized flag
    data[1..33].copy_from_slice(owner_info.key().as_ref());

    // Zero out the data field (8 bytes)
    data[33..41].fill(0);

    msg!("Program account initialized with owner: {}", owner_info.key());
    Ok(())
}

/// VULNERABLE: Update owner without verifying the current owner signed
///
/// This function demonstrates the vulnerability at the low level:
/// 1. It accepts an owner AccountInfo without checking is_signer()
/// 2. It only validates that the data MATCHES the provided key
/// 3. An attacker can pass any public key without having the signature
///
/// ATTACK SCENARIO:
/// 1. Alice initializes an account, becoming the owner
/// 2. Bob (attacker) reads Alice's public key from the account data
/// 3. Bob calls update_owner, passing Alice's public key in the accounts
/// 4. The data validation passes (stored key == provided key)
/// 5. Bob successfully changes ownership to himself WITHOUT Alice's signature!
fn update_owner(accounts: &[AccountInfo]) -> ProgramResult {
    let [owner_info, program_account_info, new_owner_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify the account is owned by our program
    if program_account_info.owner() != &ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Read current account data
    let mut data = program_account_info.try_borrow_mut_data()?;

    if data.len() < ProgramAccount::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Check account is initialized
    if data[0] != 1 {
        return Err(ProgramError::UninitializedAccount);
    }

    // Read stored owner key from account data
    let stored_owner = Pubkey::from(<[u8; 32]>::try_from(&data[1..33]).unwrap());

    // VULNERABILITY: We verify the data matches, but NOT that owner_info signed!
    // This is checking stored_owner == owner_info.key, but NOT checking owner_info.is_signer()
    if stored_owner != *owner_info.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // MISSING CHECK: Should verify owner_info.is_signer() here!
    // Without this check, anyone can pass the correct key without signing

    let old_owner = stored_owner;

    // Update owner in account data
    data[1..33].copy_from_slice(new_owner_info.key().as_ref());

    msg!("Owner updated from {} to {}", old_owner, new_owner_info.key());
    Ok(())
}
