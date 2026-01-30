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
    0xf1, 0x68, 0x91, 0x4a, 0x2b, 0xdc, 0x3f, 0x5e,
    0x70, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07,
    0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
    0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x01,
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
        Some(&0) => initialize(accounts, instruction_data),
        Some(&1) => update_data(accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a new program account
fn initialize(accounts: &[AccountView], instruction_data: &[u8]) -> ProgramResult {
    let [authority_info, program_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if !program_account_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Parse data from instruction (skip first byte which is instruction discriminator)
    if instruction_data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let data = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());

    // Write initial data
    let mut account_data = program_account_info.try_borrow_mut()?;

    // Check account has enough space
    if account_data.len() < ProgramAccount::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Initialize the account
    account_data[0] = 1; // Initialized flag
    account_data[1..9].copy_from_slice(&data.to_le_bytes());
    account_data[9..41].copy_from_slice(authority_info.address().as_ref());

    Ok(())
}

/// VULNERABLE: Update account data without verifying program ownership
///
/// This function demonstrates the vulnerability at the low level:
/// 1. It accepts a program_account AccountInfo without checking owner
/// 2. It reads and trusts data from the account
/// 3. An attacker can pass ANY account with matching structure
/// 4. The attacker's fake account can contain malicious data
///
/// ATTACK SCENARIO:
/// 1. Alice initializes a legitimate account owned by this program with data = 100
/// 2. Bob (attacker) creates his own account (owned by ANY program he controls)
/// 3. Bob structures his fake account identically: initialized flag + data + authority
/// 4. Bob sets data = 200 in his fake account
/// 5. Bob calls update_data, passing his fake account
/// 6. The program reads data = 200 from Bob's fake account
/// 7. The instruction logic executes based on MALICIOUS data from Bob's account
/// 8. Bob has successfully manipulated program behavior without owning a real account!
///
/// WHY THIS IS DANGEROUS:
/// - The program trusts account data without verifying WHO owns the account
/// - Attackers can craft "lookalike" accounts with malicious values
/// - Business logic based on the data field can be completely subverted
/// - Without owner checks, there's no guarantee the account is legitimate
fn update_data(accounts: &[AccountView], instruction_data: &[u8]) -> ProgramResult {
    let [authority_info, program_account_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer (this is correct)
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // VULNERABILITY: NOT checking if program_account_info is owned by our program!
    // This is the critical missing check. We should verify:
    // if !program_account_info.owned_by(&ID) {
    //     return Err(ProgramError::InvalidAccountOwner);
    // }
    //
    // Without this check, an attacker can pass ANY account from ANY program,
    // and we'll trust its data as if it were our own!

    // Parse new data from instruction (skip first byte which is instruction discriminator)
    if instruction_data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_data = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());

    // Read current account data
    let account_data = program_account_info.try_borrow()?;

    if account_data.len() < ProgramAccount::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Check account is initialized
    if account_data[0] != 1 {
        return Err(ProgramError::UninitializedAccount);
    }

    // Read stored data from account
    let stored_data = u64::from_le_bytes(account_data[1..9].try_into().unwrap());
    let stored_authority = Address::new_from_array(<[u8; 32]>::try_from(&account_data[9..41]).unwrap());

    // DANGER: We're reading and trusting this data, but we NEVER verified
    // that the account is owned by our program! An attacker controls these values!

    // Even if we validate the data here, it doesn't matter!
    // An attacker can set stored_data to ANY value they want in their fake account.

    // Business logic based on the unverified data
    // The attacker has full control over the execution path!

    // In a real scenario, we might write back to the account or perform other actions
    // But the damage is already done - we trusted unverified data!

    Ok(())
}
