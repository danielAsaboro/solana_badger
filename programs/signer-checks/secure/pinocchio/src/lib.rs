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

const ID: Pubkey = pinocchio::pubkey!("5ecrPino111111111111111111111111111111111");

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

    // Verify owner is a signer
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

/// SECURE: Update owner with proper signer validation
///
/// This implementation demonstrates the fix for the signer check vulnerability:
/// 1. It validates that the owner AccountInfo signed the transaction
/// 2. It checks both data matching AND signature presence
/// 3. An attacker CANNOT pass someone else's key without their signature
///
/// SECURITY GUARANTEES:
/// - The is_signer() check ensures the current owner authorized this transaction
/// - Attackers cannot steal accounts by just knowing the owner's public key
/// - This provides the same security as Anchor's Signer type, but manually
///
/// KEY DIFFERENCE FROM ANCHOR:
/// - Anchor's Signer type does this automatically via the type system
/// - Pinocchio requires explicit is_signer() checks (more control, more responsibility)
/// - Both approaches are equally secure when implemented correctly
fn update_owner(accounts: &[AccountInfo]) -> ProgramResult {
    let [owner_info, program_account_info, new_owner_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // FIX: Validate that the owner signed the transaction BEFORE doing anything else!
    // This is the critical check that prevents unauthorized ownership transfers.
    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

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

    // Verify the data matches (this prevents using the wrong account)
    if stored_owner != *owner_info.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Now we have dual protection:
    // 1. is_signer() check: Ensures owner authorized this transaction
    // 2. Data matching check: Ensures we're updating the correct account

    let old_owner = stored_owner;

    // Safe to update owner now - we've verified signature + data
    data[1..33].copy_from_slice(new_owner_info.key().as_ref());

    msg!("Owner updated from {} to {}", old_owner, new_owner_info.key());
    Ok(())
}
