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
    0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x02,
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

    // Verify owner is a signer
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

/// SECURE: Update owner with proper signer validation
///
/// This implementation demonstrates the fix for the signer check vulnerability:
/// 1. It validates that the owner AccountView signed the transaction
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
fn update_owner(accounts: &[AccountView]) -> ProgramResult {
    let [owner_info, program_account_info, new_owner_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // FIX: Validate that the owner signed the transaction BEFORE doing anything else!
    // This is the critical check that prevents unauthorized ownership transfers.
    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

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

    // Verify the data matches (this prevents using the wrong account)
    if stored_owner != *owner_info.address() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Now we have dual protection:
    // 1. is_signer() check: Ensures owner authorized this transaction
    // 2. Data matching check: Ensures we're updating the correct account

    // Safe to update owner now - we've verified signature + data
    data[1..33].copy_from_slice(new_owner_info.address().as_ref());

    Ok(())
}
