#![no_std]

use pinocchio::{
    entrypoint,
    AccountView,
    Address,
    ProgramResult,
};
use solana_program_error::ProgramError;

pub mod state;
use state::Vault;

// Program ID as a constant byte array
const ID: Address = Address::new_from_array([
    0x3e, 0x2d, 0x1c, 0x0b, 0xfa, 0xe9, 0xd8, 0xc7,
    0xb6, 0xa5, 0x94, 0x83, 0x72, 0x61, 0x50, 0x4f,
    0x3e, 0x2d, 0x1c, 0x0b, 0xfa, 0xe9, 0xd8, 0xc7,
    0xb6, 0xa5, 0x94, 0x83, 0x72, 0x61, 0x50, 0x4f,
]);

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    // Verify program ID
    if program_id != &ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Instruction dispatch based on first byte
    match instruction_data.first() {
        Some(&0) => initialize(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// SECURE: Initialize a vault with discriminator validation
///
/// This function demonstrates how to prevent reinitialization attacks in Pinocchio:
///
/// FIX #1 (Shown here - Recommended): Check discriminator before initialization
/// - Before writing any data, we check if discriminator is already set
/// - If discriminator == DISCRIMINATOR (1), account is already initialized
/// - Only proceed if discriminator is 0 (uninitialized)
/// - This prevents overwriting existing vault data
///
/// FIX #2 (Alternative): Use a custom initialization flag
/// - Add a boolean "is_initialized" field to your state
/// - Check this flag before allowing initialization
/// - Set the flag after successful initialization
///
/// SECURITY GUARANTEES:
/// - Account can only be initialized once
/// - Authority cannot be overwritten after initialization
/// - Existing vaults are protected from takeover
/// - Funds remain secure under original authority
///
/// HOW IT PREVENTS THE ATTACK:
/// 1. Alice creates vault: discriminator set to 1, authority = Alice
/// 2. Bob tries to reinitialize: discriminator check fails (it's 1, not 0)
/// 3. Function returns AccountAlreadyInitialized error
/// 4. Alice's authority is never overwritten, vault stays safe
fn initialize(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, vault_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the vault account is owned by our program
    if !vault_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Get mutable access to vault data
    let mut data = vault_info.try_borrow_mut()?;

    // Check account has enough space
    if data.len() < Vault::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // FIX: Check if account is already initialized by validating discriminator
    // This is the critical security check that prevents reinitialization!
    if data[0] == Vault::DISCRIMINATOR {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // FIX #2 (Alternative): Check custom initialization flag
    // If using a custom flag instead of discriminator:
    // let is_initialized = data[0] != 0;
    // if is_initialized {
    //     return Err(ProgramError::AccountAlreadyInitialized);
    // }

    // Safe to initialize now - we've verified account is uninitialized
    data[0] = Vault::DISCRIMINATOR; // Set discriminator
    data[1..33].copy_from_slice(authority_info.address().as_ref()); // Set authority
    data[33..41].fill(0); // Zero out balance

    Ok(())
}
