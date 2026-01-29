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

const ID: Pubkey = pinocchio::pubkey!("5ecrPino222222222222222222222222222222222");

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
        Some(&0) => initialize(accounts, instruction_data),
        Some(&1) => update_data(accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a new program account
fn initialize(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let [authority_info, program_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if program_account_info.owner() != &ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Parse data from instruction (skip first byte which is instruction discriminator)
    if instruction_data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let data = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());

    // Write initial data
    let mut account_data = program_account_info.try_borrow_mut_data()?;

    // Check account has enough space
    if account_data.len() < ProgramAccount::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Initialize the account
    account_data[0] = 1; // Initialized flag
    account_data[1..9].copy_from_slice(&data.to_le_bytes());
    account_data[9..41].copy_from_slice(authority_info.key().as_ref());

    msg!("Program account initialized with data: {}", data);
    Ok(())
}

/// SECURE: Update account data with proper owner validation
///
/// This implementation demonstrates the fix for the owner check vulnerability:
/// 1. It validates that the account is owned by this program using is_owned_by()
/// 2. It checks ownership BEFORE reading or trusting any account data
/// 3. An attacker CANNOT pass fake accounts owned by other programs
///
/// SECURITY GUARANTEES:
/// - The owner check ensures the account is controlled by this program
/// - Even if an attacker creates an account with identical structure, it will be rejected
/// - The program will only process data from accounts it actually owns
/// - This prevents malicious data injection through lookalike accounts
///
/// KEY DIFFERENCE FROM ANCHOR:
/// - Anchor's Account<'info, T> type does this automatically via the type system
/// - Pinocchio requires explicit is_owned_by() checks (more control, more responsibility)
/// - Both approaches are equally secure when implemented correctly
///
/// BEST PRACTICES:
/// - ALWAYS check ownership BEFORE reading account data
/// - Use is_owned_by() or direct owner comparison: account.owner() == &ID
/// - Place the check as early as possible in the instruction handler
/// - Don't trust any account data until ownership is verified
fn update_data(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let [authority_info, program_account_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // FIX: Validate that the account is owned by our program BEFORE reading its data!
    // This is the critical check that prevents attackers from passing fake accounts.
    //
    // Two equivalent ways to check ownership:
    // Method 1: Using is_owned_by() helper (more idiomatic)
    if !program_account_info.is_owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    // Method 2: Direct comparison (more explicit)
    // if program_account_info.owner() != &ID {
    //     return Err(ProgramError::InvalidAccountOwner);
    // }

    // Parse new data from instruction (skip first byte which is instruction discriminator)
    if instruction_data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_data = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());

    // Read current account data
    let account_data = program_account_info.try_borrow_data()?;

    if account_data.len() < ProgramAccount::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Check account is initialized
    if account_data[0] != 1 {
        return Err(ProgramError::UninitializedAccount);
    }

    // Read stored data from account
    let stored_data = u64::from_le_bytes(account_data[1..9].try_into().unwrap());
    let stored_authority = Pubkey::from(<[u8; 32]>::try_from(&account_data[9..41]).unwrap());

    // Now it's safe to trust this data - we've verified the account is owned by our program!
    msg!("Current data from account: {}", stored_data);
    msg!("Authority from account: {}", stored_authority);

    // Business logic based on validated data
    if stored_data < 100 {
        msg!("Data validation passed, allowing update");
    }

    // Safe to process - we know this is a legitimate account owned by our program
    msg!("Updating data from {} to {}", stored_data, new_data);

    // In a real scenario, we would write back to the account here
    // It's safe because we verified ownership
    // let mut account_data = program_account_info.try_borrow_mut_data()?;
    // account_data[1..9].copy_from_slice(&new_data.to_le_bytes());

    Ok(())
}
