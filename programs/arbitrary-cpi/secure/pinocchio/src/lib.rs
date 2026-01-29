#![no_std]

use core::panic::PanicInfo;
use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub mod state;
use state::Vault;

// Note: Using fixed program IDs for demonstration
// In production, these would be dynamically assigned
const ID: [u8; 32] = [
    0xc9, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
];

// SPL Token program ID: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if program_id.as_ref() != &ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Simple instruction dispatch based on first byte
    // 0 = Initialize
    // 1 = Transfer tokens
    match instruction_data.first() {
        Some(&0) => initialize(accounts, instruction_data),
        Some(&1) => transfer_tokens(accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a vault with authority
///
/// Accounts expected:
/// 0. `[signer]` Authority
/// 1. `[writable]` Vault PDA
/// 2. `[]` Vault token account
/// 3. `[]` System program
fn initialize(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let [authority_info, vault_info, vault_token_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the vault account is owned by our program
    if vault_info.owner().as_ref() != &ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Get bump from instruction data (byte index 1)
    let bump = *instruction_data.get(1).ok_or(ProgramError::InvalidInstructionData)?;

    // Initialize vault data
    let mut vault_data = unsafe { vault_info.borrow_mut_data_unchecked() };

    if vault_data.len() < Vault::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let vault = Vault {
        authority: *authority_info.key(),
        token_account: *vault_token_account_info.key(),
        bump,
    };

    vault.to_bytes(&mut vault_data).map_err(|_| ProgramError::AccountDataTooSmall)?;

    msg!("Vault initialized successfully");

    Ok(())
}

/// SECURE: Transfer tokens with proper program validation
///
/// This instruction fixes the Arbitrary CPI vulnerability by:
/// 1. Validating the token_program account matches SPL_TOKEN_PROGRAM_ID
/// 2. Checking the program ID BEFORE performing the CPI
/// 3. Rejecting any attempts to call malicious programs
///
/// SECURITY IMPROVEMENTS:
/// - Explicit program ID validation: token_program.key() == SPL_TOKEN_PROGRAM_ID
/// - Attacker cannot substitute a malicious program
/// - Transaction fails before CPI if wrong program is provided
/// - The transfer will always use the real SPL Token program logic
///
/// COMPARISON WITH VULNERABLE VERSION:
/// Vulnerable:  No validation, accepts any program
/// Secure:      Validates token_program.key() == SPL_TOKEN_PROGRAM_ID
///
/// This single check provides complete protection against arbitrary CPI attacks
///
/// Accounts expected:
/// 0. `[signer]` Authority
/// 1. `[]` Vault PDA
/// 2. `[writable]` Source token account
/// 3. `[writable]` Destination token account
/// 4. `[]` Token program (VALIDATED!)
fn transfer_tokens(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let [authority_info, vault_info, source_info, destination_info, token_program_info] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the vault account is owned by our program
    if vault_info.owner().as_ref() != &ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Load vault data
    let vault_data = unsafe { vault_info.borrow_data_unchecked() };
    let vault = Vault::from_bytes(&vault_data).map_err(|_| ProgramError::InvalidAccountData)?;

    // Verify authority matches vault authority
    if authority_info.key() != &vault.authority {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify source is vault's token account
    if source_info.key() != &vault.token_account {
        return Err(ProgramError::InvalidAccountData);
    }

    // Get amount from instruction data (bytes 1-9, u64 little-endian)
    let amount_bytes: [u8; 8] = instruction_data
        .get(1..9)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let amount = u64::from_le_bytes(amount_bytes);

    // FIX: Validate the token program ID BEFORE making the CPI
    // This is the critical security check that prevents arbitrary CPI attacks
    if token_program_info.key().as_ref() != &SPL_TOKEN_PROGRAM_ID {
        msg!("Error: Invalid token program provided!");
        return Err(ProgramError::IncorrectProgramId);
    }

    msg!("Token program validated successfully");

    // Build transfer instruction
    // SPL Token transfer instruction format:
    // - Instruction discriminator: 3 (transfer)
    // - Amount: u64 (8 bytes)
    let mut instruction_data_buf = [0u8; 9];
    instruction_data_buf[0] = 3; // Transfer instruction
    instruction_data_buf[1..9].copy_from_slice(&amount.to_le_bytes());

    // Perform CPI to validated token program
    // Safe because we verified token_program_info.key() == SPL_TOKEN_PROGRAM_ID
    unsafe {
        pinocchio::program::invoke(
            &pinocchio::instruction::Instruction {
                program_id: token_program_info.key(),
                accounts: &[
                    pinocchio::instruction::AccountMeta::writable(source_info.key()),
                    pinocchio::instruction::AccountMeta::writable(destination_info.key()),
                    pinocchio::instruction::AccountMeta::readonly_signer(authority_info.key()),
                ],
                data: &instruction_data_buf,
            },
            &[
                source_info,
                destination_info,
                authority_info,
                token_program_info,
            ],
        )?;
    }

    msg!("Transfer completed successfully");
    Ok(())
}
