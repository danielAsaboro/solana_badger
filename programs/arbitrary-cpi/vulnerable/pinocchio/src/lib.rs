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

// Note: Using fixed program IDs for demonstration
// In production, these would be dynamically assigned
const ID: Address = Address::new_from_array([
    0xc9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
]);

// SPL Token program ID: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
const SPL_TOKEN_PROGRAM_ID: Address = Address::new_from_array([
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
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
fn initialize(accounts: &[AccountView], instruction_data: &[u8]) -> ProgramResult {
    let [authority_info, vault_info, vault_token_account_info, _system_program] = accounts else {
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

    // Get bump from instruction data (byte index 1)
    let bump = *instruction_data.get(1).ok_or(ProgramError::InvalidInstructionData)?;

    // Initialize vault data
    let mut vault_data = vault_info.try_borrow_mut()?;

    if vault_data.len() < Vault::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let vault = Vault {
        authority: authority_info.address().clone(),
        token_account: vault_token_account_info.address().clone(),
        bump,
    };

    vault.to_bytes(&mut vault_data).map_err(|_| ProgramError::AccountDataTooSmall)?;

    Ok(())
}

/// VULNERABLE: Transfer tokens using arbitrary program without validation
///
/// This instruction demonstrates the Arbitrary CPI vulnerability by:
/// 1. Accepting any program account without validating its program ID
/// 2. Performing CPI to that program without checking if it's the real Token program
/// 3. Trusting the caller to provide the legitimate Token program
///
/// ATTACK SCENARIO:
/// 1. Attacker creates a malicious "fake-token" program with same instruction format
/// 2. Fake program's transfer instruction does the OPPOSITE: transfers from destination to source
/// 3. Attacker calls this instruction but passes their fake program as token_program
/// 4. The vault authority signs, thinking tokens will be sent to destination
/// 5. Fake program reverses the transfer, draining the destination account instead!
///
/// WHY IT WORKS:
/// - The authority signature is properly checked
/// - The vault PDA is properly validated
/// - BUT: The token_program account is never validated against SPL_TOKEN_PROGRAM_ID
/// - The CPI just calls whatever program is provided
/// - An attacker controls which program executes the sensitive operation
///
/// Accounts expected:
/// 0. `[signer]` Authority
/// 1. `[]` Vault PDA
/// 2. `[writable]` Source token account
/// 3. `[writable]` Destination token account
/// 4. `[]` Token program (UNCHECKED - THE VULNERABILITY!)
fn transfer_tokens(accounts: &[AccountView], instruction_data: &[u8]) -> ProgramResult {
    let [authority_info, vault_info, source_info, destination_info, token_program_info] = accounts
    else {
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

    // Load vault data
    let vault_data = vault_info.try_borrow()?;
    let vault = Vault::from_bytes(&vault_data).map_err(|_| ProgramError::InvalidAccountData)?;

    // Verify authority matches vault authority
    if authority_info.address() != &vault.authority {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify source is vault's token account
    if source_info.address() != &vault.token_account {
        return Err(ProgramError::InvalidAccountData);
    }

    // Get amount from instruction data (bytes 1-9, u64 little-endian)
    let amount_bytes: [u8; 8] = instruction_data
        .get(1..9)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let amount = u64::from_le_bytes(amount_bytes);

    // VULNERABILITY: No validation that token_program_info is the real SPL Token program!
    // This should check: if token_program_info.address() != &SPL_TOKEN_PROGRAM_ID { ... }
    // Without this check, an attacker can pass ANY program that implements the transfer interface

    // Use pinocchio_token Transfer - but vulnerable because we don't validate the program passed
    use pinocchio_token::instructions::Transfer;
    Transfer {
        from: source_info,
        to: destination_info,
        authority: authority_info,
        amount,
    }
    .invoke()?;

    Ok(())
}
