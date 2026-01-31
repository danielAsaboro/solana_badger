#![no_std]

#[cfg(not(feature = "no-entrypoint"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

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
    0xd1, 0x6c, 0x7e, 0x1f, 0x8a, 0xb3, 0x4c, 0x5d,
    0xe9, 0x2a, 0x1b, 0xf6, 0xc3, 0x7d, 0x4e, 0x8f,
    0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa, 0x0b, 0x1c,
    0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94,
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
        Some(&0) => unsafe_initialize(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// VULNERABLE: Initialize a vault without checking if already initialized
///
/// This function demonstrates the reinitialization vulnerability at the Pinocchio level:
/// 1. It has a discriminator field in the account layout
/// 2. But it NEVER checks if the discriminator is already set
/// 3. It directly overwrites all account data, including existing authority
/// 4. An attacker can call this on an existing vault to steal ownership
///
/// THE VULNERABILITY:
/// Even though we have a discriminator in our layout (byte 0), this function
/// never validates it before writing. This means:
/// - Alice creates a vault with herself as authority
/// - Bob calls unsafe_initialize on Alice's vault account
/// - Bob's key overwrites Alice's authority in the account data
/// - Bob gains control over Alice's vault
///
/// ATTACK SCENARIO:
/// 1. Alice initializes vault: [DISC=1][alice_key][balance=1000_SOL]
/// 2. Bob (attacker) discovers Alice's vault address via PDA derivation
///    - PDAs are DETERMINISTIC and publicly derivable!
///    - Vault PDA: derived from [b"vault", alice_pubkey]
///    - Bob computes: find_program_address([b"vault", alice_pubkey], program_id)
///    - Result: Bob knows Alice's vault address WITHOUT Alice's permission
/// 3. Bob calls unsafe_initialize on Alice's vault account with Bob as authority
/// 4. Account becomes: [DISC=1][bob_key][balance=0] - authority overwritten!
/// 5. Bob gains control, Alice loses her 1000 SOL!
///
/// HOW ATTACKERS FIND VICTIM VAULTS:
/// PDAs are deterministic, so attackers can:
/// - Scan blockchain for vault accounts owned by this program
/// - For each vault, try deriving PDAs with common seed patterns
/// - Match addresses to identify vault owners
/// - Call unsafe_initialize on any vault to steal it
/// - This makes the attack PRACTICAL, not just theoretical!
fn unsafe_initialize(accounts: &[AccountView]) -> ProgramResult {
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

    // VULNERABILITY: No check if discriminator is already set!
    // We should check: if data[0] == Vault::DISCRIMINATOR { return error; }
    // Without this check, we allow reinitialization of existing vaults.

    // DANGEROUS: Directly overwrite all data without validation
    data[0] = Vault::DISCRIMINATOR; // Set discriminator
    data[1..33].copy_from_slice(authority_info.address().as_ref()); // Set authority
    data[33..41].fill(0); // Zero out balance

    Ok(())
}
