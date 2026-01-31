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
use state::{Admin, User};

const ID: Address = Address::new_from_array([
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0x01,
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

    // Instruction dispatch based on first byte
    match instruction_data.first() {
        Some(&0) => initialize_admin(accounts),
        Some(&1) => initialize_user(accounts),
        Some(&2) => admin_operation(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a new Admin account
fn initialize_admin(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, admin_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if !admin_account_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Initialize the account
    let mut data = admin_account_info.try_borrow_mut()?;

    if data.len() < Admin::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Serialize Admin account with discriminator
    let authority_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    Admin::serialize(&authority_bytes, 0, &mut data);

    Ok(())
}

/// Initialize a new User account
fn initialize_user(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, user_account_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    if !user_account_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Initialize the account
    let mut data = user_account_info.try_borrow_mut()?;

    if data.len() < User::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Serialize User account with discriminator
    let authority_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    User::serialize(&authority_bytes, 0, &mut data);

    Ok(())
}

/// VULNERABLE: Admin operation without discriminator validation
///
/// THE VULNERABILITY:
/// This function deserializes account data without checking the discriminator.
/// An attacker can pass a User account where an Admin account is expected!
///
/// ATTACK SCENARIO:
/// 1. Attacker creates a User account with discriminator = 2
/// 2. User account has: [2, authority(32), 1, count(8)] = 42 bytes
/// 3. Attacker calls admin_operation with their User account
/// 4. Program checks program ownership (passes for both Admin and User)
/// 5. Program deserializes without checking discriminator
/// 6. Admin::deserialize reads bytes [1..33] (authority), [33] (privilege), [34..42] (count)
/// 7. Deserialization succeeds because User has identical layout!
/// 8. The "privilege_level" field reads the User's privilege (1) not Admin's (10)
/// 9. But the operation still executes, granting the User admin privileges!
///
/// WHY IT WORKS:
/// - Admin and User have identical memory layouts after the discriminator
/// - We never check if data[0] == Admin::DISCRIMINATOR
/// - The deserialize functions skip the discriminator byte
/// - Authority check passes because the attacker signs with their own key
fn admin_operation(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, admin_account_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the account is owned by our program
    // VULNERABILITY: This check passes for BOTH Admin and User accounts!
    if !admin_account_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // MISSING CHECK: Should verify discriminator here!
    // if data[0] != Admin::DISCRIMINATOR {
    //     return Err(ProgramError::InvalidAccountData);
    // }

    // Deserialize the account data
    let data = admin_account_info.try_borrow()?;

    if data.len() < Admin::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // VULNERABILITY: Deserialize without checking discriminator
    // This will successfully deserialize a User account as Admin!
    let admin = Admin::deserialize(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Verify the authority matches
    let authority_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    if admin.authority != authority_bytes {
        return Err(ProgramError::InvalidAccountData);
    }

    // At this point, "admin" could actually be a User account!
    // The type cosplay attack has succeeded

    // In a real scenario, this would perform privileged operations
    // like transferring funds, updating critical state, etc.

    // Update operation count
    drop(data); // Release borrow
    let mut data = admin_account_info.try_borrow_mut()?;

    // VULNERABILITY: We update without checking discriminator again
    let admin = Admin::deserialize(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    let new_count = admin.operation_count + 1;

    // Re-serialize (this preserves whatever discriminator was there!)
    // If it was a User account, it stays a User account
    data[34..42].copy_from_slice(&new_count.to_le_bytes());

    Ok(())
}
