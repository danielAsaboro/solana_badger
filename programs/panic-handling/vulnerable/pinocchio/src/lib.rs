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
use state::ProcessorState;

const ID: Address = Address::new_from_array([
    0xD1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01,
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

    // VULNERABLE: Direct array indexing - panics if empty
    let instruction = instruction_data[0];

    match instruction {
        0 => initialize(accounts),
        1 => process(accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn initialize(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, state_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !state_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let mut data = state_info.try_borrow_mut()?;
    if data.len() < ProcessorState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let auth_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    ProcessorState::serialize(&auth_bytes, 0, 0, &mut data);

    Ok(())
}

/// VULNERABLE: Process with multiple panic-inducing patterns
///
/// Instruction data layout:
/// [0] = instruction (1)
/// [1] = divisor (u8)
/// [2] = count of values (u8)
/// [3..] = values as u64 little-endian (8 bytes each)
fn process(accounts: &[AccountView], instruction_data: &[u8]) -> ProgramResult {
    // VULNERABLE: Direct array indexing - panics if fewer than 2 accounts
    let authority_info = &accounts[0];
    let state_info = &accounts[1];

    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !state_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // VULNERABLE: Direct array indexing - panics if instruction_data too short
    let divisor = instruction_data[1] as u64;
    let count = instruction_data[2] as usize;

    let mut total: u64 = 0;
    let mut offset = 3;

    for _ in 0..count {
        // VULNERABLE: Direct slice indexing - panics if out of bounds
        let value_bytes = &instruction_data[offset..offset + 8];
        // VULNERABLE: .unwrap() panics on conversion error
        let value = u64::from_le_bytes(value_bytes.try_into().unwrap());
        total = total + value;
        offset += 8;
    }

    // VULNERABLE: Division by zero panics
    let average = total / divisor;

    let mut data = state_info.try_borrow_mut()?;
    let auth_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    ProcessorState::serialize(&auth_bytes, average, count as u8, &mut data);

    Ok(())
}
