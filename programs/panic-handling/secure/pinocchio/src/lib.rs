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
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02,
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

    // SECURE: Bounds-checked access
    let instruction = instruction_data.first()
        .ok_or(ProgramError::InvalidInstructionData)?;

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

/// SECURE: Process with proper error handling
///
/// Instruction data layout:
/// [0] = instruction (1)
/// [1] = divisor (u8)
/// [2] = count of values (u8)
/// [3..] = values as u64 little-endian (8 bytes each)
fn process(accounts: &[AccountView], instruction_data: &[u8]) -> ProgramResult {
    // SECURE: Bounds-checked access with .get()
    let authority_info = accounts.get(0)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let state_info = accounts.get(1)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !state_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // SECURE: Bounds-checked access
    let divisor = *instruction_data.get(1)
        .ok_or(ProgramError::InvalidInstructionData)? as u64;
    let count = *instruction_data.get(2)
        .ok_or(ProgramError::InvalidInstructionData)? as usize;

    let mut total: u64 = 0;
    let mut offset = 3usize;

    for _ in 0..count {
        // SECURE: Bounds-checked slice access
        let end = offset.checked_add(8)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let value_bytes = instruction_data.get(offset..end)
            .ok_or(ProgramError::InvalidInstructionData)?;

        // SECURE: Proper error handling for conversion
        let value_array: [u8; 8] = value_bytes.try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let value = u64::from_le_bytes(value_array);

        // SECURE: Checked addition
        total = total.checked_add(value)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        offset = end;
    }

    // SECURE: Checked division - handles zero divisor
    let average = total.checked_div(divisor)
        .ok_or(ProgramError::InvalidArgument)?;

    let mut data = state_info.try_borrow_mut()?;
    let auth_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    ProcessorState::serialize(&auth_bytes, average, count as u8, &mut data);

    Ok(())
}
