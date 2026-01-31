#![no_std]

#[cfg(not(feature = "no-entrypoint"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use pinocchio::{entrypoint, AccountView, Address, ProgramResult};
use solana_program_error::ProgramError;

pub mod state;
use state::DataStore;

const ID: Address = Address::new_from_array([
    0xF1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
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
    if program_id != &ID { return Err(ProgramError::IncorrectProgramId); }
    match instruction_data.first() {
        Some(&0) => {
            // initialize: value(u64) at [1..9], label([u8;32]) at [9..41]
            if instruction_data.len() < 41 { return Err(ProgramError::InvalidInstructionData); }
            let value = u64::from_le_bytes(instruction_data[1..9].try_into().map_err(|_| ProgramError::InvalidInstructionData)?);
            let mut label = [0u8; 32];
            label.copy_from_slice(&instruction_data[9..41]);
            initialize(accounts, value, &label)
        }
        Some(&1) => read_data(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn initialize(accounts: &[AccountView], value: u64, label: &[u8; 32]) -> ProgramResult {
    let [authority_info, store_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority_info.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if !store_info.owned_by(&ID) { return Err(ProgramError::InvalidAccountOwner); }

    let mut data = store_info.try_borrow_mut()?;
    if data.len() < DataStore::LEN { return Err(ProgramError::AccountDataTooSmall); }

    DataStore::serialize(authority_info.address().as_ref().try_into().unwrap(), value, label, 1, &mut data);
    Ok(())
}

/// VULNERABLE: Uses unsafe pointer cast to read account data
fn read_data(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, store_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority_info.is_signer() { return Err(ProgramError::MissingRequiredSignature); }

    // VULNERABILITY: No ownership check! Accepts any account
    // VULNERABILITY: Unsafe pointer cast trusts raw bytes
    let data = store_info.try_borrow()?;

    unsafe {
        let ptr = data.as_ptr() as *const DataStoreRaw;
        let _raw = &*ptr;
        // Reading through raw pointer without:
        // 1. Verifying account ownership
        // 2. Checking data length
        // 3. Validating fields
    }

    Ok(())
}

#[repr(C)]
struct DataStoreRaw {
    authority: [u8; 32],
    value: u64,
    label: [u8; 32],
    is_initialized: u8,
}
