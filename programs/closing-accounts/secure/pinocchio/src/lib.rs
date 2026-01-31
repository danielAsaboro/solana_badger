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
use state::VaultState;

const ID: Address = Address::new_from_array([
    0xE1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
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

    match instruction_data.first() {
        Some(&0) => {
            if instruction_data.len() < 9 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let deposit = u64::from_le_bytes(
                instruction_data[1..9]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            initialize(accounts, deposit)
        }
        Some(&1) => force_close(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn initialize(accounts: &[AccountView], deposit: u64) -> ProgramResult {
    let [authority_info, vault_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !vault_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let mut data = vault_info.try_borrow_mut()?;
    if data.len() < VaultState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let auth_bytes: [u8; 32] = authority_info.address().as_ref().try_into().unwrap();
    VaultState::serialize(&auth_bytes, deposit, 1, &mut data);

    Ok(())
}

/// SECURE: Zeros account data before draining lamports.
/// This prevents the account from being "revived" within the same
/// transaction because the data will be all zeros.
fn force_close(accounts: &[AccountView]) -> ProgramResult {
    let [authority_info, vault_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !vault_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Verify authority
    {
        let data = vault_info.try_borrow()?;
        let vault = VaultState::deserialize(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?;

        if vault.authority != *authority_info.address() {
            return Err(ProgramError::InvalidAccountData);
        }
    }

    // SECURE: Zero out account data first
    {
        let mut data = vault_info.try_borrow_mut()?;
        data.fill(0);
    }

    // Then drain lamports
    let vault_lamports = vault_info.lamports();
    vault_info.set_lamports(0);
    authority_info.set_lamports(authority_info.lamports() + vault_lamports);

    Ok(())
}
