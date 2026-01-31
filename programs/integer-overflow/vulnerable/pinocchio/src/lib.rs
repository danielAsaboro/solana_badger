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
    0xC1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
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

    match instruction_data.first() {
        Some(&0) => initialize(accounts),
        Some(&1) => {
            if instruction_data.len() < 9 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let amount = u64::from_le_bytes(
                instruction_data[1..9]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            deposit(accounts, amount)
        }
        Some(&2) => {
            if instruction_data.len() < 9 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let amount = u64::from_le_bytes(
                instruction_data[1..9]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            withdraw(accounts, amount)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn initialize(accounts: &[AccountView]) -> ProgramResult {
    let [vault_info, owner_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !vault_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let mut data = vault_info.try_borrow_mut()?;
    if data.len() < VaultState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let owner_bytes: [u8; 32] = owner_info.address().as_ref().try_into().unwrap();
    VaultState::serialize(&owner_bytes, 0, &mut data);

    Ok(())
}

fn deposit(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let [vault_info, owner_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !vault_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let mut data = vault_info.try_borrow_mut()?;
    let vault = VaultState::deserialize(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    if vault.owner != *owner_info.address() {
        return Err(ProgramError::InvalidAccountData);
    }

    // VULNERABLE: Using plain addition that wraps on overflow
    // With overflow-checks = false, this will silently wrap around
    let new_balance = vault.balance + amount;

    let owner_bytes: [u8; 32] = owner_info.address().as_ref().try_into().unwrap();
    VaultState::serialize(&owner_bytes, new_balance, &mut data);

    Ok(())
}

fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let [vault_info, owner_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !vault_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let mut data = vault_info.try_borrow_mut()?;
    let vault = VaultState::deserialize(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    if vault.owner != *owner_info.address() {
        return Err(ProgramError::InvalidAccountData);
    }

    // VULNERABLE: Using plain subtraction that wraps on underflow
    // With overflow-checks = false, this allows withdrawing more than balance
    let new_balance = vault.balance - amount;

    let owner_bytes: [u8; 32] = owner_info.address().as_ref().try_into().unwrap();
    VaultState::serialize(&owner_bytes, new_balance, &mut data);

    Ok(())
}
