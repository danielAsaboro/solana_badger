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

    // SECURE: Using checked_add to prevent overflow
    let new_balance = vault.balance
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

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

    // SECURE: Validate amount is greater than 0
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
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

    // SECURE: Using checked_sub to prevent underflow
    let new_balance = vault.balance
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;

    let owner_bytes: [u8; 32] = owner_info.address().as_ref().try_into().unwrap();
    VaultState::serialize(&owner_bytes, new_balance, &mut data);

    Ok(())
}
