#![no_std]

// Note: solana-program provides the panic handler, so we don't define one here

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
    0xB1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
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
            if instruction_data.len() < 2 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let bump = instruction_data[1];
            withdraw(accounts, bump)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn initialize(accounts: &[AccountView]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let vault = &accounts[0];
    let user = &accounts[1];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Get the user's address bytes
    let user_bytes = user.address().as_ref();

    // Find the canonical bump for this PDA
    let seeds: &[&[u8]] = &[b"vault", user_bytes];
    let (expected_vault, canonical_bump) = find_pda(seeds, ID.as_ref());

    if vault.address() != &expected_vault {
        return Err(ProgramError::InvalidSeeds);
    }

    // Initialize vault state with the canonical bump
    let mut vault_data = vault.try_borrow_mut()?;
    if vault_data.len() < VaultState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut user_array = [0u8; 32];
    user_array.copy_from_slice(user_bytes);
    VaultState::serialize(&user_array, 0, canonical_bump, &mut vault_data);

    Ok(())
}

fn withdraw(accounts: &[AccountView], bump: u8) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let vault = &accounts[0];
    let user = &accounts[1];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Read vault state to get the stored canonical bump
    let vault_data = vault.try_borrow()?;
    let vault_state = VaultState::deserialize(&vault_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // SECURE: Verify the provided bump matches the stored canonical bump
    if bump != vault_state.bump {
        return Err(ProgramError::InvalidSeeds);
    }

    // Verify the PDA with the canonical bump
    let user_bytes = user.address().as_ref();
    let seeds: &[&[u8]] = &[b"vault", user_bytes, &[bump]];
    let derived = create_program_address(seeds, ID.as_ref())?;

    if vault.address() != &derived {
        return Err(ProgramError::InvalidSeeds);
    }

    // SECURE: Only the canonical bump stored during initialization can be used
    // This prevents attackers from using alternate bumps to create non-canonical PDAs

    Ok(())
}

fn find_pda(seeds: &[&[u8]], program_id: &[u8]) -> (Address, u8) {
    use solana_program::pubkey::Pubkey;
    let program_pubkey = Pubkey::new_from_array(program_id.try_into().unwrap());
    let (pubkey, bump) = Pubkey::find_program_address(seeds, &program_pubkey);
    let addr_bytes: [u8; 32] = pubkey.to_bytes();
    (Address::new_from_array(addr_bytes), bump)
}

fn create_program_address(seeds: &[&[u8]], program_id: &[u8]) -> Result<Address, ProgramError> {
    use solana_program::pubkey::Pubkey;
    let program_pubkey = Pubkey::new_from_array(program_id.try_into().unwrap());

    let mut seed_refs: [&[u8]; 16] = [&[]; 16];
    if seeds.len() > 16 {
        return Err(ProgramError::InvalidSeeds);
    }
    for (i, seed) in seeds.iter().enumerate() {
        seed_refs[i] = seed;
    }

    let pubkey = Pubkey::create_program_address(&seed_refs[..seeds.len()], &program_pubkey)
        .map_err(|_| ProgramError::InvalidSeeds)?;
    let addr_bytes: [u8; 32] = pubkey.to_bytes();
    Ok(Address::new_from_array(addr_bytes))
}
