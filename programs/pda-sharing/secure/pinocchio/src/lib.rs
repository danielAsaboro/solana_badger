#![no_std]

use pinocchio::{
    entrypoint,
    AccountView,
    Address,
    ProgramResult,
};
use solana_program_error::ProgramError;
use pinocchio_token::instructions::Transfer;

// Helper function to find program address
fn find_pda(seeds: &[&[u8]], program_id: &[u8]) -> (Address, u8) {
    use solana_program::pubkey::Pubkey;
    let program_pubkey = Pubkey::new_from_array(program_id.try_into().unwrap());
    let (pubkey, bump) = Pubkey::find_program_address(seeds, &program_pubkey);
    let addr_bytes: [u8; 32] = pubkey.to_bytes();
    (Address::new_from_array(addr_bytes), bump)
}

pub mod state;
use state::TokenPool;

const ID: Address = Address::new_from_array([
    0x50, 0x44, 0x41, 0x32, 0x50, 0x69, 0x6e, 0x6f,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x02,
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
        Some(&0) => initialize_pool(accounts),
        Some(&1) => {
            // Deposit amount encoded as u64 in bytes [1..9]
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
            // Withdraw amount encoded as u64 in bytes [1..9]
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

/// Initialize a user-specific token pool
///
/// SECURITY FIX: The pool PDA is derived using BOTH owner AND mint:
/// seeds = [b"pool", owner.key(), mint.key()]
///
/// This creates unique PDAs per user:
/// - Alice's pool: [b"pool", ALICE_PUBKEY, USDC_MINT]
/// - Bob's pool: [b"pool", BOB_PUBKEY, USDC_MINT]
/// - Charlie's pool: [b"pool", CHARLIE_PUBKEY, USDC_MINT]
///
/// Each user has isolated authority over only their own tokens!
///
/// Expected accounts:
/// 0. `[writable, signer]` owner
/// 1. `[writable]` pool PDA account
/// 2. `[]` vault token account
/// 3. `[]` mint
/// 4. `[]` system_program
fn initialize_pool(accounts: &[AccountView]) -> ProgramResult {
    let [owner_info, pool_info, vault_info, mint_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify owner is signer
    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify pool is owned by our program
    if !pool_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // SECURITY FIX: Derive PDA from BOTH owner AND mint
    // Seeds: [b"pool", owner.address(), mint.address()]
    // This creates a unique PDA for each user-mint combination
    let (expected_pool, bump) = find_pda(
        &[b"pool", owner_info.address().as_ref(), mint_info.address().as_ref()],
        ID.as_ref(),
    );

    if pool_info.address().as_ref() != expected_pool.as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // Verify vault is owned by pool PDA
    let vault_owner = {
        let data = vault_info.try_borrow()?;
        let owner_bytes: [u8; 32] = data[32..64].try_into().unwrap();
        Address::new_from_array(owner_bytes)
    };

    if vault_owner.as_ref() != expected_pool.as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Initialize pool state
    let mut pool_data = pool_info.try_borrow_mut()?;

    if pool_data.len() < TokenPool::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let owner_bytes: [u8; 32] = owner_info.address().as_ref().try_into().unwrap();
    let mint_bytes: [u8; 32] = mint_info.address().as_ref().try_into().unwrap();
    let vault_bytes: [u8; 32] = vault_info.address().as_ref().try_into().unwrap();
    TokenPool::serialize(
        &owner_bytes,
        &mint_bytes,
        &vault_bytes,
        bump,
        &mut pool_data,
    );

    Ok(())
}

/// Deposit tokens into the user's personal pool
///
/// SECURITY: User deposits into their own isolated vault
/// - Pool PDA is user-specific
/// - Tokens cannot mix with other users' deposits
///
/// Expected accounts:
/// 0. `[signer]` depositor (must match pool owner)
/// 1. `[]` pool PDA
/// 2. `[writable]` user's token account
/// 3. `[writable]` vault token account
/// 4. `[]` token program
fn deposit(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let [depositor_info, pool_info, user_token_info, vault_info, _token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify depositor is signer
    if !depositor_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Deserialize pool
    let pool_data = pool_info.try_borrow()?;
    let pool = TokenPool::deserialize(&pool_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // SECURITY: Verify pool PDA derivation includes owner
    let (expected_pool, _bump) = find_pda(
        &[b"pool", pool.owner.as_ref(), pool.mint.as_ref()],
        ID.as_ref(),
    );

    if pool_info.address().as_ref() != expected_pool.as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // SECURITY: Verify depositor matches pool owner
    if depositor_info.address().as_ref() != pool.owner.as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify vault matches pool
    if vault_info.address().as_ref() != pool.vault.as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Transfer tokens from user to their personal vault
    Transfer {
        from: user_token_info,
        to: vault_info,
        authority: depositor_info,
        amount,
    }
    .invoke()?;

    Ok(())
}

/// SECURE: Withdraw tokens with proper validation
///
/// THE FIX:
/// This instruction prevents PDA sharing attacks through:
///
/// 1. User-Specific PDA: seeds = [b"pool", owner, mint]
///    - Each user has their own unique pool PDA
///    - Bob cannot derive Alice's pool PDA
///
/// 2. Owner Validation: Verify pool.owner matches signer
///    - Only the true owner can sign for withdrawals
///
/// 3. PDA Derivation Validation: Verify seeds include owner
///    - Prevents using someone else's pool
///
/// ATTACK PREVENTION:
/// 1. Alice deposits 100 USDC → vault at [b"pool", ALICE, USDC_MINT]
/// 2. Bob tries to withdraw:
///    - Needs pool at [b"pool", ALICE, USDC_MINT]
///    - But he can only sign as BOB
///    - pool.owner = ALICE != BOB (signer)
/// 3. Bob's transaction rejected - owner validation fails
///
/// Expected accounts:
/// 0. `[signer]` owner (must match pool owner)
/// 1. `[]` pool PDA
/// 2. `[writable]` vault token account
/// 3. `[writable]` destination token account
/// 4. `[]` token program
fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let [owner_info, pool_info, vault_info, destination_info, _token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify owner is signer
    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Deserialize pool
    let pool_data = pool_info.try_borrow()?;
    let pool = TokenPool::deserialize(&pool_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // SECURITY FIX 1: Verify pool PDA derivation includes owner
    let (expected_pool, bump) = find_pda(
        &[b"pool", pool.owner.as_ref(), pool.mint.as_ref()],
        ID.as_ref(),
    );

    if pool_info.address().as_ref() != expected_pool.as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // SECURITY FIX 2: Verify signer matches pool owner
    if owner_info.address().as_ref() != pool.owner.as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify vault matches pool
    if vault_info.address().as_ref() != pool.vault.as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // SECURITY: User-specific PDA seeds ensure isolated authority
    let bump_seed = [bump];
    let seeds = [
        pinocchio::cpi::Seed::from(&b"pool"[..]),
        pinocchio::cpi::Seed::from(pool.owner.as_ref()),
        pinocchio::cpi::Seed::from(pool.mint.as_ref()),
        pinocchio::cpi::Seed::from(&bump_seed[..]),
    ];
    let signer = pinocchio::cpi::Signer::from(&seeds[..]);

    Transfer {
        from: vault_info,
        to: destination_info,
        authority: pool_info,
        amount,
    }
    .invoke_signed(&[signer])?;

    Ok(())
}
