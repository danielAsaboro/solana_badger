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
    0x50, 0x44, 0x41, 0x31, 0x50, 0x69, 0x6e, 0x6f,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x01,
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

/// Initialize a token pool for a specific mint
///
/// VULNERABILITY: The pool PDA is derived using ONLY the mint address.
/// This means all users depositing the same token share the SAME pool PDA!
///
/// Expected accounts:
/// 0. `[writable, signer]` initializer
/// 1. `[writable]` pool PDA account
/// 2. `[]` vault token account
/// 3. `[]` mint
/// 4. `[]` system_program
fn initialize_pool(accounts: &[AccountView]) -> ProgramResult {
    let [initializer_info, pool_info, vault_info, mint_info, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify initializer is signer
    if !initializer_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify pool is owned by our program
    if !pool_info.owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // VULNERABILITY: Derive PDA from mint only
    // Seeds: [b"pool", mint.address()]
    // This creates a SHARED PDA for all users of this mint!
    let (expected_pool, bump) = find_pda(
        &[b"pool", mint_info.address().as_ref()],
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

    let mint_bytes: [u8; 32] = mint_info.address().as_ref().try_into().unwrap();
    let vault_bytes: [u8; 32] = vault_info.address().as_ref().try_into().unwrap();
    TokenPool::serialize(
        &mint_bytes,
        &vault_bytes,
        bump,
        &mut pool_data,
    );

    Ok(())
}

/// Deposit tokens into the pool
///
/// This instruction appears safe but contributes to the vulnerability:
/// - User deposits into the shared vault
/// - Tokens mix with other users' deposits
/// - The shared PDA can be exploited to withdraw any user's tokens
///
/// Expected accounts:
/// 0. `[signer]` depositor
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

    // Verify pool PDA derivation (mint-only)
    let (expected_pool, _bump) = find_pda(
        &[b"pool", pool.mint.as_ref()],
        ID.as_ref(),
    );

    if pool_info.address().as_ref() != expected_pool.as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // Verify vault matches pool
    if vault_info.address().as_ref() != pool.vault.as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Transfer tokens from user to vault
    Transfer {
        from: user_token_info,
        to: vault_info,
        authority: depositor_info,
        amount,
    }
    .invoke()?;

    Ok(())
}

/// VULNERABLE: Withdraw tokens from pool
///
/// THE VULNERABILITY:
/// This allows ANYONE to withdraw tokens from the shared vault to ANY destination:
///
/// 1. Pool PDA derived from mint only: [b"pool", mint]
/// 2. All users share this same PDA
/// 3. PDA has signing authority over the vault
/// 4. No validation that withdrawer owns the tokens
/// 5. No per-user balance tracking
///
/// ATTACK SCENARIO:
/// 1. Alice deposits 100 USDC
/// 2. Bob derives same pool PDA: [b"pool", USDC_MINT]
/// 3. Bob calls withdraw with his destination
/// 4. Pool PDA signs the transfer (it has authority)
/// 5. Bob steals Alice's 100 USDC
///
/// Expected accounts:
/// 0. `[signer]` withdrawer (not validated!)
/// 1. `[]` pool PDA
/// 2. `[writable]` vault token account
/// 3. `[writable]` destination token account
/// 4. `[]` token program
fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let [_withdrawer_info, pool_info, vault_info, destination_info, _token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // VULNERABILITY: No validation that withdrawer owns these tokens!
    // Anyone can call this with any destination

    // Deserialize pool
    let pool_data = pool_info.try_borrow()?;
    let pool = TokenPool::deserialize(&pool_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Verify pool PDA derivation (mint-only)
    let (expected_pool, bump) = find_pda(
        &[b"pool", pool.mint.as_ref()],
        ID.as_ref(),
    );

    if pool_info.address().as_ref() != expected_pool.as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // Verify vault matches pool
    if vault_info.address().as_ref() != pool.vault.as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // VULNERABILITY: The shared pool PDA signs for ANY withdrawal
    // No check that the withdrawer actually deposited these tokens
    let bump_seed = [bump];
    let seeds = [
        pinocchio::cpi::Seed::from(&b"pool"[..]),
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
