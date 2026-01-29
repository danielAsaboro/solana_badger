use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;
use crate::state::Vault;

/// VULNERABLE: Initialize a vault without checking if already initialized
///
/// This instruction demonstrates the reinitialization vulnerability:
/// 1. It uses UncheckedAccount instead of Account<'info, Vault>
/// 2. It manually serializes data without using the `init` constraint
/// 3. It NEVER checks if the account is already initialized
/// 4. It directly overwrites whatever data exists in the account
///
/// THE VULNERABILITY:
/// By using manual serialization (try_serialize) and writing directly to the
/// account data buffer, this bypasses Anchor's discriminator checks. An attacker
/// can call this function on an ALREADY INITIALIZED vault account, and the
/// authority field will be overwritten with the attacker's key.
///
/// WHY THIS IS DANGEROUS:
/// - No check for existing discriminator
/// - No check for initialization flag
/// - Direct memory write overwrites all existing data
/// - Attacker gains control of victim's vault and funds
pub fn unsafe_initialize(ctx: Context<UnsafeInitialize>) -> Result<()> {
    // VULNERABILITY: We serialize and write directly without any checks!
    // This will overwrite ANY existing data in the account, including
    // the authority field of an already-initialized vault.
    let mut writer: Vec<u8> = vec![];

    // Create new vault data with the signer as authority
    Vault {
        authority: ctx.accounts.authority.key(),
        balance: 0,
    }.try_serialize(&mut writer)?;

    // DANGEROUS: Direct memory copy that overwrites existing data
    // This is the key vulnerability - no checks before writing!
    let mut data = ctx.accounts.vault.try_borrow_mut_data()?;
    anchor_lang::solana_program::program_memory::sol_memcpy(
        &mut data,
        &writer,
        writer.len(),
    );

    msg!("Vault initialized (or RE-initialized!) with authority: {}", ctx.accounts.authority.key());
    Ok(())
}

#[derive(Accounts)]
pub struct UnsafeInitialize<'info> {
    /// The signer who will become the authority
    #[account(mut)]
    pub authority: Signer<'info>,

    /// VULNERABILITY: Using UncheckedAccount instead of proper initialization
    ///
    /// This should be:
    /// #[account(
    ///     init,
    ///     payer = authority,
    ///     space = Vault::LEN
    /// )]
    /// pub vault: Account<'info, Vault>,
    ///
    /// Instead, we use UncheckedAccount which bypasses all safety checks:
    /// - No discriminator validation
    /// - No initialization check
    /// - No automatic space allocation
    /// - Allows reinitialization of existing accounts
    #[account(mut)]
    /// CHECK: UNSAFE - This account is not checked for initialization status
    pub vault: UncheckedAccount<'info>,

    /// System program for potential account creation
    pub system_program: Program<'info, System>,
}
