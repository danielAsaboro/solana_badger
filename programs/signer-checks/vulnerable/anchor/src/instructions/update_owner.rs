use anchor_lang::prelude::*;
use crate::state::ProgramAccount;

/// VULNERABLE: Updates the owner without verifying the current owner signed the transaction
///
/// This function accepts an UncheckedAccount for the owner parameter, which means:
/// 1. It does NOT verify that the owner actually signed the transaction
/// 2. An attacker can pass ANY public key as the owner
/// 3. The has_one constraint only checks that the data MATCHES, not that it SIGNED
///
/// ATTACK SCENARIO:
/// 1. Alice initializes an account, becoming the owner
/// 2. Bob (attacker) reads Alice's public key from on-chain data
/// 3. Bob calls update_owner, passing Alice's public key but NOT getting her signature
/// 4. The has_one check passes (data matches), but Alice never signed!
/// 5. Bob successfully changes ownership to himself, stealing Alice's account
pub fn update_owner(ctx: Context<UpdateOwnership>) -> Result<()> {
    let program_account = &mut ctx.accounts.program_account;
    let old_owner = program_account.owner;

    // VULNERABILITY: This executes without verifying the owner signed the transaction!
    program_account.owner = ctx.accounts.new_owner.key();

    msg!("Owner updated from {} to {}", old_owner, program_account.owner);
    Ok(())
}

#[derive(Accounts)]
pub struct UpdateOwnership<'info> {
    // VULNERABILITY: Using UncheckedAccount instead of Signer!
    // This accepts ANY public key without verifying a signature exists.
    // An attacker can pass the victim's public key here without the victim signing.
    /// CHECK: INTENTIONALLY VULNERABLE - This should be a Signer but isn't!
    pub owner: UncheckedAccount<'info>,

    /// The program account to update
    ///
    /// The has_one constraint checks that program_account.owner == owner.key()
    /// But it does NOT check that owner.is_signer == true!
    /// This is the critical mistake - data validation is not the same as signature validation.
    #[account(
        mut,
        has_one = owner,
        seeds = [b"program-account", owner.key().as_ref()],
        bump
    )]
    pub program_account: Account<'info, ProgramAccount>,

    /// The new owner to set (this is fine to be UncheckedAccount since we're just reading the key)
    /// CHECK: This is the new owner being set, no validation needed
    pub new_owner: UncheckedAccount<'info>,
}
