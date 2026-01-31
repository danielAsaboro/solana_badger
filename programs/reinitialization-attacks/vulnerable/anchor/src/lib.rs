use anchor_lang::prelude::*;

declare_id!("BBQQXUoERwojEV7hSgSCMjsNvmv2nTKkdsMpRHuGXZjT");

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

#[program]
pub mod vulnerable_reinitialization_attacks {
    use super::*;

    /// VULNERABLE: Initialize a vault account without checking if already initialized
    ///
    /// This instruction has a critical vulnerability: it doesn't check if the account
    /// has already been initialized. This allows an attacker to call this function
    /// on an existing vault, overwriting the authority and stealing control.
    ///
    /// ATTACK SCENARIO:
    /// 1. Alice creates a vault with 1000 SOL, setting herself as authority
    /// 2. Bob (attacker) discovers Alice's vault address using PDA derivation
    ///    - PDAs are DETERMINISTIC and publicly derivable!
    ///    - Vault PDA seeds: [b"vault", alice_pubkey]
    ///    - Bob can compute: find_program_address([b"vault", alice_pubkey], program_id)
    ///    - Result: Bob knows Alice's vault address WITHOUT needing Alice's permission
    /// 3. Bob calls unsafe_initialize on Alice's vault account with Bob as authority
    /// 4. The instruction overwrites Alice's authority with Bob's key
    /// 5. Bob now controls Alice's vault and can withdraw all 1000 SOL
    ///
    /// HOW ATTACKERS FIND VICTIM VAULTS:
    /// Since PDAs are deterministic, attackers can:
    /// - Scan the blockchain for all vault accounts owned by this program
    /// - For each vault, derive the expected PDA for different user pubkeys
    /// - Match vault addresses to identify which users own which vaults
    /// - Call unsafe_initialize on any vault they want to steal
    /// This is why initialization guards are CRITICAL!
    pub fn unsafe_initialize(ctx: Context<UnsafeInitialize>) -> Result<()> {
        instructions::unsafe_initialize(ctx)
    }

    /// Deposit SOL into a vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        instructions::deposit(ctx, amount)
    }

    /// Withdraw SOL from a vault (only authority can call)
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        instructions::withdraw(ctx, amount)
    }
}
