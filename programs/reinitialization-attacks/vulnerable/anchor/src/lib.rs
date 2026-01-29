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
    /// 2. Bob (attacker) calls unsafe_initialize on Alice's vault account
    /// 3. The instruction overwrites Alice's authority with Bob's key
    /// 4. Bob now controls Alice's vault and can withdraw all funds
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
