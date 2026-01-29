# Reinitialization Attacks

This directory contains implementations demonstrating reinitialization attack vulnerabilities and their fixes in Solana programs.

## Overview

Reinitialization attacks exploit programs that fail to check whether an account has already been initialized, allowing attackers to overwrite existing data and hijack control of valuable accounts. This vulnerability is particularly devastating in protocols like escrows, vaults, or any system where account ownership determines control over valuable assets.

## The Vulnerability

The core issue occurs when initialization functions:
1. Don't check if an account has already been initialized
2. Directly overwrite account data without validation
3. Missing discriminator or initialization flag checks
4. Allow attackers to reset existing accounts to attacker-controlled states

### Attack Scenario

1. **Victim initializes a vault**: Alice creates a vault account, depositing 1000 SOL with herself as authority
2. **Attacker discovers the vault**: Bob identifies Alice's initialized vault account
3. **Attacker calls reinitialization**: Bob calls the initialization function on Alice's existing vault
4. **Authority overwritten**: Alice's authority is replaced with Bob's public key
5. **Funds stolen**: Bob can now withdraw all of Alice's funds

## Directory Structure

```
reinitialization-attacks/
├── vulnerable/
│   ├── anchor/          # Vulnerable Anchor implementation
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── state.rs
│   │   │   └── instructions/
│   │   │       ├── mod.rs
│   │   │       ├── unsafe_initialize.rs
│   │   │       ├── deposit.rs
│   │   │       └── withdraw.rs
│   │   └── Cargo.toml
│   └── pinocchio/       # Vulnerable Pinocchio implementation
│       ├── src/
│       │   ├── lib.rs
│       │   └── state.rs
│       └── Cargo.toml
├── secure/
│   ├── anchor/          # Secure Anchor implementation
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── state.rs
│   │   │   └── instructions/
│   │   │       ├── mod.rs
│   │   │       ├── initialize.rs
│   │   │       ├── deposit.rs
│   │   │       └── withdraw.rs
│   │   └── Cargo.toml
│   └── pinocchio/       # Secure Pinocchio implementation
│       ├── src/
│       │   ├── lib.rs
│       │   └── state.rs
│       └── Cargo.toml
└── README.md
```

## Vulnerable Implementation

### Anchor (vulnerable/anchor/)

The vulnerable Anchor implementation demonstrates the attack by:
- Using `UncheckedAccount` instead of proper Account initialization
- Manually serializing data without using the `init` constraint
- Never checking if the account discriminator is already set
- Directly overwriting all account data with `sol_memcpy`

**Key vulnerability in `unsafe_initialize.rs`:**
```rust
// VULNERABLE: No initialization check!
let mut writer: Vec<u8> = vec![];
Vault {
    authority: ctx.accounts.authority.key(),
    balance: 0,
}.try_serialize(&mut writer)?;

// Direct memory overwrite - no validation!
let mut data = ctx.accounts.vault.try_borrow_mut_data()?;
sol_memcpy(&mut data, &writer, writer.len());
```

### Pinocchio (vulnerable/pinocchio/)

The vulnerable Pinocchio implementation shows:
- Discriminator field exists in the layout but is never checked
- Direct data writing without validation
- No check that discriminator == 0 before initialization
- Allows complete account data overwrite

**Key vulnerability in `lib.rs`:**
```rust
fn unsafe_initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let mut data = vault_info.try_borrow_mut_data()?;

    // MISSING: No check if data[0] == DISCRIMINATOR
    // Directly overwrites all data including existing authority
    data[0] = Vault::DISCRIMINATOR;
    data[1..33].copy_from_slice(authority_info.key().as_ref());
    data[33..41].fill(0);

    Ok(())
}
```

## Secure Implementation

### Anchor (secure/anchor/)

The secure Anchor implementation uses the `init` constraint which:
- Automatically checks discriminator is zero (uninitialized)
- Creates the account with correct size
- Sets discriminator to prevent future reinitialization
- Handles rent payment automatically

**Fix in `initialize.rs`:**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    // FIX: Use init constraint for automatic protection
    #[account(
        init,
        payer = authority,
        space = Vault::LEN
    )]
    pub vault: Account<'info, Vault>,

    pub system_program: Program<'info, System>,
}
```

Alternative fix - manual discriminator check:
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Manual check if discriminator is zero
    let discriminator = &ctx.accounts.vault.to_account_info().data.borrow()[..8];
    if discriminator != [0u8; 8] {
        return Err(ProgramError::AccountAlreadyInitialized.into());
    }

    // Safe to initialize...
    Ok(())
}
```

### Pinocchio (secure/pinocchio/)

The secure Pinocchio implementation validates the discriminator:
- Checks if discriminator is already set before initialization
- Returns error if account is already initialized
- Prevents overwriting of existing account data

**Fix in `lib.rs`:**
```rust
fn initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let mut data = vault_info.try_borrow_mut_data()?;

    // FIX: Check if already initialized
    if data[0] == Vault::DISCRIMINATOR {
        msg!("Error: Account already initialized");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // Safe to initialize now
    data[0] = Vault::DISCRIMINATOR;
    data[1..33].copy_from_slice(authority_info.key().as_ref());
    data[33..41].fill(0);

    Ok(())
}
```

## Building the Programs

### Anchor Programs

```bash
# Build vulnerable Anchor program
cd vulnerable/anchor
anchor build

# Build secure Anchor program
cd ../../secure/anchor
anchor build
```

### Pinocchio Programs

```bash
# Build vulnerable Pinocchio program
cd vulnerable/pinocchio
cargo build-sbf

# Build secure Pinocchio program
cd ../../secure/pinocchio
cargo build-sbf
```

## Testing the Vulnerability

To demonstrate the reinitialization attack:

1. **Initialize a vault** with Alice as authority
2. **Deposit funds** into the vault (e.g., 1000 SOL)
3. **Attempt reinitialization** with Bob as authority
   - Vulnerable version: Succeeds, Bob becomes new authority
   - Secure version: Fails with `AccountAlreadyInitialized` error
4. **Try to withdraw** as Bob
   - Vulnerable version: Bob can steal all funds
   - Secure version: Bob cannot withdraw (not the authority)

## Key Takeaways

### For Anchor Developers:
- **Always use the `init` constraint** for account initialization
- Never use `UncheckedAccount` with manual serialization for new accounts
- Avoid `init_if_needed` unless you understand the risks
- If manual initialization is required, check discriminator is zero

### For Pinocchio Developers:
- **Always check discriminator** before allowing initialization
- Validate that discriminator == 0 before writing new data
- Consider using a custom initialization flag as an alternative
- Never skip initialization validation, even if it seems redundant

### General Security Principles:
1. **Discriminators are critical** - they prevent reinitialization
2. **One-time initialization** - accounts should only be initialized once
3. **Validate before write** - always check state before modifying data
4. **Authority protection** - ownership/authority fields must be immutable after init

## Related Vulnerabilities

- **Missing Signer Checks**: Related to authority validation
- **Owner Checks**: Verifying program ownership of accounts
- **Type Cosplay**: Account type confusion through discriminator manipulation

## References

- [Solana Cookbook - Account Data Validation](https://solanacookbook.com/guides/account-data-matching.html)
- [Anchor Book - Account Constraints](https://www.anchor-lang.com/docs/account-constraints)
- [Neodyme Blog - Reinitialization Attacks](https://blog.neodyme.io/posts/solana_common_pitfalls)
