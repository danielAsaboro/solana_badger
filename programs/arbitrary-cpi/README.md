# Arbitrary CPI Vulnerability

This directory contains example programs demonstrating the **Arbitrary CPI (Cross-Program Invocation)** vulnerability and its secure implementations in both Anchor and Pinocchio frameworks.

## Overview

Arbitrary CPI attacks occur when programs blindly call whatever program is passed in as a parameter, rather than validating they're invoking the intended program. This transforms your secure program into a launcher for malicious code, allowing attackers to hijack your program's authority and execute unauthorized operations.

## The Vulnerability

The danger lies in Solana's flexible account model. Since callers can pass any program ID into your instruction's account list, failing to validate program addresses means your program becomes a proxy for arbitrary code execution.

### Attack Scenario

1. **Legitimate Program Setup**: A vault program performs token transfers via CPI to the SPL Token program
2. **Attacker Creates Fake Program**: Attacker deploys a malicious program with the same interface as SPL Token
3. **Fake Program Logic**: Instead of transferring from source to destination, it reverses the transfer or drains to attacker's wallet
4. **Attack Execution**: Attacker calls the vault program but passes their fake program as the "token program"
5. **Exploitation**: The vault authority signs, thinking tokens will be sent legitimately, but the fake program executes malicious logic
6. **Result**: Unauthorized token transfers or complete vault drainage

### Why It Succeeds

The attack succeeds even when all other security checks pass:
- Account ownership is correctly validated
- Signatures are properly checked
- Data structures are verified
- BUT: The program performing the CPI is never validated

## Directory Structure

```
arbitrary-cpi/
├── vulnerable/
│   ├── anchor/          # Vulnerable Anchor implementation
│   │   ├── src/
│   │   │   ├── instructions/
│   │   │   │   ├── initialize.rs
│   │   │   │   ├── transfer_tokens.rs
│   │   │   │   └── mod.rs
│   │   │   ├── lib.rs
│   │   │   └── state.rs
│   │   ├── Cargo.toml
│   │   └── Anchor.toml
│   └── pinocchio/       # Vulnerable Pinocchio implementation
│       ├── src/
│       │   ├── lib.rs
│       │   └── state.rs
│       └── Cargo.toml
└── secure/
    ├── anchor/          # Secure Anchor implementation
    │   ├── src/
    │   │   ├── instructions/
    │   │   │   ├── initialize.rs
    │   │   │   ├── transfer_tokens.rs
    │   │   │   ├── transfer_tokens_with_cpi_helper.rs
    │   │   │   └── mod.rs
    │   │   ├── lib.rs
    │   │   └── state.rs
    │   ├── Cargo.toml
    │   └── Anchor.toml
    └── pinocchio/       # Secure Pinocchio implementation
        ├── src/
        │   ├── lib.rs
        │   └── state.rs
        └── Cargo.toml
```

## Vulnerable Implementation

### Anchor

The vulnerable Anchor implementation uses `UncheckedAccount` for the token program:

```rust
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    pub authority: Signer<'info>,
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub source: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    /// CHECK: This account is NOT checked - that's the vulnerability!
    pub token_program: UncheckedAccount<'info>,
}
```

Then performs CPI without validation:

```rust
solana_program::program::invoke(
    &spl_token::instruction::transfer(
        ctx.accounts.token_program.key,  // Could be ANY program!
        ctx.accounts.source.key,
        ctx.accounts.destination.key,
        ctx.accounts.authority.key,
        &[],
        amount,
    )?,
    &[
        ctx.accounts.source.to_account_info(),
        ctx.accounts.destination.to_account_info(),
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
    ],
)?;
```

### Pinocchio

The vulnerable Pinocchio implementation accepts any program without validation:

```rust
// VULNERABILITY: No program ID validation!
// Should check: if token_program_info.key() != &SPL_TOKEN_PROGRAM_ID { ... }

unsafe {
    pinocchio::program::invoke_signed(
        &pinocchio::instruction::Instruction {
            program_id: token_program_info.key(),  // Could be malicious!
            accounts: &[
                pinocchio::instruction::AccountMeta::writable(source_info.key()),
                pinocchio::instruction::AccountMeta::writable(destination_info.key()),
                pinocchio::instruction::AccountMeta::readonly_signer(authority_info.key()),
            ],
            data: &instruction_data_buf,
        },
        &[
            source_info.clone(),
            destination_info.clone(),
            authority_info.clone(),
            token_program_info.clone(),
        ],
        &[],
    )?;
}
```

## Secure Implementation

### Anchor - Method 1: Program Type

Use `Program<'info, Token>` instead of `UncheckedAccount`:

```rust
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    pub authority: Signer<'info>,
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub source: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,  // Automatically validates program ID!
}
```

Anchor automatically validates that `token_program.key() == spl_token::ID`.

### Anchor - Method 2: CPI Helpers (RECOMMENDED)

Use Anchor's CPI helper functions for type-safe CPIs:

```rust
use anchor_spl::token::{self, Transfer};

token::transfer(
    CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        Transfer {
            from: ctx.accounts.source.to_account_info(),
            to: ctx.accounts.destination.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        },
    ),
    amount,
)?;
```

This approach:
- Automatically validates the program ID
- Provides type safety
- Reduces boilerplate code
- Is the recommended pattern for Anchor programs

### Anchor - Method 3: Manual Validation

Explicitly check the program ID before CPI:

```rust
if ctx.accounts.token_program.key() != &spl_token::ID {
    return Err(ProgramError::IncorrectProgramId.into());
}

// Then perform CPI...
```

### Pinocchio

Manually validate the program ID before making the CPI:

```rust
const SPL_TOKEN_PROGRAM_ID: Pubkey =
    pinocchio::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

// Validate program ID BEFORE CPI
if token_program_info.key() != &SPL_TOKEN_PROGRAM_ID {
    msg!("Error: Invalid token program provided!");
    return Err(ProgramError::IncorrectProgramId);
}

// Safe to perform CPI now
unsafe {
    pinocchio::program::invoke_signed(
        &pinocchio::instruction::Instruction {
            program_id: token_program_info.key(),  // Validated!
            // ... rest of the instruction
        },
        // ... accounts
        &[],
    )?;
}
```

## Key Differences

| Aspect | Vulnerable | Secure |
|--------|-----------|--------|
| **Anchor Program Type** | `UncheckedAccount` | `Program<'info, Token>` |
| **Program Validation** | None | Automatic (Anchor) or Manual (Pinocchio) |
| **Attack Surface** | Any program can be called | Only validated program can be called |
| **Security** | High risk | Protected |

## Building the Programs

### Anchor Programs

```bash
# Vulnerable version
cd vulnerable/anchor
anchor build

# Secure version
cd secure/anchor
anchor build
```

### Pinocchio Programs

```bash
# Vulnerable version
cd vulnerable/pinocchio
cargo build-sbf

# Secure version
cd secure/pinocchio
cargo build-sbf
```

## Testing

The programs demonstrate:

1. **Initialization**: Setting up a vault with authority and token account
2. **Vulnerable Transfer**: Accepting arbitrary program for CPI (can be exploited)
3. **Secure Transfer**: Validating program ID before CPI (protected)
4. **CPI Helper**: Using Anchor's type-safe CPI helpers (recommended)

## Real-World Impact

Arbitrary CPI vulnerabilities can lead to:

1. **Token Drainage**: Attacker reverses transfers to drain vaults
2. **Unauthorized Operations**: Malicious programs execute with your program's authority
3. **Protocol Compromise**: Core functionality hijacked by fake programs
4. **Fund Loss**: Users lose tokens through misdirected transfers

## Prevention Checklist

- [ ] Never use `UncheckedAccount` for programs you'll call via CPI
- [ ] Always use `Program<'info, SpecificProgram>` in Anchor
- [ ] Prefer Anchor's CPI helpers over manual CPIs
- [ ] In Pinocchio, always validate program IDs before CPI
- [ ] Document which programs your CPIs should call
- [ ] Test with malicious program accounts to verify protections

## Best Practices

1. **Anchor Programs**: Use `Program<'info, Token>` for automatic validation
2. **Anchor CPIs**: Prefer CPI helpers (`anchor_spl::token::transfer`) over manual CPIs
3. **Pinocchio Programs**: Always validate program IDs with explicit comparisons
4. **Documentation**: Comment all CPI calls with expected program IDs
5. **Testing**: Include tests that attempt to pass wrong programs

## Additional Resources

- [Solana CPI Documentation](https://docs.solana.com/developing/programming-model/calling-between-programs)
- [Anchor CPI Guide](https://www.anchor-lang.com/docs/cross-program-invocations)
- [SPL Token Program](https://spl.solana.com/token)
- [Pinocchio Documentation](https://github.com/febo/pinocchio)

## License

This code is provided for educational purposes as part of the Solana Security Training Ground bounty submission.
