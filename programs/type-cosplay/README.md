# Type Cosplay Vulnerability

Type cosplay attacks exploit programs that fail to verify account discriminators, allowing attackers to substitute accounts with identical data structures but different intended purposes. This vulnerability enables privilege escalation by passing low-privilege accounts (User) where high-privilege accounts (Admin) are expected.

## Overview

Solana stores all account data as raw bytes. Without proper type validation through discriminators, a program cannot distinguish between accounts that have the same memory layout but different semantic meanings. An attacker who controls a User account can masquerade as an Admin account, bypassing authorization checks and gaining elevated privileges.

## The Vulnerability

### Root Cause

The vulnerability stems from two critical mistakes:

1. **Missing Discriminator Validation**: Using `UncheckedAccount` (Anchor) or deserializing without checking the discriminator byte (Pinocchio)
2. **Structural Ambiguity**: Multiple account types (Admin, User) with identical memory layouts after the discriminator

When both conditions exist, an attacker can perform a "type cosplay attack" by passing the wrong account type to an instruction.

### Attack Scenario

1. **Setup**: Program has two account types:
   - `Admin`: authority (32 bytes) + privilege_level: 10 (1 byte) + operation_count (8 bytes)
   - `User`: authority (32 bytes) + privilege_level: 1 (1 byte) + operation_count (8 bytes)

2. **Attacker Actions**:
   - Creates a legitimate User account (privilege_level = 1)
   - Calls `admin_operation` instruction
   - Passes their User account where Admin account is expected

3. **Exploitation**:
   - Program checks program ownership ✓ (both owned by program)
   - Program checks authority signature ✓ (attacker signs with own key)
   - Program SKIPS discriminator check ✗
   - Deserialization succeeds (identical layouts)
   - User account treated as Admin account
   - Privileged operation executes

4. **Impact**: Attacker gains admin privileges without being an admin!

## Implementations

### Vulnerable Versions

Both vulnerable implementations demonstrate the same core issue:

**Anchor Vulnerable** (`programs/type-cosplay/vulnerable/anchor/`)
- Uses `UncheckedAccount` instead of `Account<'info, Admin>`
- Manually deserializes without checking discriminator
- Only validates program ownership and authority signature
- Allows User accounts to impersonate Admin accounts

**Pinocchio Vulnerable** (`programs/type-cosplay/vulnerable/pinocchio/`)
- Deserializes account data without discriminator validation
- `Admin::deserialize()` skips the discriminator byte
- Identical to Anchor issue but at a lower level

### Secure Versions

**Anchor Secure** (`programs/type-cosplay/secure/anchor/`)
- Uses `Account<'info, Admin>` for automatic validation
- Anchor checks discriminator matches `hash("account:Admin")[..8]`
- Prevents User accounts from being deserialized as Admin
- Type safety enforced at compile time

**Pinocchio Secure** (`programs/type-cosplay/secure/pinocchio/`)
- Manual discriminator validation before deserialization
- Checks `data[0] == Admin::DISCRIMINATOR` explicitly
- Returns error if discriminator doesn't match
- Prevents type confusion attacks

## Technical Details

### Discriminators

Discriminators are unique identifiers that tag account types:

**Anchor**:
- 8-byte discriminator automatically added by `#[account]` macro
- Derived from `hash("account:TypeName")[..8]`
- Admin: `hash("account:Admin")[..8]` (e.g., `0x1234567890abcdef`)
- User: `hash("account:User")[..8]` (e.g., `0xfedcba0987654321`)

**Pinocchio**:
- Manual 1-byte discriminator (can be any size)
- Admin: `1`
- User: `2`
- Must be checked explicitly in code

### Memory Layout Comparison

Both account types have identical layouts (after discriminator):

```
Admin Account:
[discriminator][authority: 32 bytes][privilege: 1 byte][count: 8 bytes]
[     1       ][  0x1234...        ][      10        ][    0      ]

User Account:
[discriminator][authority: 32 bytes][privilege: 1 byte][count: 8 bytes]
[     2       ][  0x1234...        ][       1        ][    0      ]
```

When the discriminator isn't checked, the program can't tell them apart!

## Prevention

### For Anchor Programs

✅ **DO**: Use typed accounts
```rust
#[account(mut)]
pub admin_account: Account<'info, Admin>,
```

✅ **DO**: Use `#[account]` macro on state structs
```rust
#[account]
pub struct Admin {
    pub authority: Pubkey,
    pub privilege_level: u8,
}
```

❌ **DON'T**: Use `UncheckedAccount` without validation
```rust
/// CHECK: UNSAFE!
pub admin_account: UncheckedAccount<'info>,
```

### For Pinocchio Programs

✅ **DO**: Check discriminator before deserializing
```rust
if data[0] != Admin::DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
```

✅ **DO**: Include validation in deserialize functions
```rust
pub fn deserialize(data: &[u8]) -> Result<AdminData, &'static str> {
    if data[0] != Self::DISCRIMINATOR {
        return Err("Invalid discriminator");
    }
    // ... deserialize rest
}
```

❌ **DON'T**: Skip discriminator validation
```rust
// VULNERABLE: Skips first byte without checking it
let admin = Admin::deserialize(&data[1..])?;
```

## Building and Testing

### Build All Programs

```bash
# Anchor programs
cd programs/type-cosplay/vulnerable/anchor && anchor build
cd ../../../secure/anchor && anchor build

# Pinocchio programs (requires cargo-build-sbf)
cd programs/type-cosplay/vulnerable/pinocchio && cargo-build-sbf
cd ../../../secure/pinocchio && cargo-build-sbf
```

### Test the Vulnerability

Create test script demonstrating the attack:

```typescript
// 1. Initialize User account (attacker)
await program.methods.initializeUser()
  .accounts({ authority: attacker.publicKey })
  .rpc();

// 2. Try to execute admin operation with User account
// Vulnerable: Succeeds!
// Secure: Fails with "AccountDiscriminatorMismatch"
await program.methods.adminOperation()
  .accounts({
    authority: attacker,
    adminAccount: userAccountPda, // Passing User as Admin!
  })
  .rpc();
```

## Key Takeaways

1. **Always validate account types** using discriminators
2. **Anchor's `Account<'info, T>` provides automatic protection**
3. **UncheckedAccount requires manual validation**
4. **Structural similarity doesn't mean type equivalence**
5. **Discriminators are essential for type safety on Solana**

## Related Vulnerabilities

- **Owner Checks**: Verifying program ownership (prerequisite)
- **Signer Checks**: Validating authority signatures (insufficient alone)
- **Account Validation**: Complete validation requires discriminator + owner + signer checks

## References

- [Anchor Account Types](https://www.anchor-lang.com/docs/account-types)
- [Solana Cookbook - Account Validation](https://solanacookbook.com/)
- [Type Cosplay Security Advisory](../../resources/content/courses/program-security/type-cosplay/)

## License

This code is provided for educational purposes to demonstrate security vulnerabilities in Solana programs.
