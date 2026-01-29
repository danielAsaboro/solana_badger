# Missing Owner Checks Vulnerability

## Overview

**Severity:** 🔴 Critical
**Difficulty:** Beginner-friendly

Missing owner checks occur when programs accept accounts without verifying they are actually owned by the program. This allows attackers to pass fake accounts with malicious data, completely subverting program logic.

## Vulnerability Details

The vulnerability arises when:
1. A program accepts an `UncheckedAccount` (Anchor) or `AccountInfo` (Pinocchio) without validation
2. The program reads and trusts data from the account
3. The program does NOT verify the account is owned by itself (via program ID)
4. An attacker can create a lookalike account with identical structure but malicious data

## Attack Scenario

1. **Alice** initializes a legitimate account owned by the program with `data = 100`
2. **Bob (attacker)** creates his own account (owned by ANY program he controls)
3. **Bob** structures his fake account identically: discriminator + data + authority fields
4. **Bob** sets `data = 200` in his fake account (or any malicious value)
5. **Bob** calls `update_data`, passing his fake account instead of Alice's
6. The program deserializes Bob's fake account successfully (structure matches!)
7. The program reads `data = 200` from Bob's fake account
8. Business logic executes based on MALICIOUS data from Bob's account!
9. **Bob** has successfully manipulated program behavior without owning a real account

## Why This Is Dangerous

- The program trusts account data without verifying WHO owns the account
- Attackers can craft "lookalike" accounts with any data they want
- Business logic based on account data can be completely subverted
- It's like accepting a fake ID that "looks right" without checking the issuer
- Even Anchor's discriminator check is bypassed (attacker can replicate it)

## The Critical Difference

**What people get wrong:** "I'm checking the data, so it's safe"
**The reality:** Data validation ≠ Ownership validation

An attacker controls EVERY byte of their fake account, including:
- The discriminator (they can match yours exactly)
- All data fields (they set whatever values they want)
- The structure and layout (they replicate your account type)

The ONLY thing they can't fake is the `owner` field in `AccountInfo`, which is set by Solana's runtime based on who actually owns the account.

## Implementations

This directory contains 4 implementations:

### Vulnerable Versions
- `vulnerable/anchor/` - Anchor program using `UncheckedAccount` without owner validation
- `vulnerable/pinocchio/` - Pinocchio program missing `is_owned_by()` check

### Secure Versions
- `secure/anchor/` - Fixed Anchor implementation (3 methods shown)
- `secure/pinocchio/` - Fixed Pinocchio implementation with manual checks

## Building

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

Run the exploit demonstration:

```bash
# From repository root
npm test -- owner-checks
```

**Expected behavior:**
- ✅ Vulnerable programs: Exploit succeeds (demonstrates the vulnerability)
- ❌ Secure programs: Exploit blocked (demonstrates the fix)

## Key Takeaways

### For Anchor Developers

**Three ways to fix:**
1. Use `Account<'info, T>` type (recommended)
2. Use `#[account(owner = ID)]` constraint
3. Manual owner check in instruction logic

**Recommended approach:**
```rust
pub program_account: Account<'info, ProgramAccount>,  // Automatic owner check
```

**Why it works:**
- Anchor checks `account.owner == crate::ID` before deserializing
- Type system enforces security at compile time
- Prevents fake accounts at the framework level

### For Pinocchio Developers

**Always check:**
```rust
if !program_account_info.is_owned_by(&ID) {
    return Err(ProgramError::InvalidAccountOwner);
}
```

**Or equivalently:**
```rust
if program_account_info.owner() != &ID {
    return Err(ProgramError::InvalidAccountOwner);
}
```

**Best practices:**
- Check ownership BEFORE reading any account data
- Place the check as early as possible in the instruction
- Don't trust account data until ownership is verified
- Use the `is_owned_by()` helper for cleaner code

**Key difference:** Anchor does this automatically via types; Pinocchio requires manual checks.

## Real-World Impact

This vulnerability has led to:
- Complete program logic bypass
- Unauthorized access to privileged operations
- Financial losses when business logic depends on account data
- State manipulation and data corruption

It's one of the most common vulnerabilities in Solana programs because:
- It's easy to overlook (data looks valid)
- Discriminators give false sense of security
- Not obvious that ownership needs separate validation

## Learn More

- [Full Documentation](../../badger/docs/vulnerabilities/owner-checks.mdx)
- [Video Walkthrough](../../badger/docs/videos/security-deep-dive.mdx)
- [Framework Comparison](../../badger/docs/comparisons/anchor-vs-pinocchio.mdx)

## Related Vulnerabilities

- [Signer Checks](../signer-checks/) - Another critical validation issue
- [Type Cosplay](../type-cosplay/) - Account type confusion attacks
- [Arbitrary CPI](../arbitrary-cpi/) - Missing program ID validation
