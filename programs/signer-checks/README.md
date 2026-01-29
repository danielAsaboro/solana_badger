# Missing Signer Checks Vulnerability

## Overview

**Severity:** 🔴 Critical
**Difficulty:** Beginner-friendly

Missing signer checks occur when programs accept accounts without verifying the transaction was actually signed by the account owner. This allows attackers to modify accounts they don't control.

## Vulnerability Details

The vulnerability arises when:
1. A program accepts an `UncheckedAccount` (Anchor) or `AccountInfo` (Pinocchio) without validation
2. The program checks if data matches but doesn't verify signatures
3. An attacker can pass any public key without obtaining the owner's signature

## Attack Scenario

1. **Alice** initializes an account, becoming the owner
2. **Bob (attacker)** reads Alice's public key from on-chain data
3. **Bob** calls `update_owner`, passing Alice's public key but NOT getting her signature
4. The `has_one` check passes (data matches), but Alice never signed!
5. **Bob** successfully changes ownership to himself, stealing Alice's account

## Implementations

This directory contains 4 implementations:

### Vulnerable Versions
- `vulnerable/anchor/` - Anchor program with missing signer check
- `vulnerable/pinocchio/` - Pinocchio program with missing signer check

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
npm test -- signer-checks
```

**Expected behavior:**
- ✅ Vulnerable programs: Exploit succeeds (demonstrates the vulnerability)
- ❌ Secure programs: Exploit blocked (demonstrates the fix)

## Key Takeaways

### For Anchor Developers

**Three ways to fix:**
1. Use `Signer<'info>` type (recommended)
2. Use `#[account(signer)]` constraint
3. Manual `is_signer` check in instruction logic

**Recommended approach:**
```rust
pub owner: Signer<'info>,  // Forces signature validation
```

### For Pinocchio Developers

**Always check:**
```rust
if !owner_info.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}
```

**Key difference:** Anchor does this automatically via types; Pinocchio requires manual checks.

## Learn More

- [Full Documentation](../../badger/docs/vulnerabilities/signer-checks.mdx)
- [Video Walkthrough](../../badger/docs/videos/security-deep-dive.mdx)
- [Framework Comparison](../../badger/docs/comparisons/anchor-vs-pinocchio.mdx)

## Related Vulnerabilities

- [Owner Checks](../owner-checks/) - Another critical validation issue
- [Type Cosplay](../type-cosplay/) - Account type confusion attacks
