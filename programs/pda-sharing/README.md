# PDA Sharing Vulnerability

## Overview

**Severity:** 🔴 Critical
**Difficulty:** Intermediate

PDA (Program Derived Address) sharing attacks exploit programs that use insufficient seeds when deriving PDAs, causing multiple users to share the same PDA authority. This allows attackers to access funds, data, or permissions belonging to other users. When a PDA serves as a signing authority for user funds but lacks user-specific seeds, it becomes a master key that unlocks everyone's assets.

## Vulnerability Details

The vulnerability arises when:
1. A program derives a PDA using only global identifiers (like mint address)
2. Multiple users end up sharing the same PDA authority
3. No per-user isolation exists in the PDA derivation
4. The shared PDA has signing authority over user funds or sensitive operations
5. No additional validation checks user ownership

### The Problem

**Vulnerable PDA derivation:**
```rust
// VULNERABLE: Only uses mint in seeds
seeds = [b"pool", mint.key().as_ref()]
```

This creates a single shared PDA for all users depositing the same token type. All users of USDC would share one pool, all users of SOL would share another pool, etc.

**Secure PDA derivation:**
```rust
// SECURE: Uses user pubkey + mint in seeds
seeds = [b"pool", user.key().as_ref(), mint.key().as_ref()]
```

This creates a unique PDA for each user-mint combination. Alice gets her own USDC pool, Bob gets his own USDC pool, and they cannot interfere with each other.

## Attack Scenario

### The Setup
1. **Alice** deposits 100 USDC into the token pool
   - Pool PDA derived: `[b"pool", USDC_MINT]`
   - Her 100 USDC goes into a vault controlled by this PDA
   - Pool account: `seeds = [b"pool", USDC_MINT], bump = 255`

2. **Bob** (attacker) observes the program on-chain
   - He sees the vulnerable PDA derivation
   - He notices Alice deposited 100 USDC
   - He realizes the pool PDA only uses mint, not user pubkey

### The Attack
3. **Bob** derives the same pool PDA
   - Seeds: `[b"pool", USDC_MINT]`
   - Result: SAME PDA as Alice's pool!
   - This PDA has signing authority over the vault

4. **Bob** calls the withdraw instruction with:
   - `pool`: The shared PDA `[b"pool", USDC_MINT]`
   - `vault`: The token account holding Alice's funds
   - `destination`: Bob's own USDC token account
   - `amount`: 100 (all of Alice's tokens)

5. **The Program Executes**:
   ```rust
   // Pool PDA signs the transfer
   let seeds = &[b"pool", mint.as_ref(), &[bump]];
   token::transfer(ctx, amount)?; // Signs with shared PDA
   ```

6. **Result**: Bob successfully steals Alice's 100 USDC because:
   - The pool PDA is shared between users
   - The PDA has signing authority over the vault
   - No validation checks if Bob owns those tokens
   - The program trusts the shared PDA to sign for ANY withdrawal

### Why It Works

The vulnerability succeeds because:
- **Shared Authority**: One PDA controls multiple users' funds
- **Missing User Context**: PDA doesn't know which user's funds it's authorizing
- **No Ownership Validation**: Program doesn't verify token ownership
- **PDA Signs Blindly**: The PDA will sign any transfer request it receives

## Business Logic Context

This vulnerability commonly appears in:

### DeFi Token Pools
```rust
// Vulnerable: Global pool per mint
seeds = [b"pool", mint]
// One shared vault for all users of this token
```

### Staking Programs
```rust
// Vulnerable: Single staking pool per mint
seeds = [b"stake_pool", mint]
// All stakers share one authority
```

### Escrow Services
```rust
// Vulnerable: Shared escrow authority
seeds = [b"escrow", mint]
// All escrows share the same PDA signer
```

## Implementations

This directory contains 4 complete implementations demonstrating the vulnerability and fix:

### Vulnerable Versions
- `vulnerable/anchor/` - Anchor program with mint-only PDA seeds
- `vulnerable/pinocchio/` - Pinocchio program with mint-only PDA seeds

Both vulnerable versions use:
```rust
seeds = [b"pool", mint.key().as_ref()]
```

### Secure Versions
- `secure/anchor/` - Fixed Anchor implementation with user-specific seeds
- `secure/pinocchio/` - Fixed Pinocchio implementation with user-specific seeds

Both secure versions use:
```rust
seeds = [b"pool", user.key().as_ref(), mint.key().as_ref()]
```

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
npm test -- pda-sharing
```

**Expected behavior:**
- ✅ Vulnerable programs: Bob successfully steals Alice's tokens (demonstrates the vulnerability)
- ❌ Secure programs: Bob's theft attempt is rejected (demonstrates the fix)

## The Fix Explained

### Fix #1: User-Specific Seeds

**Change PDA derivation to include user pubkey:**

```rust
// Before (VULNERABLE):
seeds = [b"pool", mint.key().as_ref()]

// After (SECURE):
seeds = [b"pool", user.key().as_ref(), mint.key().as_ref()]
```

This ensures:
- Each user gets their own unique pool PDA
- Alice's pool: `[b"pool", ALICE_KEY, USDC_MINT]`
- Bob's pool: `[b"pool", BOB_KEY, USDC_MINT]`
- No PDA collision possible

### Fix #2: Owner Validation (Anchor)

**Use `has_one` constraint to validate ownership:**

```rust
#[account(
    seeds = [b"pool", pool.owner.as_ref(), pool.mint.as_ref()],
    bump = pool.bump,
    has_one = owner @ ErrorCode::UnauthorizedWithdrawal
)]
pub pool: Account<'info, TokenPool>,

pub owner: Signer<'info>,
```

The `has_one = owner` constraint:
- Verifies `pool.owner` field matches the `owner` signer
- Prevents someone from using another user's pool
- Enforces that only the pool owner can withdraw

### Fix #3: Manual Owner Validation (Pinocchio)

**Explicitly check owner matches signer:**

```rust
// Verify pool PDA includes owner
let (expected_pool, bump) = Pubkey::find_program_address(
    &[b"pool", pool.owner.as_ref(), pool.mint.as_ref()],
    &ID,
);

if pool_info.key() != &expected_pool {
    return Err(ProgramError::InvalidSeeds);
}

// Verify signer is the pool owner
if owner_info.key() != &pool.owner {
    return Err(ProgramError::InvalidAccountData);
}
```

## Code Comparison

### Vulnerable Approach

```rust
// Anchor vulnerable example
#[account(
    seeds = [b"pool", pool.mint.as_ref()],  // ❌ No user context
    bump = pool.bump,
)]
pub pool: Account<'info, TokenPool>,

// Anyone can withdraw - no owner check!
pub withdrawer: Signer<'info>,
```

### Secure Approach

```rust
// Anchor secure example
#[account(
    seeds = [b"pool", pool.owner.as_ref(), pool.mint.as_ref()],  // ✅ User-specific
    bump = pool.bump,
    has_one = owner @ ErrorCode::UnauthorizedWithdrawal  // ✅ Owner validation
)]
pub pool: Account<'info, TokenPool>,

// Only pool owner can withdraw
pub owner: Signer<'info>,
```

## Key Takeaways

### For Anchor Developers

**Critical Rules:**
1. **Always include user-specific seeds** in PDAs that control user funds
2. **Use `has_one` constraints** to validate ownership
3. **Never share PDAs** across users for fund management
4. **Think about PDA scope**: Who should have access to this authority?

**PDA Design Checklist:**
- [ ] Does this PDA control user funds or sensitive operations?
- [ ] Are the seeds specific enough to isolate per user?
- [ ] Is there a user pubkey in the seed derivation?
- [ ] Are ownership constraints (`has_one`) in place?
- [ ] Could two different users derive the same PDA?

### For Pinocchio Developers

**Critical Validations:**
1. **Derive PDAs with user-specific seeds**
2. **Manually validate ownership**: Compare `pool.owner` with `signer.key()`
3. **Verify PDA derivation**: Check seeds include user context
4. **Validate before signing**: Ensure the signer owns the resources

**Manual Check Pattern:**
```rust
// 1. Deserialize state
let pool = TokenPool::deserialize(&data)?;

// 2. Verify PDA includes user
let (expected_pool, _) = Pubkey::find_program_address(
    &[b"pool", pool.owner.as_ref(), pool.mint.as_ref()],
    &ID,
);

// 3. Verify owner is signer
if owner_info.key() != &pool.owner {
    return Err(ProgramError::InvalidAccountData);
}
```

## Real-World Impact

PDA sharing vulnerabilities have led to:
- **Complete fund drainage** in DeFi protocols
- **Cross-user token theft** in staking programs
- **Unauthorized withdrawals** from escrow services
- **Protocol insolvency** when all users' funds are stolen

The impact is typically **total loss of all funds** in the shared pool.

## Common Patterns to Avoid

### ❌ Mint-Only Seeds
```rust
seeds = [b"vault", mint.key().as_ref()]
// All users of this mint share one vault
```

### ❌ Program-Only Seeds
```rust
seeds = [b"pool"]
// ALL users share one global pool
```

### ❌ Mint + Instruction Seeds
```rust
seeds = [b"pool", mint.key().as_ref(), b"withdraw"]
// Still shared across all users
```

## Common Patterns to Use

### ✅ User + Mint Seeds
```rust
seeds = [b"pool", user.key().as_ref(), mint.key().as_ref()]
// Each user-mint combo gets unique pool
```

### ✅ User + Destination Seeds
```rust
seeds = [b"escrow", user.key().as_ref(), destination.key().as_ref()]
// Unique per user-destination pair
```

### ✅ User + Index Seeds
```rust
seeds = [b"account", user.key().as_ref(), &index.to_le_bytes()]
// Users can have multiple accounts
```

## Prevention Strategies

1. **Design Phase**: Plan PDA seeds to ensure per-user isolation
2. **Code Review**: Check all PDA derivations for user-specific seeds
3. **Testing**: Write tests that simulate cross-user attacks
4. **Audit**: Have security experts review PDA seed derivations
5. **Principle**: If a PDA controls user funds, it MUST include user pubkey in seeds

## Learn More

- [Anchor PDA Documentation](https://www.anchor-lang.com/docs/pdas)
- [Solana PDA Deep Dive](https://solana.com/docs/core/pda)
- [Program Security Best Practices](https://github.com/coral-xyz/sealevel-attacks)

## Related Vulnerabilities

- [Owner Checks](../owner-checks/) - Validating account ownership
- [Signer Checks](../signer-checks/) - Verifying transaction signatures
- [Arbitrary CPI](../arbitrary-cpi/) - Validating program invocations

---

**Remember**: A PDA is only as secure as its seed derivation. Always include user-specific identifiers when the PDA controls user resources.
