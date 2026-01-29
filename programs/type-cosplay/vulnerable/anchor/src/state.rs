use anchor_lang::prelude::*;

/// Admin account with elevated privileges
///
/// This account type should have a unique discriminator (derived from "account:Admin")
/// that distinguishes it from User accounts. However, when using UncheckedAccount,
/// the discriminator is never validated!
#[account]
pub struct Admin {
    /// Authority who controls this admin account
    pub authority: Pubkey,
    /// Privilege level (10 = full admin access)
    pub privilege_level: u8,
    /// Number of admin operations performed
    pub operation_count: u64,
}

impl Admin {
    /// Space calculation: 32 (pubkey) + 1 (u8) + 8 (u64)
    pub const LEN: usize = 32 + 1 + 8;

    /// Admin accounts have privilege level 10
    pub const PRIVILEGE_LEVEL: u8 = 10;
}

/// User account with basic privileges
///
/// CRITICAL: This struct has the EXACT same memory layout as Admin:
/// - Pubkey (32 bytes)
/// - u8 (1 byte)
/// - u64 (8 bytes)
///
/// This structural similarity enables the type cosplay attack!
/// When deserialized as raw bytes, a User account looks identical to an Admin.
/// Only the discriminator (first 8 bytes prepended by Anchor) differs.
#[account]
pub struct User {
    /// Authority who controls this user account
    pub authority: Pubkey,
    /// Privilege level (1 = basic user access)
    pub privilege_level: u8,
    /// Number of operations performed
    pub operation_count: u64,
}

impl User {
    /// Space calculation: 32 (pubkey) + 1 (u8) + 8 (u64)
    /// Note: Identical to Admin::LEN due to same structure!
    pub const LEN: usize = 32 + 1 + 8;

    /// User accounts have privilege level 1
    pub const PRIVILEGE_LEVEL: u8 = 1;
}
