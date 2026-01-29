use anchor_lang::prelude::*;

/// Admin account with elevated privileges
///
/// The #[account] macro automatically adds:
/// 1. An 8-byte discriminator (hash of "account:Admin")
/// 2. Serialization/deserialization logic
/// 3. Discriminator validation when using Account<'info, Admin>
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
/// Despite having the same structure as Admin, the #[account] macro
/// ensures a different discriminator is used, preventing type confusion.
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
    pub const LEN: usize = 32 + 1 + 8;

    /// User accounts have privilege level 1
    pub const PRIVILEGE_LEVEL: u8 = 1;
}
