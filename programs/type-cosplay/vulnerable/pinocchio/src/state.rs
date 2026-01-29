/// Account discriminators for type identification
///
/// In a secure implementation, these would be checked before deserializing.
/// The vulnerability is that we DON'T check these discriminators!
pub mod discriminators {
    /// Admin account discriminator
    /// In production, this would be derived from a hash
    pub const ADMIN: u8 = 1;

    /// User account discriminator
    /// Different from ADMIN to distinguish account types
    pub const USER: u8 = 2;
}

/// Admin account state layout
///
/// Layout in account data:
/// - Byte 0: Discriminator (1 for Admin)
/// - Bytes 1-32: Authority public key (32 bytes)
/// - Byte 33: Privilege level (10 for admin)
/// - Bytes 34-41: Operation count (u64, 8 bytes)
///
/// Total: 42 bytes
pub struct Admin;

impl Admin {
    pub const LEN: usize = 1 + 32 + 1 + 8; // 42 bytes
    pub const DISCRIMINATOR: u8 = discriminators::ADMIN;
    pub const PRIVILEGE_LEVEL: u8 = 10;

    /// Serialize an Admin account into raw bytes
    pub fn serialize(authority: &[u8; 32], operation_count: u64, dest: &mut [u8]) {
        dest[0] = Self::DISCRIMINATOR;
        dest[1..33].copy_from_slice(authority);
        dest[33] = Self::PRIVILEGE_LEVEL;
        dest[34..42].copy_from_slice(&operation_count.to_le_bytes());
    }

    /// Deserialize an Admin account from raw bytes
    /// VULNERABILITY: This doesn't check the discriminator!
    pub fn deserialize(data: &[u8]) -> Result<AdminData, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }

        let mut authority = [0u8; 32];
        authority.copy_from_slice(&data[1..33]);

        let privilege_level = data[33];

        let mut count_bytes = [0u8; 8];
        count_bytes.copy_from_slice(&data[34..42]);
        let operation_count = u64::from_le_bytes(count_bytes);

        Ok(AdminData {
            authority,
            privilege_level,
            operation_count,
        })
    }
}

/// User account state layout
///
/// Layout in account data:
/// - Byte 0: Discriminator (2 for User)
/// - Bytes 1-32: Authority public key (32 bytes)
/// - Byte 33: Privilege level (1 for user)
/// - Bytes 34-41: Operation count (u64, 8 bytes)
///
/// Total: 42 bytes
///
/// CRITICAL: This has the EXACT same layout as Admin (after the discriminator)!
/// This structural similarity enables the type cosplay attack.
pub struct User;

impl User {
    pub const LEN: usize = 1 + 32 + 1 + 8; // 42 bytes (same as Admin!)
    pub const DISCRIMINATOR: u8 = discriminators::USER;
    pub const PRIVILEGE_LEVEL: u8 = 1;

    /// Serialize a User account into raw bytes
    pub fn serialize(authority: &[u8; 32], operation_count: u64, dest: &mut [u8]) {
        dest[0] = Self::DISCRIMINATOR;
        dest[1..33].copy_from_slice(authority);
        dest[33] = Self::PRIVILEGE_LEVEL;
        dest[34..42].copy_from_slice(&operation_count.to_le_bytes());
    }

    /// Deserialize a User account from raw bytes
    pub fn deserialize(data: &[u8]) -> Result<UserData, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }

        let mut authority = [0u8; 32];
        authority.copy_from_slice(&data[1..33]);

        let privilege_level = data[33];

        let mut count_bytes = [0u8; 8];
        count_bytes.copy_from_slice(&data[34..42]);
        let operation_count = u64::from_le_bytes(count_bytes);

        Ok(UserData {
            authority,
            privilege_level,
            operation_count,
        })
    }
}

/// Deserialized Admin account data
pub struct AdminData {
    pub authority: [u8; 32],
    pub privilege_level: u8,
    pub operation_count: u64,
}

/// Deserialized User account data
pub struct UserData {
    pub authority: [u8; 32],
    pub privilege_level: u8,
    pub operation_count: u64,
}
