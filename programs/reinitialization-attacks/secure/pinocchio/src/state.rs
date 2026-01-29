/// Vault account state layout
///
/// Layout:
/// - Byte 0: Discriminator (0 = uninitialized, 1 = initialized)
/// - Bytes 1-32: Authority public key (32 bytes)
/// - Bytes 33-40: Balance field (8 bytes for u64)
///
/// SECURITY: The discriminator at byte 0 is checked before initialization
/// to ensure the account hasn't been initialized yet. This prevents
/// reinitialization attacks where an attacker would overwrite the authority.
pub struct Vault;

impl Vault {
    pub const LEN: usize = 1 + 32 + 8; // 41 bytes total
    pub const DISCRIMINATOR: u8 = 1;
}
