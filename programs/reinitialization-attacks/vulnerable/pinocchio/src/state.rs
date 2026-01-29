/// Vault account state layout
///
/// Layout:
/// - Byte 0: Discriminator (0 = uninitialized, 1 = initialized)
/// - Bytes 1-32: Authority public key (32 bytes)
/// - Bytes 33-40: Balance field (8 bytes for u64)
///
/// VULNERABILITY: The discriminator is present in the layout, but the
/// unsafe_initialize function never checks it before writing data.
/// This allows reinitialization attacks where an attacker can overwrite
/// an existing vault's authority and steal control of the funds.
pub struct Vault;

impl Vault {
    pub const LEN: usize = 1 + 32 + 8; // 41 bytes total
    pub const DISCRIMINATOR: u8 = 1;
}
