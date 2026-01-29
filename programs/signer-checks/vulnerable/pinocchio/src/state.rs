/// Program account state layout
///
/// Layout:
/// - Byte 0: Initialized flag (1 = initialized, 0 = uninitialized)
/// - Bytes 1-32: Owner public key (32 bytes)
/// - Bytes 33-40: Data field (8 bytes for u64)
pub struct ProgramAccount;

impl ProgramAccount {
    pub const LEN: usize = 1 + 32 + 8; // 41 bytes total
}
