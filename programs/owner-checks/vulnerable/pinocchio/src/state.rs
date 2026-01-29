/// Program account state layout
///
/// Layout:
/// - Byte 0: Initialized flag (1 = initialized, 0 = uninitialized)
/// - Bytes 1-8: Data field (8 bytes for u64)
/// - Bytes 9-40: Authority public key (32 bytes)
pub struct ProgramAccount;

impl ProgramAccount {
    pub const LEN: usize = 1 + 8 + 32; // 41 bytes total
}
