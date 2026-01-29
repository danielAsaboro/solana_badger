use pinocchio::pubkey::Pubkey;

/// Token pool state tracking vault and mint
///
/// VULNERABILITY: This pool uses only the mint address in its PDA derivation,
/// creating a SHARED PDA across all users depositing the same token type.
///
/// Memory layout:
/// [0..32]   mint: Pubkey (32 bytes)
/// [32..64]  vault: Pubkey (32 bytes)
/// [64]      bump: u8 (1 byte)
/// Total: 65 bytes
pub struct TokenPool {
    /// The token mint this pool manages
    pub mint: Pubkey,

    /// The token account (vault) holding deposited tokens
    /// ISSUE: Single vault per mint means all users' funds are mixed
    pub vault: Pubkey,

    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl TokenPool {
    pub const LEN: usize = 32 + 32 + 1; // 65 bytes

    /// Serialize pool data into account
    pub fn serialize(mint: &[u8; 32], vault: &[u8; 32], bump: u8, data: &mut [u8]) {
        data[0..32].copy_from_slice(mint);
        data[32..64].copy_from_slice(vault);
        data[64] = bump;
    }

    /// Deserialize pool data from account
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }

        let mut mint_bytes = [0u8; 32];
        mint_bytes.copy_from_slice(&data[0..32]);

        let mut vault_bytes = [0u8; 32];
        vault_bytes.copy_from_slice(&data[32..64]);

        Ok(TokenPool {
            mint: Pubkey::from(mint_bytes),
            vault: Pubkey::from(vault_bytes),
            bump: data[64],
        })
    }
}
