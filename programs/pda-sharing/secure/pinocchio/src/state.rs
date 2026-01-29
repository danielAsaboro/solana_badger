use pinocchio::pubkey::Pubkey;

/// Token pool state with user-specific ownership
///
/// SECURITY FIX: This pool uses BOTH owner AND mint in PDA derivation:
/// seeds = [b"pool", owner, mint]
///
/// This ensures each user gets their own unique pool PDA.
///
/// Memory layout:
/// [0..32]   owner: Pubkey (32 bytes)
/// [32..64]  mint: Pubkey (32 bytes)
/// [64..96]  vault: Pubkey (32 bytes)
/// [96]      bump: u8 (1 byte)
/// Total: 97 bytes
pub struct TokenPool {
    /// The user who owns this pool
    /// CRITICAL: Used in PDA derivation to ensure uniqueness
    pub owner: Pubkey,

    /// The token mint this pool manages
    pub mint: Pubkey,

    /// The token account (vault) holding this user's deposited tokens
    pub vault: Pubkey,

    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl TokenPool {
    pub const LEN: usize = 32 + 32 + 32 + 1; // 97 bytes

    /// Serialize pool data into account
    pub fn serialize(owner: &[u8; 32], mint: &[u8; 32], vault: &[u8; 32], bump: u8, data: &mut [u8]) {
        data[0..32].copy_from_slice(owner);
        data[32..64].copy_from_slice(mint);
        data[64..96].copy_from_slice(vault);
        data[96] = bump;
    }

    /// Deserialize pool data from account
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }

        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&data[0..32]);

        let mut mint_bytes = [0u8; 32];
        mint_bytes.copy_from_slice(&data[32..64]);

        let mut vault_bytes = [0u8; 32];
        vault_bytes.copy_from_slice(&data[64..96]);

        Ok(TokenPool {
            owner: Pubkey::from(owner_bytes),
            mint: Pubkey::from(mint_bytes),
            vault: Pubkey::from(vault_bytes),
            bump: data[96],
        })
    }
}
