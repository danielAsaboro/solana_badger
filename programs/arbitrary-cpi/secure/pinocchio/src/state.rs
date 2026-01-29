#![allow(dead_code)]

use pinocchio::pubkey::Pubkey;

/// Vault state tracking authority and token account
pub struct Vault {
    pub authority: Pubkey,
    pub token_account: Pubkey,
    pub bump: u8,
}

impl Vault {
    pub const LEN: usize = 32 + // authority
        32 + // token_account
        1; // bump

    /// Deserialize vault from account data
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }

        let authority = Pubkey::from(<[u8; 32]>::try_from(&data[0..32]).unwrap());
        let token_account = Pubkey::from(<[u8; 32]>::try_from(&data[32..64]).unwrap());
        let bump = data[64];

        Ok(Self {
            authority,
            token_account,
            bump,
        })
    }

    /// Serialize vault to account data
    pub fn to_bytes(&self, data: &mut [u8]) -> Result<(), &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }

        data[0..32].copy_from_slice(self.authority.as_ref());
        data[32..64].copy_from_slice(self.token_account.as_ref());
        data[64] = self.bump;

        Ok(())
    }
}
