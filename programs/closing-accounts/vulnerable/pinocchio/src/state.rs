use pinocchio::Address;

pub struct VaultState {
    pub authority: Address,
    pub balance: u64,
    pub is_active: u8, // 1 = active, 0 = closed
}

impl VaultState {
    pub const LEN: usize = 32 + 8 + 1; // 41 bytes

    pub fn serialize(authority: &[u8; 32], balance: u64, is_active: u8, data: &mut [u8]) {
        data[0..32].copy_from_slice(authority);
        data[32..40].copy_from_slice(&balance.to_le_bytes());
        data[40] = is_active;
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }
        let mut auth_bytes = [0u8; 32];
        auth_bytes.copy_from_slice(&data[0..32]);
        let balance = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let is_active = data[40];
        Ok(VaultState {
            authority: Address::new_from_array(auth_bytes),
            balance,
            is_active,
        })
    }
}
