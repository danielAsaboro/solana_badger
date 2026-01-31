use pinocchio::Address;

pub struct VaultState {
    pub user: Address,
    pub balance: u64,
    pub bump: u8,
}

impl VaultState {
    pub const LEN: usize = 32 + 8 + 1; // 41 bytes

    pub fn serialize(user: &[u8; 32], balance: u64, bump: u8, data: &mut [u8]) {
        data[0..32].copy_from_slice(user);
        data[32..40].copy_from_slice(&balance.to_le_bytes());
        data[40] = bump;
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }
        let mut user_bytes = [0u8; 32];
        user_bytes.copy_from_slice(&data[0..32]);
        let balance = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let bump = data[40];
        Ok(VaultState {
            user: Address::new_from_array(user_bytes),
            balance,
            bump,
        })
    }
}
