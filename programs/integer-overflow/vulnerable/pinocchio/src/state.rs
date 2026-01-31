use pinocchio::Address;

pub struct VaultState {
    pub owner: Address,
    pub balance: u64,
}

impl VaultState {
    pub const LEN: usize = 32 + 8; // 40 bytes

    pub fn serialize(owner: &[u8; 32], balance: u64, data: &mut [u8]) {
        data[0..32].copy_from_slice(owner);
        data[32..40].copy_from_slice(&balance.to_le_bytes());
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }
        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&data[0..32]);
        let balance = u64::from_le_bytes(data[32..40].try_into().unwrap());
        Ok(VaultState {
            owner: Address::new_from_array(owner_bytes),
            balance,
        })
    }
}
