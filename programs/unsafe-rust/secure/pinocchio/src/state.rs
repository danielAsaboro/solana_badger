use pinocchio::Address;

pub struct DataStore {
    pub authority: Address,
    pub value: u64,
    pub label: [u8; 32],
    pub is_initialized: u8,
}

impl DataStore {
    pub const LEN: usize = 32 + 8 + 32 + 1; // 73 bytes

    pub fn serialize(authority: &[u8; 32], value: u64, label: &[u8; 32], is_initialized: u8, data: &mut [u8]) {
        data[0..32].copy_from_slice(authority);
        data[32..40].copy_from_slice(&value.to_le_bytes());
        data[40..72].copy_from_slice(label);
        data[72] = is_initialized;
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }
        let mut auth_bytes = [0u8; 32];
        auth_bytes.copy_from_slice(&data[0..32]);
        let value = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let mut label = [0u8; 32];
        label.copy_from_slice(&data[40..72]);
        let is_initialized = data[72];
        Ok(DataStore {
            authority: Address::new_from_array(auth_bytes),
            value,
            label,
            is_initialized,
        })
    }
}
