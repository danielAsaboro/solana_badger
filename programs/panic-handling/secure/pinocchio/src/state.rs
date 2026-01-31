use pinocchio::Address;

pub struct ProcessorState {
    pub authority: Address,
    pub total: u64,
    pub count: u8,
}

impl ProcessorState {
    pub const LEN: usize = 32 + 8 + 1; // 41 bytes

    pub fn serialize(authority: &[u8; 32], total: u64, count: u8, data: &mut [u8]) {
        data[0..32].copy_from_slice(authority);
        data[32..40].copy_from_slice(&total.to_le_bytes());
        data[40] = count;
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::LEN {
            return Err("Account data too small");
        }
        let mut auth_bytes = [0u8; 32];
        auth_bytes.copy_from_slice(&data[0..32]);
        let total = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let count = data[40];
        Ok(ProcessorState {
            authority: Address::new_from_array(auth_bytes),
            total,
            count,
        })
    }
}
