use anchor_lang::prelude::*;

pub fn read_data(ctx: Context<ReadData>) -> Result<()> {
    let account_info = ctx.accounts.store.to_account_info();
    let data = account_info.try_borrow_data()?;

    // VULNERABILITY: Unsafe pointer cast - trusts raw bytes without validation
    // This bypasses Anchor's discriminator check and type safety
    // An attacker could pass an account with crafted data
    let store_data = unsafe {
        let raw_ptr = data.as_ptr().add(8) as *const RawDataStore; // skip discriminator
        &*raw_ptr
    };

    // VULNERABILITY: No bounds checking, no validation
    // If account data is shorter than expected, this reads garbage memory
    msg!("Authority: {:?}", store_data.authority);
    msg!("Value: {}", store_data.value);

    Ok(())
}

/// Raw struct for unsafe casting - mirrors DataStore layout
#[repr(C)]
pub struct RawDataStore {
    pub authority: [u8; 32],
    pub value: u64,
    pub label: [u8; 32],
    pub is_initialized: u8,
}

#[derive(Accounts)]
pub struct ReadData<'info> {
    pub authority: Signer<'info>,

    /// CHECK: INTENTIONALLY VULNERABLE - accepts any account for unsafe read
    pub store: UncheckedAccount<'info>,
}
