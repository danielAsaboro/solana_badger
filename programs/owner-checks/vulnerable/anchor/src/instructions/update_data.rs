use anchor_lang::prelude::*;
use crate::state::ProgramAccount;

/// VULNERABLE: Updates account data without verifying program ownership
///
/// This function demonstrates a critical owner check vulnerability:
/// 1. It uses UncheckedAccount which does NOT validate the account owner
/// 2. It manually deserializes data without Anchor's type safety
/// 3. An attacker can create a fake account with identical data structure
/// 4. The fake account will deserialize correctly, but is NOT owned by this program
///
/// ATTACK SCENARIO:
/// 1. Alice initializes a legitimate account owned by this program with data = 100
/// 2. Bob (attacker) creates his own account (owned by ANY program he controls)
/// 3. Bob structures his fake account with identical layout: discriminator + data + authority
/// 4. Bob sets data = 200 in his fake account
/// 5. Bob calls update_data, passing his fake account
/// 6. The program deserializes Bob's fake account successfully (structure matches!)
/// 7. The program reads data = 200 from Bob's fake account
/// 8. The instruction logic executes based on MALICIOUS data from Bob's account
/// 9. Bob has successfully manipulated program behavior without owning a real account!
///
/// WHY THIS IS DANGEROUS:
/// - The program trusts account data without verifying WHO owns the account
/// - Attackers can craft "lookalike" accounts with malicious values
/// - Business logic based on the data field can be completely subverted
/// - It's like accepting a fake ID that "looks right" without checking the issuer
pub fn update_data(ctx: Context<UpdateData>, new_data: u64) -> Result<()> {
    // VULNERABILITY: Manual deserialization without owner validation!
    // We're manually borrowing and deserializing data from an UncheckedAccount.
    // Anchor's Account<T> type would automatically verify:
    // 1. The account is owned by this program (crate::ID)
    // 2. The discriminator matches ProgramAccount
    // 3. The data deserializes correctly
    // But with UncheckedAccount + manual deserialization, we only get #3!
    let account_data = ctx.accounts.program_account.try_borrow_data()?;
    let mut account_data_slice: &[u8] = &account_data;
    let account_state = ProgramAccount::try_deserialize(&mut account_data_slice)?;

    msg!("Current data from account: {}", account_state.data);
    msg!("Authority from account: {}", account_state.authority);

    // Even if we validate the data here, it doesn't matter!
    // An attacker controls the ENTIRE account data structure.
    // They can set data and authority to ANY values they want.
    if account_state.data < 100 {
        msg!("Data validation passed, allowing update");
    }

    // Now we would perform some business logic based on the account data
    // But since the attacker controls the data, they control the execution path!
    msg!("Updating data from {} to {}", account_state.data, new_data);

    // In a real scenario, we might write back to the account or perform other actions
    // But the damage is already done - we trusted unverified data!

    Ok(())
}

#[derive(Accounts)]
pub struct UpdateData<'info> {
    /// The authority making the update
    pub authority: Signer<'info>,

    /// VULNERABILITY: Using UncheckedAccount instead of Account<'info, ProgramAccount>!
    ///
    /// This is the critical mistake. UncheckedAccount means:
    /// - NO owner verification (account could be owned by ANY program)
    /// - NO discriminator verification (could be ANY account type)
    /// - NO automatic deserialization with type safety
    ///
    /// The /// CHECK comment is Anchor's way of saying "I know this is dangerous,
    /// I'm handling validation manually" - but we're NOT handling it correctly!
    #[account(mut)]
    /// CHECK: INTENTIONALLY VULNERABLE - This should be Account<'info, ProgramAccount>!
    pub program_account: UncheckedAccount<'info>,
}
