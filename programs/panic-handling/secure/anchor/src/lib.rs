use anchor_lang::prelude::*;

declare_id!("BCaMVsHMzC2yT9S6fxEjnWHL7tm2VFk9jMetawEgTh4t");

pub mod state;
use state::ProcessorState;

#[program]
pub mod secure_panic_handling {
    use super::*;

    pub fn process_data(ctx: Context<ProcessData>, values: Vec<u64>, divisor: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;

        // SECURE: Proper error handling with meaningful errors
        let first = values.first().ok_or(PanicError::EmptyValues)?;

        // SECURE: Bounds-checked access
        let last = values.get(values.len().wrapping_sub(1))
            .ok_or(PanicError::EmptyValues)?;

        // SECURE: Checked division
        let sum = first.checked_add(*last).ok_or(PanicError::Overflow)?;
        let average = sum.checked_div(divisor).ok_or(PanicError::DivisionByZero)?;

        state.data = values;
        state.total = average;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct ProcessData<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = ProcessorState::LEN,
        seeds = [b"processor", authority.key().as_ref()],
        bump
    )]
    pub state: Account<'info, ProcessorState>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum PanicError {
    #[msg("Cannot process empty values")]
    EmptyValues,
    #[msg("Division by zero")]
    DivisionByZero,
    #[msg("Integer overflow")]
    Overflow,
}
