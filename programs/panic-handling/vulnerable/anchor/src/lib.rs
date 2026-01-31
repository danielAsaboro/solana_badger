use anchor_lang::prelude::*;

declare_id!("A5QPcpmFYpkPQdPNhv92vXUZRGWMDsmy1HAy6dj2xKjr");

pub mod state;
use state::ProcessorState;

#[program]
pub mod vulnerable_panic_handling {
    use super::*;

    pub fn process_data(ctx: Context<ProcessData>, values: Vec<u64>, divisor: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;

        // VULNERABLE: .unwrap() panics on None
        let first = values.first().unwrap();

        // VULNERABLE: Array indexing panics if out of bounds
        let last = values[values.len() - 1];

        // VULNERABLE: Division by zero panics
        let average = (first + last) / divisor;

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
