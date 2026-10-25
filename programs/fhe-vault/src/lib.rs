//! `fhe-vault`: the on-chain half of the starter kit.
//!
//! The program stores RLWE ciphertexts in accounts and runs the homomorphic
//! operations that fit inside a Solana program's compute budget: addition,
//! subtraction, and multiplication by a public scalar. Each of those is
//! coefficient-wise modular arithmetic over the account bytes, with no
//! transform and no key material. `docs/FEASIBILITY.md` explains, with
//! measurements, why ciphertext times ciphertext multiplication is not here.
//!
//! Two things this program deliberately does not do:
//!
//! * It never decrypts. It has no secret key and cannot get one.
//! * It never measures noise. It propagates a conservative bound, because a real
//!   measurement needs the secret key. `fhe_core::noise` is where that lives,
//!   and each account records the bound so a reader can check it.
//!
//! Value accounts are created by [`create_value`], uploaded in chunks by
//! [`write_chunk`] (one ciphertext is far larger than one transaction), and
//! combined by [`homomorphic_add`] and [`scalar_mul`]. Results produced by the
//! off-chain engine are recorded by [`commit_evaluation`], which is the seam
//! between the two tiers.

use anchor_lang::prelude::*;
use anchor_lang::system_program;
use fhe_core::account::{self, Header, HEADER_LEN};
use fhe_core::params::Params;
use fhe_core::{noise, ops, FheError};

declare_id!("EJimqNCEMedCWkzUFPMFVWudYpHSvHAWFHyqeegyfqYt");

/// Seed for a value account: `["value", creator, index_le]`.
pub const VALUE_SEED: &[u8] = b"value";
/// Seed for an evaluation record: `["evaluation", author, index_le]`.
pub const EVALUATION_SEED: &[u8] = b"evaluation";

/// Discriminates the operation recorded in an [`OperationApplied`] event.
pub const OP_ADD: u8 = 0;
/// See [`OP_ADD`].
pub const OP_SCALAR_MUL: u8 = 1;

/// The off-chain engine that produced a committed result.
pub const SCHEME_SEAL_BFV: u8 = 1;

/// The most an account created through a cross-program invocation may grow in
/// one instruction.
///
/// This is a runtime rule, not a choice: `create_account` invoked from a program
/// can only allocate this much, so a standard tier value account (about 32 KiB)
/// is allocated in steps by [`fhe_vault::grow_value`]. The demo tier fits in one
/// go. Discovering this is part of the point of the kit; it is recorded in
/// `docs/FINDINGS.md`.
pub const MAX_PERMITTED_DATA_INCREASE: usize = 10_240;

#[program]
pub mod fhe_vault {
    use super::*;

    /// Create an empty value account for one ciphertext.
    ///
    /// The account is a PDA, so the program signs for its own creation and the
    /// caller needs no extra keypair. The ciphertext itself arrives later, in
    /// chunks, because it does not fit in one transaction.
    pub fn create_value(ctx: Context<CreateValue>, param_id: u8, index: u64) -> Result<()> {
        let params = Params::from_id(param_id).ok_or(VaultError::UnknownParameterSet)?;
        let value = ctx.accounts.value.to_account_info();
        require!(
            value.data_is_empty() && value.lamports() == 0,
            VaultError::AlreadyInitialized
        );

        let bump = ctx.bumps.value;
        let payer_key = ctx.accounts.payer.key();
        let index_bytes = index.to_le_bytes();
        let seeds: &[&[u8]] = &[VALUE_SEED, payer_key.as_ref(), &index_bytes, &[bump]];

        let space = account::account_len(&params);
        // See MAX_PERMITTED_DATA_INCREASE: anything larger than one inner
        // allocation step is grown afterwards.
        let allocated = space.min(MAX_PERMITTED_DATA_INCREASE);
        system_program::create_account(
            CpiContext::new_with_signer(
                system_program::ID,
                system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: value.clone(),
                },
                &[seeds],
            ),
            Rent::get()?.minimum_balance(allocated),
            allocated as u64,
            ctx.program_id,
        )?;

        let header = Header::fresh(
            &params,
            ctx.accounts.payer.key().to_bytes(),
            bump,
            Clock::get()?.slot,
        );
        let mut data = value.try_borrow_mut_data()?;
        account::write_header(&mut data, &header).map_err(map_fhe)?;

        emit!(ValueCreated {
            value: value.key(),
            param_id,
            blob_len: params.blob_len() as u32,
            slots: params.slot_capacity() as u32,
        });
        Ok(())
    }

    /// Grow a value account towards the size its ciphertext needs.
    ///
    /// Called repeatedly by the client, one allocation step at a time, because
    /// that is the only way the runtime allows an account this large to come
    /// into existence. The step is enforced by the runtime, not by this program.
    pub fn grow_value(ctx: Context<GrowValue>, index: u64, new_len: u32) -> Result<()> {
        let value = ctx.accounts.value.to_account_info();
        let _ = index;

        let header = {
            let data = value.try_borrow_data()?;
            account::read_header(&data).map_err(map_fhe)?
        };
        let params = params_of(&header)?;

        let target = account::account_len(&params);
        let requested = new_len as usize;
        require!(requested <= target, VaultError::ChunkOutOfRange);

        let current = value.data_len();
        require!(requested >= current, VaultError::AlreadyInitialized);
        require!(
            requested - current <= MAX_PERMITTED_DATA_INCREASE,
            VaultError::AllocationStepTooLarge
        );

        // Keep the account rent exempt as it grows, then resize it.
        let shortfall = Rent::get()?
            .minimum_balance(requested)
            .saturating_sub(value.lamports());
        if shortfall > 0 {
            system_program::transfer(
                CpiContext::new(
                    system_program::ID,
                    system_program::Transfer {
                        from: ctx.accounts.payer.to_account_info(),
                        to: value.clone(),
                    },
                ),
                shortfall,
            )?;
        }
        value.resize(requested)?;

        emit!(ValueGrown {
            value: value.key(),
            len: requested as u32,
            target: target as u32,
        });
        Ok(())
    }

    /// Write a chunk of the ciphertext into its account.
    ///
    /// A standard tier ciphertext is 32 KiB and a legacy transaction carries
    /// about 1.2 KiB, so this is not an optimisation, it is the only way to get
    /// the bytes on chain.
    pub fn write_chunk(ctx: Context<WriteValue>, offset: u32, data: Vec<u8>) -> Result<()> {
        let info = ctx.accounts.value.to_account_info();
        let mut account_data = info.try_borrow_mut_data()?;
        let header = account::read_header(&account_data).map_err(map_fhe)?;
        require!(
            header.owner == ctx.accounts.writer.key().to_bytes(),
            VaultError::NotOwner
        );

        let start = HEADER_LEN + offset as usize;
        let end = start + data.len();
        let blob_end = HEADER_LEN + header.blob_len as usize;
        require!(end <= blob_end, VaultError::ChunkOutOfRange);

        account_data[start..end].copy_from_slice(&data);

        let mut updated = header;
        updated.written = updated.written.max(offset + data.len() as u32);
        account::write_header(&mut account_data, &updated).map_err(map_fhe)?;

        emit!(ValueWritten {
            value: info.key(),
            written: updated.written,
            blob_len: updated.blob_len,
        });
        Ok(())
    }

    /// `out = a + b`, computed on chain, coefficient by coefficient.
    ///
    /// The two inputs may belong to anyone, because nothing about them is
    /// signed for. `out` must be a fresh account created by [`create_value`].
    pub fn homomorphic_add(ctx: Context<HomomorphicAdd>) -> Result<()> {
        let a_info = ctx.accounts.a.to_account_info();
        let b_info = ctx.accounts.b.to_account_info();
        let out_info = ctx.accounts.out.to_account_info();

        require_keys_neq!(a_info.key(), b_info.key(), VaultError::AliasedAccounts);
        require_keys_neq!(out_info.key(), a_info.key(), VaultError::AliasedAccounts);
        require_keys_neq!(out_info.key(), b_info.key(), VaultError::AliasedAccounts);
        for info in [&a_info, &b_info, &out_info] {
            require_keys_eq!(*info.owner, *ctx.program_id, VaultError::NotAValueAccount);
        }

        let a_data = a_info.try_borrow_data()?;
        let b_data = b_info.try_borrow_data()?;
        let a_header = account::read_header(&a_data).map_err(map_fhe)?;
        let b_header = account::read_header(&b_data).map_err(map_fhe)?;

        require_eq!(
            a_header.param_id,
            b_header.param_id,
            VaultError::ParameterMismatch
        );
        let params = params_of(&a_header)?;
        require!(
            a_header.written == a_header.blob_len && b_header.written == b_header.blob_len,
            VaultError::IncompleteCiphertext
        );

        let a_blob = account::blob(&a_data).map_err(map_fhe)?;
        let b_blob = account::blob(&b_data).map_err(map_fhe)?;

        let bound = noise::add_bound(a_header.noise_bound, b_header.noise_bound);
        require!(
            noise::is_decryptable(&params, bound),
            VaultError::NoiseBudgetExhausted
        );

        let mut out_data = out_info.try_borrow_mut_data()?;
        let out_header = account::read_header(&out_data).map_err(map_fhe)?;
        require!(
            out_header.written == 0 && out_header.depth == 0,
            VaultError::OutputNotEmpty
        );
        require_eq!(
            out_header.param_id,
            a_header.param_id,
            VaultError::ParameterMismatch
        );
        require!(
            out_header.owner == ctx.accounts.payer.key().to_bytes(),
            VaultError::NotOwner
        );

        let out_blob = account::blob_mut(&mut out_data).map_err(map_fhe)?;
        ops::add(&params, a_blob, b_blob, out_blob).map_err(map_fhe)?;

        let mut updated = out_header;
        updated.depth = a_header.depth.max(b_header.depth) + 1;
        updated.noise_bound = bound;
        updated.written = updated.blob_len;
        updated.parent_a = a_info.key().to_bytes();
        updated.parent_b = b_info.key().to_bytes();
        account::write_header(&mut out_data, &updated).map_err(map_fhe)?;

        emit!(OperationApplied {
            out: out_info.key(),
            op: OP_ADD,
            depth: updated.depth,
            noise_bound: updated.noise_bound,
            noise_bits: noise::budget_bits(&params, updated.noise_bound),
        });
        Ok(())
    }

    /// `out = k * a` for a public scalar `k`, computed on chain.
    pub fn scalar_mul(ctx: Context<ScalarMul>, k: u64) -> Result<()> {
        let a_info = ctx.accounts.a.to_account_info();
        let out_info = ctx.accounts.out.to_account_info();

        require_keys_neq!(out_info.key(), a_info.key(), VaultError::AliasedAccounts);
        for info in [&a_info, &out_info] {
            require_keys_eq!(*info.owner, *ctx.program_id, VaultError::NotAValueAccount);
        }

        let a_data = a_info.try_borrow_data()?;
        let a_header = account::read_header(&a_data).map_err(map_fhe)?;
        let params = params_of(&a_header)?;
        require!(
            a_header.written == a_header.blob_len,
            VaultError::IncompleteCiphertext
        );

        let bound = noise::scalar_mul_bound(a_header.noise_bound, k);
        require!(
            noise::is_decryptable(&params, bound),
            VaultError::NoiseBudgetExhausted
        );

        let a_blob = account::blob(&a_data).map_err(map_fhe)?;

        let mut out_data = out_info.try_borrow_mut_data()?;
        let out_header = account::read_header(&out_data).map_err(map_fhe)?;
        require!(
            out_header.written == 0 && out_header.depth == 0,
            VaultError::OutputNotEmpty
        );
        require_eq!(
            out_header.param_id,
            a_header.param_id,
            VaultError::ParameterMismatch
        );
        require!(
            out_header.owner == ctx.accounts.payer.key().to_bytes(),
            VaultError::NotOwner
        );

        let out_blob = account::blob_mut(&mut out_data).map_err(map_fhe)?;
        ops::scalar_mul(&params, k, a_blob, out_blob).map_err(map_fhe)?;

        let mut updated = out_header;
        updated.depth = a_header.depth + 1;
        updated.noise_bound = bound;
        updated.written = updated.blob_len;
        updated.parent_a = a_info.key().to_bytes();
        account::write_header(&mut out_data, &updated).map_err(map_fhe)?;

        emit!(OperationApplied {
            out: out_info.key(),
            op: OP_SCALAR_MUL,
            depth: updated.depth,
            noise_bound: updated.noise_bound,
            noise_bits: noise::budget_bits(&params, updated.noise_bound),
        });
        Ok(())
    }

    /// Record a result produced off chain, by the full FHE engine.
    ///
    /// This is the seam between the tiers. The program cannot verify the
    /// computation, and does not pretend to: it records a digest, the scheme
    /// that produced it, and the depth, so anyone can see what was claimed and
    /// check it against the off-chain engine themselves.
    pub fn commit_evaluation(
        ctx: Context<CommitEvaluation>,
        index: u64,
        digest: [u8; 32],
        depth: u16,
        noise_bits: u16,
    ) -> Result<()> {
        let record = &mut ctx.accounts.record;
        record.author = ctx.accounts.author.key();
        record.index = index;
        record.scheme = SCHEME_SEAL_BFV;
        record.depth = depth;
        record.noise_bits = noise_bits;
        record.slot = Clock::get()?.slot;
        record.digest = digest;

        emit!(EvaluationCommitted {
            record: record.key(),
            scheme: record.scheme,
            depth,
            noise_bits,
            digest,
        });
        Ok(())
    }
}

fn params_of(header: &Header) -> Result<Params> {
    Params::from_id(header.param_id).ok_or(VaultError::UnknownParameterSet.into())
}

fn map_fhe(error: FheError) -> anchor_lang::error::Error {
    match error {
        FheError::UnknownParameterSet(_) => VaultError::UnknownParameterSet.into(),
        FheError::WrongMagic | FheError::UnsupportedVersion(_) | FheError::WrongLength { .. } => {
            VaultError::NotAValueAccount.into()
        }
        FheError::CoefficientOutOfRange { .. } => VaultError::AccountNotReduced.into(),
        FheError::ScalarOutOfRange { .. } => VaultError::ScalarOutOfRange.into(),
        FheError::NoiseBudgetExceeded { .. } => VaultError::NoiseBudgetExhausted.into(),
    }
}

/// Create one empty ciphertext account.
#[derive(Accounts)]
#[instruction(param_id: u8, index: u64)]
pub struct CreateValue<'info> {
    /// Pays for the account.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// The value account, a PDA of this program.
    /// CHECK: created below, and the seeds constraint pins the address.
    #[account(
        mut,
        seeds = [VALUE_SEED, payer.key().as_ref(), &index.to_le_bytes()],
        bump,
    )]
    pub value: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// Grow a value account by one allocation step.
///
/// The runtime, not this program, is what limits the step to
/// [`MAX_PERMITTED_DATA_INCREASE`]. The client calls this until the account is
/// large enough for its ciphertext.
///
/// The resize is done in the instruction body rather than through Anchor's
/// `realloc` constraint, because that constraint only accepts typed accounts and
/// a value account is a raw layout this kit defines.
#[derive(Accounts)]
#[instruction(index: u64, new_len: u32)]
pub struct GrowValue<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: owned by this program; the header is checked inside, and the
    /// account is resized in the instruction body.
    #[account(
        mut,
        seeds = [VALUE_SEED, payer.key().as_ref(), &index.to_le_bytes()],
        bump,
    )]
    pub value: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// Upload a chunk of an existing ciphertext.
#[derive(Accounts)]
pub struct WriteValue<'info> {
    pub writer: Signer<'info>,
    /// CHECK: checked inside the instruction. Owned by this program, carries the
    /// magic, and its owner field is compared against the signer.
    #[account(mut)]
    pub value: UncheckedAccount<'info>,
}

/// Add two ciphertexts into a third.
#[derive(Accounts)]
pub struct HomomorphicAdd<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: validated inside; any value account of this program may be an input.
    pub a: UncheckedAccount<'info>,
    /// CHECK: as above.
    pub b: UncheckedAccount<'info>,
    /// CHECK: the destination, validated inside: owned by this program, owned by
    /// the payer, and still empty.
    #[account(mut)]
    pub out: UncheckedAccount<'info>,
}

/// Scale one ciphertext by a public constant.
#[derive(Accounts)]
pub struct ScalarMul<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: validated inside.
    pub a: UncheckedAccount<'info>,
    /// CHECK: the destination, validated inside as for [`HomomorphicAdd`].
    #[account(mut)]
    pub out: UncheckedAccount<'info>,
}

/// Record an off-chain evaluation.
#[derive(Accounts)]
#[instruction(index: u64)]
pub struct CommitEvaluation<'info> {
    #[account(mut)]
    pub author: Signer<'info>,
    #[account(
        init,
        payer = author,
        space = 8 + EvaluationRecord::INIT_SPACE,
        seeds = [EVALUATION_SEED, author.key().as_ref(), &index.to_le_bytes()],
        bump,
    )]
    pub record: Account<'info, EvaluationRecord>,
    pub system_program: Program<'info, System>,
}

/// A digest of a result computed by the off-chain engine.
#[account]
#[derive(InitSpace)]
pub struct EvaluationRecord {
    pub author: Pubkey,
    pub index: u64,
    pub scheme: u8,
    pub depth: u16,
    pub noise_bits: u16,
    pub slot: u64,
    pub digest: [u8; 32],
}

#[event]
pub struct ValueCreated {
    pub value: Pubkey,
    pub param_id: u8,
    pub blob_len: u32,
    pub slots: u32,
}

#[event]
pub struct ValueWritten {
    pub value: Pubkey,
    pub written: u32,
    pub blob_len: u32,
}

#[event]
pub struct ValueGrown {
    pub value: Pubkey,
    pub len: u32,
    pub target: u32,
}

#[event]
pub struct OperationApplied {
    pub out: Pubkey,
    pub op: u8,
    pub depth: u16,
    pub noise_bound: u64,
    pub noise_bits: u32,
}

#[event]
pub struct EvaluationCommitted {
    pub record: Pubkey,
    pub scheme: u8,
    pub depth: u16,
    pub noise_bits: u16,
    pub digest: [u8; 32],
}

#[error_code]
pub enum VaultError {
    #[msg("the parameter set id is not one this kit ships")]
    UnknownParameterSet,
    #[msg("the account is not a value account created by this program")]
    NotAValueAccount,
    #[msg("the account already exists")]
    AlreadyInitialized,
    #[msg("the ciphertext has not been fully uploaded")]
    IncompleteCiphertext,
    #[msg("the two ciphertexts use different parameter sets")]
    ParameterMismatch,
    #[msg("the output account already holds a ciphertext")]
    OutputNotEmpty,
    #[msg("the accounts must be distinct")]
    AliasedAccounts,
    #[msg("the operation would exhaust the noise budget")]
    NoiseBudgetExhausted,
    #[msg("the chunk falls outside the ciphertext")]
    ChunkOutOfRange,
    #[msg("the allocation step is larger than the runtime permits")]
    AllocationStepTooLarge,
    #[msg("only the account owner may write to this value")]
    NotOwner,
    #[msg("a coefficient in the account is not reduced modulo q")]
    AccountNotReduced,
    #[msg("the scalar is not reduced modulo q")]
    ScalarOutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_program_id_is_a_real_public_key() {
        // Fails loudly if `declare_id!` was left as a placeholder.
        assert!(!ID.to_string().contains("1111111111"));
    }

    #[test]
    fn the_account_layout_matches_what_the_client_hard_codes() {
        // The TypeScript client hard codes the 136 byte value header and the
        // 85 byte evaluation record. Both are asserted here and again in
        // `fhe-core`, so a field cannot be added without a failing test.
        assert_eq!(HEADER_LEN, 136);
        assert_eq!(EvaluationRecord::INIT_SPACE, 85);
    }
}
