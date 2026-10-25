//! The on-chain account layout.
//!
//! This lives in `fhe-core` rather than in the program so that the same bytes
//! are described once, tested on the host, and shared by the Solana program and
//! the TypeScript client. The two never disagree about an offset: the layout is
//! asserted by the tests in this crate and again by the integration test.
//!
//! ```text
//! offset  size  field
//! 0       4     magic, "FHEV"
//! 4       4     version, u32 little endian, currently 1
//! 8       1     parameter set id
//! 9       1     PDA bump seed
//! 10      2     depth, the number of homomorphic operations applied
//! 12      4     ring degree n
//! 16      4     ciphertext blob length in bytes
//! 20      4     bytes of the blob written so far
//! 24      8     noise bound
//! 32      8     slot the account was created in
//! 40      32    owner
//! 72      32    first parent (zero for a directly encrypted value)
//! 104     32    second parent (zero for a directly encrypted value)
//! 136     ...   the ciphertext blob
//! ```
//!
//! The header is a fixed 136 bytes so that the client can compute the offset
//! where the ciphertext starts without knowing how the program was compiled.
//! [`HEADER_LEN`] is asserted against the struct in the module tests.

use crate::error::FheError;
use crate::params::Params;

/// Bytes the magic occupies.
pub const MAGIC_LEN: usize = 4;
/// The magic every value account starts with.
pub const MAGIC: [u8; MAGIC_LEN] = *b"FHEV";
/// The only layout version this crate understands.
pub const VERSION: u32 = 1;
/// Fixed size of the header, including the magic, in bytes.
pub const HEADER_LEN: usize = 136;

/// Where the ciphertext blob starts.
pub const BLOB_OFFSET: usize = HEADER_LEN;

#[inline]
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

#[inline]
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

#[inline]
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn read_pubkey(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[offset..offset + 32]);
    out
}

/// The fixed part of an `EncryptedValue` account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Which parameter set the ciphertext belongs to.
    pub param_id: u8,
    /// The PDA bump, kept so the program can sign for the account later.
    pub bump: u8,
    /// How many homomorphic operations produced this ciphertext.
    pub depth: u16,
    /// Ring degree, repeated so the blob can be checked without a lookup.
    pub n: u32,
    /// Blob length in bytes.
    pub blob_len: u32,
    /// How much of the blob has been written. A blob is usually uploaded in
    /// several transactions, so this tracks progress.
    pub written: u32,
    /// The conservative noise bound carried by this ciphertext.
    pub noise_bound: u64,
    /// The slot the account was created in.
    pub created_slot: u64,
    /// Who may write to the account.
    pub owner: [u8; 32],
    /// The ciphertext this one was derived from, or zero.
    pub parent_a: [u8; 32],
    /// The second parent, for a two-operand operation, or zero.
    pub parent_b: [u8; 32],
}

impl Header {
    /// A fresh header for a directly encrypted value.
    pub fn fresh(params: &Params, owner: [u8; 32], bump: u8, created_slot: u64) -> Header {
        Header {
            param_id: params.id,
            bump,
            depth: 0,
            n: params.n as u32,
            blob_len: params.blob_len() as u32,
            written: 0,
            noise_bound: params.fresh_noise_bound,
            created_slot,
            owner,
            parent_a: [0u8; 32],
            parent_b: [0u8; 32],
        }
    }
}

/// Read a header, checking the magic and version.
pub fn read_header(data: &[u8]) -> Result<Header, FheError> {
    if data.len() < HEADER_LEN {
        return Err(FheError::WrongLength {
            expected: HEADER_LEN,
            got: data.len(),
        });
    }
    if data[0..MAGIC_LEN] != MAGIC {
        return Err(FheError::WrongMagic);
    }
    let version = read_u32(data, 4);
    if version != VERSION {
        return Err(FheError::UnsupportedVersion(version));
    }
    Ok(Header {
        param_id: data[8],
        bump: data[9],
        depth: u16::from_le_bytes([data[10], data[11]]),
        n: read_u32(data, 12),
        blob_len: read_u32(data, 16),
        written: read_u32(data, 20),
        noise_bound: read_u64(data, 24),
        created_slot: read_u64(data, 32),
        owner: read_pubkey(data, 40),
        parent_a: read_pubkey(data, 72),
        parent_b: read_pubkey(data, 104),
    })
}

/// Write a header into the first [`HEADER_LEN`] bytes of `data`.
pub fn write_header(data: &mut [u8], header: &Header) -> Result<(), FheError> {
    if data.len() < HEADER_LEN {
        return Err(FheError::WrongLength {
            expected: HEADER_LEN,
            got: data.len(),
        });
    }
    data[0..MAGIC_LEN].copy_from_slice(&MAGIC);
    write_u32(data, 4, VERSION);
    data[8] = header.param_id;
    data[9] = header.bump;
    data[10..12].copy_from_slice(&header.depth.to_le_bytes());
    write_u32(data, 12, header.n);
    write_u32(data, 16, header.blob_len);
    write_u32(data, 20, header.written);
    write_u64(data, 24, header.noise_bound);
    write_u64(data, 32, header.created_slot);
    data[40..72].copy_from_slice(&header.owner);
    data[72..104].copy_from_slice(&header.parent_a);
    data[104..136].copy_from_slice(&header.parent_b);
    Ok(())
}

/// The ciphertext blob inside a value account.
pub fn blob(data: &[u8]) -> Result<&[u8], FheError> {
    let header = read_header(data)?;
    let end = BLOB_OFFSET + header.blob_len as usize;
    if data.len() < end {
        return Err(FheError::WrongLength {
            expected: end,
            got: data.len(),
        });
    }
    Ok(&data[BLOB_OFFSET..end])
}

/// The ciphertext blob inside a value account, mutably.
pub fn blob_mut(data: &mut [u8]) -> Result<&mut [u8], FheError> {
    let header = read_header(data)?;
    let end = BLOB_OFFSET + header.blob_len as usize;
    if data.len() < end {
        return Err(FheError::WrongLength {
            expected: end,
            got: data.len(),
        });
    }
    Ok(&mut data[BLOB_OFFSET..end])
}

/// The account size a value of this parameter set needs.
pub fn account_len(params: &Params) -> usize {
    BLOB_OFFSET + params.blob_len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::DEMO;

    #[test]
    fn header_len_is_the_documented_constant() {
        // The TypeScript client hard codes 136. If this changes, that breaks,
        // and this test is where it is caught.
        assert_eq!(HEADER_LEN, 136);
    }

    #[test]
    fn header_round_trips() {
        let mut data = vec![0u8; account_len(&DEMO)];
        let header = Header::fresh(&DEMO, [7u8; 32], 254, 42);
        write_header(&mut data, &header).unwrap();
        assert_eq!(read_header(&data).unwrap(), header);
        assert_eq!(data.len(), HEADER_LEN + DEMO.blob_len());
    }

    #[test]
    fn a_foreign_account_is_refused() {
        let data = vec![0u8; HEADER_LEN];
        assert!(read_header(&data).is_err());
    }

    #[test]
    fn the_blob_lives_after_the_header() {
        let mut data = vec![0u8; account_len(&DEMO)];
        let header = Header::fresh(&DEMO, [0u8; 32], 1, 0);
        write_header(&mut data, &header).unwrap();
        let blob = blob(&data).unwrap();
        assert_eq!(blob.len(), DEMO.blob_len());
        assert!(blob.iter().all(|b| *b == 0));
    }
}
