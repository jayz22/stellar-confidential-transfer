use soroban_sdk::BytesN;

pub const AMOUNT_CHUNKS: u64 = 4;
pub const BALANCE_CHUNKS: u64 = 8;
pub const CHUNK_SIZE_BITS: u64 = 16;

#[derive(Debug, Clone)]
pub struct CompressedRistretto(BytesN<32>);

#[derive(Debug, Clone)]
pub struct EncryptedChunk
{
    pub amount: CompressedRistretto, // C
    pub handle: CompressedRistretto, // D
}

#[derive(Debug, Clone)]
pub struct ConfidentialAmount(Vec<EncryptedChunk>); // 4 chunks
#[derive(Debug, Clone)]
pub struct ConfidentialBalance(Vec<EncryptedChunk>); // 8 chunks

impl ConfidentialAmount {
    pub fn new_amount_with_no_randomness(amount: u64) -> Self {
        todo!()
    } 
}

impl ConfidentialBalance {
    pub fn new_balance_with_no_randomness(amount: u64) -> Self {
        todo!()
    } 
}

/// Splits a 64-bit integer amount into four 16-bit chunks, represented as `Scalar` values.
pub fn split_into_chunks_u64(amount: u64) -> Vec<Scalar> {
    (0..AMOUNT_CHUNKS).map(|i| {
        let chunk = (amount >> (i * CHUNK_SIZE_BITS)) & 0xffff;
        new_scalar_from_u64(chunk)
    }).collect()
}
