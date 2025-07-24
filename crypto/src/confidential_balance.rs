use soroban_sdk::BytesN;


const AMOUNT_CHUNKS: u64 = 4;
const BALANCE_CHUNKS: u64 = 8;
const CHUNK_SIZE_BITS: u64 = 16;

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


