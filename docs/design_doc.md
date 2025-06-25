# Soroban Confidential Token Design

# Requirements

- Implements SEP-41, can function as and interoperate with a standard token
- Confidentiality as an optional extention  
	- if enabled, has an additional "confidential account" extention with encrypted balance
	- able to transfer from encrypted balance to standard (transparent) balance
- Auditability
	- any encrypted transfer should be auditable by additional 3rd parties
	- proper events should be emitted
- usibility
	- avoid spamming to the confidential account
- computation efficiency
    - verification should be cheap and fast (~milli-seconds)
    - proving should be reasonably fast (~seconds)

## Secondary Goals - TODO: check with Nico's doc's requirements

# Token Design

## SEP-41

A confidential token implements functions in the SEP-41 token interface.

```rust
allowance(from: Address, spender: Address) -> i128
approve(from: Address, spender: Address, amount: i128, expiration_ledger: u32)
balance(id: Address) -> i128
transfer(from: Address, to: Address, amount: i128)
transfer_from(spender: Address, from: Address, to: Address, amount: i128)
burn(from: Address, amount: i128)
burn_from(spender: Address, from: Address, amount: i128)
decimals()-> u32
name()-> String
symbol()-> String
```

invoking these functions should make the token behave like a standard token on its transparent balance.   
E.g. calling `transfer_from` function transfers `amount` from `from` to `to`, consuming the allowance that `spender`  
has on `from`'s transparent balance, authorized by spender.

## Confidential Token Interface

### `deposit(from: Address, to: Address, amt: u64)`

- Loads the confidential extention from `from` and `to`, fail if either does not exist.  
- Subtracts `amt` from `from`'s regular (transparent) `balance`, fail if `balance` is less than `amt`.
- Loads the `pending_balance` from `to`. 
- Encrypt the `amt` using zero randomness (`r = 0`) into `encrypted_amt`, add the `encrypted_amt`to the `pending_balance`. 
- Increment the counter. If counter is larger than the maximum limit (`1e16`), error. 
- Because this step does not hide the balance, no specific actions for auditing is required. 

Note: If you want to have a hidden amount from the beginning, use the `transfer_confidential` function instead.

#### Events
`Event(token_id, from, to, amt)`

#### Proofs
None required.

#### Auditing
No new action needed.

**Additional Notes**: 
- In this step the deposit is *not* confidential yet. the `amt` passed in is transparent. Encryption is done with zero randomness, anyone can decrypt it by solving the discrete log. And if this is `to`'s first deposit, that means its initial balance is *not* confidential. If `to` already had a confidential balance as a result of a previous `transfer`, then this balance will be confidential, with the randomness coming from the previous `transfer` (sum of all previous randomness).
- The counter limit check can be done earlier. 
- The pending balance each chunk might overflow 16-bits, but we don't care, the max counter prevents it from overflowing 32-bits. (same works for `transfer`). The owner of `to` needs to perform a `apply_pending_balance` to make this into available balance (in order to to do a confidential transfer).


### `rollover_pending_balance(acc: Address, new_available_balance: EncryptedQuantity, proof: NormalizationProof)`

- Loads the confidential extention from `acc`, fail if not exist.  
- Loads the `pending_balance` and `available_balance`.
- Verifies the `proof`, against `new_available_balance`.
- Sets the `available_balance` to the `new_available_balance`. 
- Sets the `pending_balance` to zero (encrypte `amt=0` with randomness `r=0`). 
- Resets the pending balance counter to 0.

#### Events
TBD

#### Proofs
Proves that before and after normalization the same balance quanity is being encrypted *and* each chunk in the new balance encrypts a value that fits within the range ($0-2^{16}$)

It contains a Sigma proof and a range proof.
See [normalization-proof](./method.md#normalization-proof) for details.

### Auditing
the `new_available_balance` will be decryptable with auditor's keys, and the additional encryption handles needs to be included as part of the proof. 

### withdraw_from_confidential(acc: Address, amt: u64, proof: WithdrawProof)

- Loads `acc`'s confidential extention, fail if not exist.
- Verifies the `proof`. 
- Encrypt the `amt` with zero randomness (`r=0`) to get `encrypted_amt`.
- (homomorphically) Subtracts `encrypted_amt` from `acc`'s `available_balance`. 
- Adds `amt` to `acc`'s (transparent) balance.

#### Events
TBD

#### Proofs
A withdraw proof is needed. It contains a Sigma proof and a range proof. See [withdraw-proof](./method.md#withdraw-proof) for details.

#### Auditing
No new action needed.

### transfer_confidential(from: Address, to: Address, transfer_amt: EncryptedQuantity, proof: TransferProof)

- Loads confidential extentions from `from` and `to` addresses, fail if either extention does not exist.
- if `to`'s `pending_balance_counter` is at max (`10^16`), fail.
- Verifies the proof.
- (homomorphically) Subtracts `transfer_amt` from `from`'s `available_balance`.
- (homomorphically) Adds `transfer_amt` to `to`'s `pending_balance`.

#### Events
TBD

#### Proofs
A `TransferProof` is required, which proves a transfer amount is valid (does not underflow sender's balance or overflow receiver's) *and* the same transfer amount is correctly encrypted by all parties' public keys *and* the sender has the right secret key to decode its balance.

It contains a Sigma and a Range proof. See [transfer-proof](./method.md#transfer-proof) for details.

#### Auditing
the `transfer_amt` will be decryptable with auditor's keys, and the additional encryption handles needs to be included as part of the proof. 

## Data Model

### Encrypted data

```rust
#[contracttype]
pub struct ElGamalEncryptionKey(BytesN<32>);

// The quantities (amount and balance) are initially divided into fixed-length (16-bit) chunks
// and encrypted individually. Additional of quantities occur on each chunk individually, therefore
// the chunk can grow to be larger than 16-bits, but not exceeding 32-bits if the max addition
// counter is 2^16.
#[contracttype]
pub struct EncryptedChunk(BytesN<32>);
#[contracttype]
pub struct DecryptionHandle(BytesN<32>);

#[contracttype]
pub struct EncryptedQuantity {
    pub amount: Vec<EncryptedChunk>,
    pub handle: DecryptionHandle,
}
```
- Data (transfer amount and account balances) are encrypted with twisted ElGamal encryption over ristretto curve25519.
- The encryption key is 32 bytes.   
- The encrypted amount contains two parts, the `amount` and the `handle` both are 32 bytes.  
- The encrypted amount is additive homomorphic, i.e. `Enc(m1, r1) + Enc (m2, r2) = Enc(m1+m2, r1+r2)`.  
- The amount can only be decrypted by the decryption key matching the encryption key in the `DecryptionHandle`  
- If multiple addresses (sender, receiver and each auditor) need to be able to decrypt the amount, then decryption handle need to be constructed multiple times, each with a different encryption key.

See [twisted-elgamal-encryption](./method.md#twisted-elgamal-encryption) for more details.

### Confidential account extention

```rust
// This is the different types of keys for the token contract's storage. 
#[contracttype]
pub enum DataKey {
    ....
    Balance(Address), // this is the regular, transparent token balance
    ConfidentialAccountExt(Address), // extention for confidential token, identified by the normal Stellar address
}

#[contracttype]
pub struct ConfidentialAccountExt {
    pub encryption_key: ElGamalEncryptionKey,
    pub encrypted_available_balance: EncryptedQuantity,
    pub encrypted_pending_balance: EncryptedQuantity,
    pub pending_increment_counter: u32,
}
```

And the token contains metadata that includes all the auditor keys. 

```rust
pub struct ConfidentialTokenMetaData
{
    // list of auditors, must be specified when the token is instantiated.
    // all token transfer amounts will be additionally encrypted by each auditor key.
    pub auditors: Vec<ElGamalEncryptionKey>,
}
```

Another approach is to have the confidential token holding accounts to be contracts implementing a special interface, and stores its internal states. We can explore this route in the future.  

Note: 
- We check if an address has been enabled with confidential token extension via storage check, but we need to make sure the `ConfidentialTokenAccount` is not expired (restore/extend-ttl if necessary). Having the recepient as a contract address has the advantage to be able to use the instnace storage which has the same lifetime as the contract instance.

## Client Design

### `create_confidential_token_account`
- Try load the account's confidential extention, fail if already exists. 
- Generate a ElGamal key pair.
- Return the public key.

### `create_withdraw_proof`

generates the withdraw proof.

TODO: add steps.

### `create_transfer_proof`

generates the transfer proof.

TODO: add steps.

### `create_rollover_balance_proof`
- Try load the account's confidential extention, fail if doesn't exist.
- Loads the pending balance, this is an encrypted amount where each chunk can be up to 32 bits
- Homomorphically adds it to the available balance. After this step the new available balance each chuck can be up to 48-bits.
- Decrypt the available balance chunk by chunk, normalize it into an i128. 
- Divide the i128 into eight 16-bit chunks, generate a new randomness, encrypt each chunk and construct a new encrypted balance `EncryptedQuantity`. 
- Generate a Sigma proof and a range proof. Deserialize them into a `NormalizationProof`.
- Returns `{new_available_balance: EncryptedQuantity, proof: NormalizationProof}`

### `decrypt_quanity`

given a secret key and an encrypted quantity, decrypt it to get the value.

## Cryptographic primitives

Refer to [the method](./method.md) document.

## Additional Features (P1+)

close/pause/freeze confidential account

key rotation

token-level admin control, allow/black-list

extended auditing

## Discussions

### No explicit normalization
The `actual_balance` is split into chunks for efficient decryption. At the start, each chunk encodes 16-bits of the i128 balance. 

The `available_pending_balance` is refreshed each time with confidential transfer `amount` (`u64`), up to a maximum counter (`2^16`). Therefore the confidential pending balance can be divided into four 16-bit chunks, each chunk may extend to 32-bits, while the max pending balance can be 80-bits (`64+16`). 
When rolling over the pending balance, we add each chunk in the `available_pending_balance` to the `actual_balance`, and in the end, we normalize the `actual_balance` such that each chunk fits into 16-bits again. 

All other operations such as `transfer`, `withdraw` requires a freshly encrypted `actual_balance` as part of the proof, and that balance will be normalized implicitly. 

Therefore, there is no requirement to provide an explicit normalization function (along with need to validate a normalization proof). While this makes the `rollover_pending_balance` more complicated (requiring a proof on the new available balance), it overall simplifies the process because the available balance is always normalized before any operation.

### About the curve choice

Ristretto curve point can be compressed for storage, then decompressed for in-memory arithmetic operations. Our contract implementation should incorporate that.

Can we choose a different curve such as bls12-381? Yes but inefficient due to needing to solve DLP on 381 instead of 256 bit field  

Solana additionally encrypts the available balance using AES keys. For more efficient decryption (probably for web display?) but it's not part of the protocol and we will not incorporate it.


### Seperate decryption key per account, token?

Technically we might be able to use the same account key-pair for encryption/decryption for confidential transfer. However this is not a good practice.

Account keys are used for transaction signing, keeping it seperate from encryption keys is better for security (if one is compromised doesn't affect the other) and auditing (one might have to hand over the decryption key for auditing). Decryption key has view-only access, does not have signing privillage.

Seperate encryption/decryption key-pair for each token? It is better for security, but is not required. Our token design should have the flexibility allow both. 
