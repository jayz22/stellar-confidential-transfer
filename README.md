# Stellar Confidential Transfer

A token contract implementation that enables confidential transfers with zero-knowledge proofs while maintaining auditability.

## Project Structure
- **`contracts/token`**: Soroban smart contract implementing confidential token operations
- **`client`**: CLI tool for key management, proof generation, and contract interaction
- **`crypto`**: Cryptographic library that implements the internal data structure with ElGamal encryption, and the proof system.

## Building


### Build All Components
```bash
cargo build --release
```

### Build Contract
```bash
cd contracts/token
make build
```

The optimized WASM contract will be located at `contracts/token/opt/confidential_token.wasm`

### Run Tests
```bash
cargo test
```

## Usage

### Interactive Demo
Experience the full confidential transfer workflow:
```bash
cd contracts/token
cargo run --bin demo --features demo
```

### Command-Line Client
Generate keys and interact with contracts:
```bash
cd client
cargo run --bin client -- --help
```

## Documentation
These are work-in-progress. 

- [`docs/design_doc.md`](docs/design_doc.md) - system design and requirements
- [`docs/method.md`](docs/method.md) - Cryptographic protocols and proof specifications

