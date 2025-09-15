.PHONY: build install test clean

# Build the project in release mode
build:
	cargo build --release

# Install the binary (runs build first)
install: build
	cargo install --path .

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean