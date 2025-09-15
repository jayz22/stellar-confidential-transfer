.PHONY: all build install clean test

# Build all packages and install binaries
all: build install

# Build all packages
build:
	@echo "Building crypto package..."
	@cd crypto && cargo build --release
	@echo "Building client package..."
	@cd client && make build
	@echo "Building token contract..."
	@cd contracts/token && make build
	@echo "Building demo binary..."
	@cd contracts/token && make build-demo
	@echo "✅ All packages built successfully"

# Install client and demo binaries
install:
	@echo "Installing client binary..."
	@cd client && make install
	@echo "Installing demo binary..."
	@cd contracts/token && make install
	@echo "✅ Binaries installed:"
	@ls -ltr ~/.cargo/bin/conf-token-client
	@ls -ltr ~/.cargo/bin/conf-token-demo
	
# Run all tests
test:
	@echo "Testing crypto package..."
	@cd crypto && cargo test
	@echo "Testing client package..."
	@cd client && make test
	@echo "Testing token contract..."
	@cd contracts/token && make test
	@echo "✅ All tests passed"

# Clean all build artifacts
clean:
	@echo "Cleaning crypto package..."
	@cd crypto && cargo clean
	@echo "Cleaning client package..."
	@cd client && make clean
	@echo "Cleaning token contract..."
	@cd contracts/token && make clean
	@echo "✅ All build artifacts cleaned"

# Show help
help:
	@echo "Available targets:"
	@echo "  make all      - Build all packages and install binaries"
	@echo "  make build    - Build all packages"
	@echo "  make install  - Install client and demo binaries"
	@echo "  make test     - Run all tests"
	@echo "  make clean    - Clean all build artifacts"
	@echo "  make help     - Show this help message"