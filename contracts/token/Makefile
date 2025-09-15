default: build

all: test

test: build
	cargo test

build:
	stellar contract build
	mkdir -p opt/
	stellar contract optimize \
		--wasm ../../target/wasm32v1-none/release/confidential_token.wasm \
		--wasm-out opt/confidential_token.wasm
	@ls -l opt/*.wasm

build-demo:
	cargo build --features demo --release --bin conf-token-demo

install: build-demo
	cargo install --path . --bin conf-token-demo --features demo
	@echo "✅ Installed conf-token-demo binary"

fmt:
	cargo fmt --all

clean:
	cargo clean

.PHONY: default all test build build-demo install fmt clean
