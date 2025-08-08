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

fmt:
	cargo fmt --all

clean:
	cargo clean
