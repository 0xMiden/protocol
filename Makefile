.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables --------------------------------------------------------------------------------------

WARNINGS=RUSTDOCFLAGS="-D warnings"
# Enable backtraces for tests where we return an anyhow::Result. If enabled, anyhow::Error will
# then contain a `Backtrace` and print it when a test returns an error.
BACKTRACE=RUST_BACKTRACE=1

# -- linting --------------------------------------------------------------------------------------

.PHONY: clippy
clippy: ## Runs Clippy with configs
	cargo clippy --workspace --all-targets --all-features -- -D warnings


.PHONY: clippy-no-std
clippy-no-std: ## Runs Clippy with configs
	cargo clippy --no-default-features --target wasm32-unknown-unknown --workspace --lib -- -D warnings


.PHONY: fix
fix: ## Runs Fix with configs
	cargo fix --workspace --allow-staged --allow-dirty --all-targets --all-features


.PHONY: format
format: ## Runs Format using nightly toolchain
	cargo +nightly fmt --all


.PHONY: format-check
format-check: ## Runs Format using nightly toolchain but only in check mode
	cargo +nightly fmt --all --check

.PHONY: shear
shear: ## Runs cargo-shear to find unused or misplaced dependencies
	cargo shear

.PHONY: typos-check
typos-check: ## Runs spellchecker
	typos

.PHONY: toml
toml: ## Runs Format for all TOML files
	taplo fmt

.PHONY: toml-check
toml-check: ## Runs Format for all TOML files but only in check mode
	taplo fmt --check

.PHONY: lint
lint: ## Runs all linting tasks at once (Clippy, fixing, formatting, typos)
	@$(MAKE) format
	@$(MAKE) fix
	@$(MAKE) clippy
	@$(MAKE) clippy-no-std
	@$(MAKE) typos-check
	@$(MAKE) toml
	@$(MAKE) shear

.PHONY: hooks-test
hooks-test: ## Runs the pytest suite for the python hooks under .claude/hooks/
	python3 -m pytest .claude/hooks/tests/

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generates & checks documentation
	$(WARNINGS) cargo doc --all-features --keep-going --release


.PHONY: serve-docs
serve-docs: ## Serves the docs
	cd docs && npm run start:dev

# --- testing -------------------------------------------------------------------------------------

.PHONY: test-release-build
test-release-build: ## Build the test binary
	cargo nextest run --cargo-profile test-dev --no-default-features --features concurrent,testing,std --no-run


# Run all tests without debug mode. This is fast but produces worse error message.
# Running `make test-release name=test_name` will only run the test `test_name`.
.PHONY: test-release
test-release:
	$(BACKTRACE) cargo nextest run --profile default --cargo-profile test-dev --no-default-features --features concurrent,testing,std $(name)

# Shorthand for make test-release.
.PHONY: test-release testr
testr: test-release

# Run all tests with debug mode. This is slower but produces better error message.
# Running `make test name=test_name` will only run the test `test_name`.
.PHONY: test
test:
	$(BACKTRACE) cargo nextest run --profile default --cargo-profile test-dev --features concurrent,testing,std $(name)


# Run all tests except the proving tests (imperfectly filtered based on name) with debug mode.
# This uses the std feature to be able to load the MASM source files back into the assembler
# source manager (see `source_manager_ext::load_masm_source_files`).
.PHONY: test-dev
test-dev: ## Run default tests excluding slow prove tests in debug mode intended to be run locally
	$(BACKTRACE) cargo nextest run --profile default --cargo-profile test-dev --features concurrent,testing,std --filter-expr "not test(prove)"


.PHONY: test-docs
test-docs: ## Run documentation tests
	$(WARNINGS) cargo test --doc


# --- checking ------------------------------------------------------------------------------------

.PHONY: check
check: ## Check all targets and features for errors without code generation
	cargo check --all-targets --all-features


.PHONY: check-no-std
check-no-std: ## Check the no-std target without any features for errors without code generation
	cargo check --no-default-features --target wasm32-unknown-unknown --workspace --lib


.PHONY: check-features
check-features: ## Checks all feature combinations compile without warnings using cargo-hack
	@scripts/check-features.sh


.PHONY: check-crates-published
check-crates-published: ## Checks every publishable workspace member already exists on crates.io
	@scripts/check-crates-published.sh


# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## By default we should build in release mode
	cargo build --release


.PHONY: build-no-std
build-no-std: ## Build without the standard library
	cargo build --no-default-features --target wasm32-unknown-unknown --workspace --lib


.PHONY: build-no-std-testing
build-no-std-testing: ## Build without the standard library. Includes the `testing` feature
	cargo build --no-default-features --target wasm32-unknown-unknown --workspace --exclude bench-transaction --features testing

# --- test vectors --------------------------------------------------------------------------------

.PHONY: generate-solidity-test-vectors
generate-solidity-test-vectors: ## Regenerate Solidity test vectors using Foundry
	cd crates/miden-agglayer/solidity-compat && forge test -vv --match-test test_generateCanonicalZeros
	cd crates/miden-agglayer/solidity-compat && forge test -vv --match-test test_generateClaimAssetVectors
	cd crates/miden-agglayer/solidity-compat && forge test -vv --match-test test_generateLeafValueVectors
	cd crates/miden-agglayer/solidity-compat && forge test -vv --match-test test_generateVerificationProofData
	cd crates/miden-agglayer/solidity-compat && forge test -vv --match-test test_generate_MTF_vectors
	cd crates/miden-agglayer/solidity-compat && forge test -vv --match-test test_generateExitRootVectors

# --- benchmarking --------------------------------------------------------------------------------

.PHONY: bench-tx
bench-tx: ## Run transaction benchmarks
	cargo run --bin bench-transaction --features concurrent
	cargo bench --bin bench-transaction --bench time_counting_benchmarks --features concurrent

.PHONY: bench-note-checker
bench-note-checker: ## Run note checker benchmarks
	cargo bench --bin bench-note-checker --bench benches

.PHONY: update-note-costs
update-note-costs: ## Regenerate bench-tx.json and the checked-in note consumption cost tables
	cargo run --bin bench-transaction --features concurrent -- update-note-costs
	cargo +nightly fmt -p miden-standards -p miden-agglayer

# --- installing ----------------------------------------------------------------------------------

.PHONY: check-tools
check-tools: ## Checks if development tools are installed
	@echo "Checking development tools..."
	@command -v npm >/dev/null 2>&1 && echo "[OK] npm is installed" || echo "[MISSING] npm is not installed (run: make install-tools)"
	@command -v typos >/dev/null 2>&1 && echo "[OK] typos is installed" || echo "[MISSING] typos is not installed (run: make install-tools)"
	@command -v cargo nextest >/dev/null 2>&1 && echo "[OK] cargo-nextest is installed" || echo "[MISSING] cargo-nextest is not installed (run: make install-tools)"
	@command -v taplo >/dev/null 2>&1 && echo "[OK] taplo is installed" || echo "[MISSING] taplo is not installed (run: make install-tools)"
	@command -v cargo-shear >/dev/null 2>&1 && echo "[OK] cargo-shear is installed" || echo "[MISSING] cargo-shear is not installed (run: make install-tools)"

.PHONY: install-tools
install-tools: ## Installs development tools required by the Makefile (mdbook, typos, nextest, taplo, shear)
	@echo "Installing development tools..."
	@if ! command -v node >/dev/null 2>&1; then \
		echo "Node.js not found. Please install Node.js from https://nodejs.org/ or using your package manager"; \
		echo "On macOS: brew install node"; \
		echo "On Ubuntu/Debian: sudo apt install nodejs npm"; \
		echo "On Windows: Download from https://nodejs.org/"; \
		exit 1; \
	fi
	cargo install typos-cli --locked
	cargo install cargo-nextest --locked
	cargo install taplo-cli --locked
	cargo install cargo-shear --locked
	@echo "Development tools installation complete!"

# -- documentation ---------------------------------------------------------------------------------

AGGLAYER_DIAGRAMS_DIR := crates/miden-agglayer/diagrams
EXCALIDRAW_SOURCES := $(wildcard $(AGGLAYER_DIAGRAMS_DIR)/*.excalidraw)
EXCALIDRAW_PNGS := $(EXCALIDRAW_SOURCES:.excalidraw=.png)

.PHONY: agglayer-spec
agglayer-spec: $(EXCALIDRAW_PNGS) ## Exports AggLayer spec diagrams from .excalidraw to .png

$(AGGLAYER_DIAGRAMS_DIR)/%.png: $(AGGLAYER_DIAGRAMS_DIR)/%.excalidraw
	@command -v npx >/dev/null 2>&1 || { echo "npx not found. Install Node.js first."; exit 1; }
	npx excalidraw-brute-export-cli -i $< --format png -o $@ --scale 2
