#!/bin/bash

set -euo pipefail

# Script to check all feature combinations compile without warnings
# This script ensures that warnings are treated as errors for CI

echo "Checking all feature combinations with cargo-hack..."

# Set environment variables to treat warnings as errors
export RUSTFLAGS="-D warnings"

# Enable file generation in the `src` directory for miden-protocol and miden-standards build scripts
export BUILD_GENERATED_FILES_IN_SRC=1

# Run cargo-hack with comprehensive feature checking
# Focus on library packages that have significant feature matrices
for package in miden-protocol miden-standards miden-agglayer miden-tx miden-testing miden-block-prover miden-tx-batch-prover; do
    echo "Checking package: $package"
    cargo hack check -p "$package" --each-feature --all-targets
done

echo "All feature combinations compiled successfully!"
