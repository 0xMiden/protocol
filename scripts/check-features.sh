#!/bin/bash

set -euo pipefail

# Script to check all feature combinations compile without warnings
# This script ensures that warnings are treated as errors for CI

echo "Checking all feature combinations with cargo-hack..."

# Set environment variables to treat warnings as errors
export RUSTFLAGS="-D warnings"

# Run cargo-hack with comprehensive feature checking
# Focus on library packages that have significant feature matrices
declare -ra PACKAGES=(
    miden-protocol
    miden-objects
    miden-standards
    miden-agglayer
    miden-tx
    miden-testing
    miden-block-prover
    miden-tx-batch
)

for package in "${PACKAGES[@]}"; do
    echo "Checking package: $package"
    cargo hack check -p "$package" --each-feature --all-targets
done

echo "All feature combinations compiled successfully!"
