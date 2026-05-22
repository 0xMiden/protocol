# Solidity Compatibility Tests

This directory contains Foundry tests for generating test vectors to verify 
that the Miden Merkle Tree Frontier implementation is compatible with the Solidity 
`DepositContractBase.sol` from [agglayer-contracts v2](https://github.com/agglayer/agglayer-contracts).

## Prerequisites

Install [Foundry](https://book.getfoundry.sh/getting-started/installation):

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## Generating Test Vectors

From the repository root, you can regenerate both canonical zeros and Merkle Tree Frontier test vectors with:

```bash
make generate-solidity-test-vectors
```

Or from this directory:

```bash
# Install dependencies (first time only)
forge install

# Generate canonical zeros (test-vectors/canonical_zeros.json)
forge test -vv --match-test test_generateCanonicalZeros

# Generate Merkle Tree Frontier vectors (test-vectors/merkle_tree_frontier_vectors.json)
forge test -vv --match-test test_generate_MTF_vectors
```

## Generated Files

- `test-vectors/canonical_zeros.json` - Canonical zeros for each tree height (ZERO_n = keccak256(ZERO_{n-1} || ZERO_{n-1}))
- `test-vectors/merkle_tree_frontier_vectors.json` - Leaf-root pairs after adding leaves 0..31

### Canonical Zeros

The canonical zeros should match the constants in:
`crates/miden-agglayer/asm/bridge/canonical_zeros.masm`

### Merkle Tree Frontier Vectors

The `test_generate_MTF_vectors` adds 32 leaves and outputs the root after each addition.
Each leaf uses:

- `amounts[i] = i + 1`
- `destination_networks[i]` and `destination_addresses[i]` generated deterministically from
  a fixed seed in `MTFTestVectors.t.sol`

This gives reproducible "random-looking" destination parameters while keeping vector generation
stable across machines and reruns.
