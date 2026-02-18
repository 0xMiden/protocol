# Fungible Faucets

Miden Standards provides several standard implementations for fungible faucets, offering different strategies for supply management and distribution.

## Basic Fungible Faucet (Fixed Supply)

The `BasicFungibleFaucet` account component implements a standard fixed-supply token model.

- **Supply Strategy**: Fixed maximum supply.
- **Minting**: Authorized accounts can mint tokens up to the defined `max_supply`. Attempts to mint beyond this limit will fail.
- **Burning**: Token holders can burn tokens, reducing the circulating supply.
- **Storage**: Uses `TokenMetadata` stored in a single storage slot to track the current supply, max supply, decimals, and symbol.

### Usage

```rust
use miden_standards::account::faucets::{BasicFungibleFaucet, create_basic_fungible_faucet};

// Create a new faucet with a max supply of 1,000,000
let faucet = BasicFungibleFaucet::new(symbol, decimals, max_supply)?;
```

## Unlimited Fungible Faucet

The `UnlimitedFungibleFaucet` allows for unrestricted minting of tokens, suitable for testnets or inflationary models.

- **Supply Strategy**: Unlimited (capped only by protocol limits, i.e., `FungibleAsset::MAX_AMOUNT`).
- **Minting**: Authorized accounts can mint an arbitrary amount of tokens.
- **Burning**: Supported.
- **Storage**: Stores `TokenMetadata`. Supply tracking is maintained but does not restrict further minting.

### Usage

```rust
use miden_standards::account::faucets::{UnlimitedFungibleFaucet, create_unlimited_fungible_faucet};

let faucet = UnlimitedFungibleFaucet::new(symbol, decimals)?;
```

## Timed Fungible Faucet

The `TimedFungibleFaucet` introduces time-based constraints on the distribution of tokens.

- **Supply Strategy**: Flexible supply with a time limit.
- **Distribution Period**: Minting is allowed only until a specified block number (`distribution_end`).
- **Post-Distribution Behavior**: After `distribution_end`, minting is disabled.
- **Burn Only Mode**: Can be configured to allow only burning of tokens (no further minting) after the distribution period.
- **Storage**: Uses two storage slots:
    1. `TokenMetadata`: Standard metadata.
    2. `SupplyConfig`: Tracks `token_supply`, `max_supply`, `distribution_end`, and `burn_only` flag.

### Usage

```rust
use miden_standards::account::faucets::{TimedFungibleFaucet, create_timed_fungible_faucet};

// Distribution ends at block 10,000
let distribution_end = 10_000u32;
let burn_only = true;

let faucet = TimedFungibleFaucet::new(
    symbol, 
    decimals, 
    max_supply, 
    distribution_end, 
    burn_only
)?;
```
