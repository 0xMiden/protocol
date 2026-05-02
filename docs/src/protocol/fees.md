---
sidebar_position: 5.1
---

# Fees

Miden transactions pay a fee that is computed and charged automatically by the transaction kernel during the epilogue.

## How fees are computed

- The fee depends on the number of VM cycles the transaction executes and grows logarithmically with that count.
- The kernel estimates the number of verification cycles by taking log2 of the estimated total execution cycles (rounded up). The result is then multiplied by the `verification_base_fee` from the reference block’s fee parameters.
- In other words, the fee is proportional to the logarithm of the transaction’s number of execution cycles, scaled by the base verification fee defined in the block header.

## Which asset is used to pay fees

- Fees are paid in the chain’s native asset, defined by the current reference block’s fee parameters.
- The native asset is chosen once as part of the genesis block and then copied to every newly created block, which means the native asset stays consistent for a given network.

## How fees are paid

- Users should ensure their account’s vault holds sufficient balance of the native asset to cover the fee. The fee is charged automatically; no explicit transaction kernel API must be called.
- If the account does not contain enough of the native asset to cover the computed fee, the transaction fails during the epilogue.
