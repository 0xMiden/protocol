---
sidebar_position: 5.1
---

# Fees

Miden transactions pay a fee by creating a public BATCH_FEE note (see the [note documentation](note.md#batch_fee)) that whoever builds the batch collects as compensation. The note is created by the account's authentication procedure as part of authorizing the transaction.

## How fees are computed

- The fee depends on the number of VM cycles the transaction executes and grows logarithmically with that count.
- The `compute_fee` transaction kernel procedure estimates the number of verification cycles by taking log2 of the estimated total execution cycles (rounded up). The result is then multiplied by the `verification_base_fee` from the reference block’s fee parameters.
- Since `compute_fee` runs before the transaction finishes, callers pass an estimate of the cycles that will still be spent after the call (e.g. for signature verification and the kernel epilogue). Standard components use conservative per-signature-scheme estimates; because of the logarithmic fee formula, overestimation costs at most a small number of base fee units.

## Which asset is used to pay fees

- The fee amount is denominated in the chain’s native fee asset, defined by the current reference block’s fee parameters.
- The native asset is chosen once as part of the genesis block and then copied to every newly created block, which means the native asset stays consistent for a given network.
- The payment asset and conversion rate are committed to via the transaction’s auth args: the auth args are the hash of the payment info (a fungible faucet ID and a rate) together with a salt, and the advice map carries the preimage. Paying in the native asset means committing to the native fee faucet at rate 1/1; any other asset is paid at the committed rate. Whether a batch builder accepts a given payment asset is up to the builder.

## How fees are paid

- The account’s authentication procedure computes the fee via `compute_fee` and creates a BATCH_FEE note funded from the account’s vault with the committed payment asset, before the transaction summary is created - so the fee note and the vault withdrawal are covered by the transaction signature. The standard singlesig component does this automatically via the `miden::standards::auth::fee::pay_fee` procedure.
- Users should ensure their account’s vault holds sufficient balance of the payment asset to cover the fee. If it does not, or if no payment info is committed for a non-zero fee, the transaction fails during the authentication procedure.
- On chains with a zero `verification_base_fee`, no fee note is created and no payment info is required.
