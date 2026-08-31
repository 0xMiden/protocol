---
sidebar_position: 5.1
---

# Fees

Miden transactions pay a fee by creating a public TX_FEE note (see the [note documentation](note.md#tx_fee)) that whoever builds the batch collects as compensation. The note is created by the account's authentication procedure as part of authorizing the transaction.

## How fees are computed

- The fee depends on the number of VM cycles the transaction executes and grows logarithmically with that count.
- The `compute_fee` transaction kernel procedure estimates the number of verification cycles by taking log2 of the estimated total execution cycles (rounded up). The result is then multiplied by the `verification_base_fee` from the reference block’s fee parameters.
- Since `compute_fee` runs before the transaction finishes, callers pass an estimate of the cycles that will still be spent after the call (e.g. for signature verification and the kernel epilogue). Standard components use conservative per-signature-scheme estimates; because of the logarithmic fee formula, overestimation costs at most a small number of base fee units.

## Which asset is used to pay fees

There are two distinct quantities involved in paying a fee:

- **The computed fee**: what the `compute_fee` kernel procedure returns. It is always denominated in the chain’s native fee asset, defined by the current reference block’s fee parameters. The native asset is chosen once as part of the genesis block and then copied to every newly created block, which means it stays consistent for a given network.
- **The paid amount**: what actually ends up in the TX_FEE note. The transaction can pay in any asset the batch builder accepts - the payment asset and its conversion rate to the native fee asset are user-supplied, committed to via the transaction’s auth args (the auth args are the hash of the conversion info - a fungible faucet ID and a rate - together with a salt, with the preimage in the advice map). The paid amount is the computed fee converted at that rate; paying in the native asset itself means committing to the native fee faucet at rate 1/1.

Auth components whose authorization can fall below the account’s full spending quorum bound what they will pay, since the rate reaches the VM from the host: the guarded and smart multisig components require the payment to be in the native fee asset and cap it at twice the computed fee. Without that bound, an authorization cheaper than an ordinary spend — guardian key rotation, or a procedure with a reduced per-procedure threshold — could move an arbitrary amount out of the vault as a fee note.

Otherwise the client software is responsible for choosing an asset and rate the intended batch builder accepts. Nothing else at the protocol level validates the conversion: enforcement happens at the batch builder, which rejects transactions whose fee note underpays it.

## How fees are paid

- The account’s authentication procedure computes the fee via `compute_fee` and creates a TX_FEE note funded from the account’s vault with the committed payment asset, before the transaction summary is created - so the fee note and the vault withdrawal are covered by the transaction signature. Standard auth components do this automatically via the pay_fee procedures in the `miden::standards::fee` module.
- Users should ensure their account’s vault holds sufficient balance of the payment asset to cover the fee. If it does not, or if no conversion info is committed for a non-zero fee, the transaction fails during the authentication procedure.
- On chains with a zero `verification_base_fee`, no fee note is created and no conversion info is required.
