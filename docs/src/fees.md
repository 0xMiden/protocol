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

The client software is responsible for choosing an asset and rate the intended batch builder accepts. Nothing at the protocol level validates the conversion: enforcement happens at the batch builder, which rejects transactions whose fee note underpays it.

## How fees are paid

- The account’s authentication procedure computes the fee via `compute_fee` and creates a TX_FEE note funded from the account’s vault with the committed payment asset, before the transaction summary is created - so the fee note and the vault withdrawal are covered by the transaction signature. Standard auth components do this automatically via the pay_fee procedures in the `miden::standards::fee` module.
- Users should ensure their account’s vault holds sufficient balance of the payment asset to cover the fee. If it does not, or if no conversion info is committed for a non-zero fee, the transaction fails during the authentication procedure.
- On chains with a zero `verification_base_fee`, no fee note is created and no conversion info is required.

## Fees for network transactions

A [network transaction](transaction.md#network-transaction) is executed by the operator, but the fee is still paid by the network account itself, out of its own vault. Network accounts always pay in the native fee asset at rate 1/1 and commit no conversion info - the native fee faucet is read from the reference block.

To recover that cost, a network account charges for the notes it consumes. Its **fee policy** - a swappable account procedure - prices each note, and senders can read a price ahead of time by calling `estimate_note_fee` through foreign procedure invocation. The standard `BasicConstantFeePolicy` maps a note script root to a fixed price.

## Sponsoring fees

A network account rejects a transaction unless every note it consumes has its price prepaid. The prepayment travels in a separate FEE_SPONSORSHIP note (see the [note documentation](note.md#fee_sponsorship)), so the sponsored note itself stays fee-unaware:

- It carries the fee as a single asset and names the note it pays for by note ID. Coverage is checked per note, so several sponsorships may top up the same one.
- Its script releases the assets only in a transaction that also consumes the bound note, so a sponsor need not trust the consumer; the account’s authentication procedure enforces the mirror image and collects the sponsorships into its vault.
- The only other consumption is a reclaim by the named reclaimer, recovering the assets if the sponsored note is consumed elsewhere. Reclaim is opt-in - without a reclaim block height the note can never be reclaimed.

Usually the sponsorship is created for you: creating a note targeted at a network account also creates a matching FEE_SPONSORSHIP note, funded from your vault and priced through the target’s fee policy. It is created inside `pay_fee` before your own fee is computed, so both are covered by the transaction signature, and it has reclaim disabled.

Network accounts sponsor their outgoing notes the same way, chaining fees along a multi-hop flow: what is collected on the way in funds the sponsorships on the way out. Since that spends the account’s own vault, its **sponsorship policy**, fixed at deployment, decides whether it may sponsor more than it collected. The default forbids it, so the account only forwards value it collected.
