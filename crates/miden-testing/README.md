# Miden Testing

This crate contains tool for testing Miden transactions, batches and blocks.

`MockChain::to_bytes` writes a versioned Protobuf snapshot. Use
`MockChain::try_from_bytes` to restore it, including pending transactions and batches.
Snapshots contain unencrypted account and validator secret keys. The decoder checks
internal consistency but does not establish trust in the genesis state. Bound the size
of untrusted input before decoding. Snapshots in the previous Winterfell format must
be regenerated.

## License

This project is [MIT licensed](../../LICENSE).
