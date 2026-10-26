---
sidebar_position: 1
---

# Non-fungible tokens

This page specifies how wallets, marketplaces and indexers read the metadata of NFTs issued by the standard `NonFungibleFaucet`. It currently covers the collection metadata. The parts still to come are listed under [Not yet specified](#not-yet-specified).

## Collection metadata

An NFT faucet describes its collection in two places:

- On-chain, in the faucet's storage: `name`, `symbol`, `description`, `logo_uri`, `contract_uri` and `token_base_uri`. Each optional field has a mutability flag that is fixed at creation and readable on-chain.
- Off-chain, in a JSON document that `contract_uri` points to. It holds presentation data that is too large or too rarely needed to keep on-chain.

The on-chain fields are the source of truth. The JSON only adds to them.

### The `contract_uri` JSON

The JSON holds only presentation data that is not on-chain. All of its fields are optional:

- `banner_image` (string): the URI of a wide image for the collection page.
- `featured_image` (string): the URI of an image for featured listings.
- `external_link` (string): the project's website. On-chain, the faucet's external URI field holds `contract_uri` itself, so the website lives here.
- `collaborators` (array of strings): accounts that may manage the collection on marketplaces, given as bech32 [account IDs](../account/id.md#encoding) on the faucet's network (e.g. `mm1...`). Readers ignore entries with a different network prefix.

The field names match the collection metadata that marketplaces already read, so existing tooling can use the JSON as is.

Example:

```json
{
  "banner_image": "ipfs://bafybeib.../banner.png",
  "featured_image": "ipfs://bafybeib.../featured.png",
  "external_link": "https://midenpunks.example",
  "collaborators": ["mm1ap86qhrsrs4gcy2ntrerfkwylure4ly5"]
}
```

### Relationship to the on-chain fields

- `name`, `symbol`, `description` and the collection image (`logo_uri`) are on-chain and should not be repeated in the JSON. If the JSON contains them anyway, readers use the on-chain values.
- `token_base_uri` is on-chain only. Readers ignore it if it appears in the JSON.
- Fields the reader does not recognize are ignored.

### Integrity and trust

The JSON is not bound to anything on-chain. Unlike token metadata, no commitment covers it, so its content is whatever the host serves.

- `contract_uri` should be content-addressed (e.g. `ipfs://`), so the JSON cannot change without the URI changing. If the faucet's `contract_uri` is also immutable, the JSON is fixed for the life of the collection.
- Readers treat the JSON and the images it links to as untrusted display data from an arbitrary host.

### Reading collection metadata

1. Read the on-chain metadata from the faucet's storage. This requires a public faucet account, since a private faucet's storage is not visible.
2. If `contract_uri` is set, fetch the JSON and apply the rules above.
3. If `contract_uri` is empty or the fetch fails, show the collection from its on-chain fields alone.

### Updates

If `is_contract_uri_mutable` is set, the faucet's authority can change `contract_uri` through `set_contract_uri`. Each change emits a [transaction log](../transaction.md#transaction-logs) under the topic `miden::standards::faucets::external_uri_updated` (`NonFungibleFaucet::contract_uri_updated_topic` in Rust), whose content is the new `contract_uri`. Readers refetch the JSON when they see this log, and can always read the current value from the faucet. If `contract_uri` is content-addressed, the JSON can only change through such an update.

## Not yet specified

This page currently covers only the collection metadata. The rest of the NFT standard will be added here as it is specified:

- Where a token's public metadata lives: the token base URI, the token URI rule and the token ID format ([#4011](https://github.com/0xMiden/protocol/issues/4011)).
- The format of a token's metadata ([#4039](https://github.com/0xMiden/protocol/issues/4039)).
- How readers verify fetched token metadata against the asset ([#4038](https://github.com/0xMiden/protocol/issues/4038)).
- How private token metadata reaches the holder ([#4012](https://github.com/0xMiden/protocol/issues/4012)).
