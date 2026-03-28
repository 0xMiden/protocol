# Changelog

## v0.15.0 (TBD)

### Features

- Added `FungibleTokenMetadata` component with name, description, logo URI, and external link support, and MASM procedures `get_token_metadata`, `get_max_supply`, `get_decimals`, and `get_token_symbol` for the token metadata standard. ([#2439](https://github.com/0xMiden/miden-base/pull/2439))
- Aligned fungible faucet token metadata with the metadata standard: faucet now uses the canonical slot `miden::standards::metadata::token_metadata` so MASM metadata getters work with faucet storage.

### Changes

- [BREAKING] Renamed `ProvenBatch::new` to `new_unchecked` ([#2687](https://github.com/0xMiden/miden-base/issues/2687)).

---

## 0.14.0 (2026-03-23)

### Features

- Made `NoteMetadataHeader` and `NoteMetadata::to_header()` public, added `NoteMetadata::from_header()` constructor, and exported `NoteMetadataHeader` from the `note` module ([#2561](https://github.com/0xMiden/protocol/pull/2561)).
- Introduce NOTE_MAX_SIZE (256 KiB) and enforce it on individual output notes ([#2205](https://github.com/0xMiden/miden-base/pull/2205), [#2651](https://github.com/0xMiden/miden-base/pull/2651)).
- Added AggLayer faucet registry to bridge account with conversion metadata, `CONFIG_AGG_BRIDGE` note for faucet registration, and FPI-based asset conversion in `bridge_out` ([#2426](https://github.com/0xMiden/miden-base/pull/2426)).
- Added single-word `Array` standard ([#2203](https://github.com/0xMiden/miden-base/pull/2203)).
- Added `SignedBlock` struct ([#2355](https://github.com/0xMiden/miden-base/pull/2235)).
- Enabled `CodeBuilder` to add advice map entries to compiled scripts ([#2275](https://github.com/0xMiden/miden-base/pull/2275)).
- Implemented verification of AggLayer deposits (claims) against GER ([#2288](https://github.com/0xMiden/miden-base/pull/2288), [#2295](https://github.com/0xMiden/miden-base/pull/2295)).
- Added `Ownable2Step` account component ([#2292](https://github.com/0xMiden/miden-base/pull/2292)).
- Added `BlockNumber::MAX` constant ([#2324](https://github.com/0xMiden/miden-base/pull/2324)).
- [BREAKING] Added `get_asset` and `get_initial_asset` kernel procedures ([#2369](https://github.com/0xMiden/miden-base/pull/2369)).
- Added `FixedWidthString` for fixed-width UTF-8 string storage ([#2633](https://github.com/0xMiden/protocol/pull/2633)).

### Changes

- [BREAKING] Renamed `NoteInputs` to `NoteStorage` ([#1662](https://github.com/0xMiden/miden-base/issues/1662)).
- [BREAKING] Renamed `WellKnownComponent` to `StandardAccountComponent`, `WellKnownNote` to `StandardNote` ([#2332](https://github.com/0xMiden/miden-base/pull/2332)).
- [BREAKING] Refactored assets in the tx kernel from one to two words (`ASSET_KEY` and `ASSET_VALUE`) ([#2396](https://github.com/0xMiden/miden-base/pull/2396)).
- [BREAKING] The native hash function changed from RPO256 to Poseidon2 ([#2508](https://github.com/0xMiden/miden-base/pull/2508)).
- [BREAKING] The stack orientation changed from big-endian to little-endian ([#2508](https://github.com/0xMiden/miden-base/pull/2508)).
- Migrated to miden-vm v0.22 and miden-crypto v0.23 ([#2644](https://github.com/0xMiden/protocol/pull/2644)).

### Fixes

- Fixed `PartialAccountTree::track_account` handling of empty leaves ([#2598](https://github.com/0xMiden/protocol/pull/2598)).