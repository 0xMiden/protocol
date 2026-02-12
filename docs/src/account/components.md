---
sidebar_position: 6
title: "Components"
---

# Account Components

Account components are reusable units of functionality that define a part of an account's code and storage. Multiple account components can be merged together to form an account's final [code](./code) and [storage](./storage).

As an example, consider a typical wallet account, capable of holding a user's assets and requiring authentication whenever assets are added or removed. Such an account can be created by merging a `BasicWallet` component with an `Falcon512Rpo` authentication component. The basic wallet does not need any storage, but contains the code to move assets in and out of the account vault. The authentication component holds a user's public key in storage and additionally contains the code to verify a signature against that public key. Together, these components form a fully functional wallet account.

## Account Component schemas

An account component schema describes a reusable piece of account functionality and captures
everything required to initialize it. The schema encapsulates the component's **metadata**, its
code, and how its storage should be laid out and typed.

Once defined, a component schema can be instantiated to an account component. Multiple components can then be
merged to form the account's `Code` and `Storage`.

## Component code

The component's code defines a library of functions that can perform arbitrary computations, as well as read and write to account storage.

## Component metadata

The component metadata describes the account component entirely: its name, description, version, and storage layout.

The storage layout is described as a set of named storage slots. Each slot name must be a valid `StorageSlotName`, and its slot ID is
derived deterministically from the name.

Each slot has a type and an optional default value. If there is no default value defined as part of the schema, the value needs to be
provided at instantiation time. Default values can also be overridden

### TOML specification

The component metadata can be defined using TOML. Below is an example specification:

```toml
name = "Fungible Faucet"
description = "This component showcases the component schema format, and the different ways of providing valid values to it."
version = "1.0.0"
supported-types = ["FungibleFaucet"]

[[storage.slots]]
name = "demo::token_metadata"
description = "Contains token metadata (max supply, symbol, decimals)."
type = [
    { type = "u32", name = "max_supply", description = "Maximum supply of the token in base units" },
    { type = "miden::standards::fungible_faucets::metadata::token_symbol", name = "symbol", description = "Token symbol", default-value = "TST" },
    { type = "u8", name = "decimals", description = "Number of decimal places for converting to absolute units" },
    { type = "void" }
]

[[storage.slots]]
name = "demo::owner_public_key"
description = "This is a typed value supplied at instantiation and interpreted as a Falcon public key"
type = "miden::standards::auth::falcon512_rpo::pub_key"

[[storage.slots]]
name = "demo::protocol_version"
description = "A whole-word init-supplied value typed as a felt (stored as [0,0,0,<value>])."
type = "u8"

[[storage.slots]]
name = "demo::static_map"
description = "A map slot with statically defined entries"
type = { key = "word", value = "word" }
default-values = [
    { key = "0x0000000000000000000000000000000000000000000000000000000000000001", value = ["0x0", "249381274", "998123581", "124991023478"] },
    { key = ["0", "0", "0", "2"], value = "0x0000000000000000000000000000000000000000000000000000000000000010" }
]

[[storage.slots]]
name = "demo::procedure_thresholds"
description = "Map which stores procedure thresholds (PROC_ROOT -> signature threshold)"
type = { key = "word", value = "u16" }
```

#### Header

The metadata header specifies four fields:

- `name`: The component schema's name
- `description` (optional): A brief description of the component schema and its functionality
- `version`: A semantic version of this component schema
- `supported-types`: Specifies the types of accounts on which the component can be used. Valid values are `FungibleFaucet`, `NonFungibleFaucet`, `RegularAccountUpdatableCode` and `RegularAccountImmutableCode`

#### Storage entries

An account component schema can contain multiple storage entries, each describing either a
**single-slot value** or a **storage map**.

In TOML, these are declared using dotted array keys:

- **Value slots**: `[[storage.slots]]` with `type = "..."` or `type = [ ... ]`
- **Map slots**: `[[storage.slots]]` with `type = { ... }`

**Value-slot** entries describe their schema via `WordSchema`. A value type can be either:

- **Simple**: defined through the `type = "<identifier>"` field, indicating the expected `SchemaTypeId` for the entire word. The value is supplied at instantiation time via `InitStorageData`. Felt types are stored as full words in the following layout: `[0, 0, 0, <felt>]`.
- **Composite**: provided through `type = [ ... ]`, which contains exactly four `FeltSchema` descriptors. Each element is either a named typed field (optionally with `default-value`) or a `void` element for reserved/padding zeros.

Composite schema entries reuse the existing TOML structure for four-element words, while simple schemas rely on `type`. In our example, the `token_metadata` slot uses a composite schema (`type = [...]`) mixing typed fields (`max_supply`, `decimals`) with defaults (`symbol`) and a reserved/padding `void` element.

Every entry carries:

- `name`: Identifies the storage entry.
- `description` (optional): Explains the entry's purpose within the component.

The remaining fields depend on whether the entry is a value slot or a map slot, as inferred by the
shape of the `type` field.

##### Word types

Simple schemas accept `word` (default) and word-shaped types such as `miden::standards::auth::falcon512_rpo::pub_key` or `miden::standards::auth::ecdsa_k256_keccak::pub_key` (parsed from hexadecimal strings).

Simple schemas can also use any felt type (e.g. `u8`, `u16`, `u32`, `felt`, `miden::standards::fungible_faucets::metadata::token_symbol`, `void`). The value is parsed as a felt and stored as a word with the parsed felt in the last element and the remaining elements set to `0`.

##### Word schema example

```toml
[[storage.slots]]
name = "demo::faucet_id"
description = "Account ID of the registered faucet"
type = [
  { type = "felt", name = "prefix", description = "Faucet ID prefix" },
  { type = "felt", name = "suffix", description = "Faucet ID suffix" },
  { type = "void" },
  { type = "void" },
]
```

##### Felt types

Valid field element types are `void`, `u8`, `u16`, `u32`, `felt` (default) and `miden::standards::fungible_faucets::metadata::token_symbol`:

- `void` is a special type which always evaluates to `0` and does not produce an init requirement; it is intended for reserved or padding elements.
- `u8`, `u16` and `u32` values can be parsed as decimal numbers and represent 8-bit, 16-bit and 32-bit unsigned integers.
- `felt` values represent a field element, and can be parsed as decimal or hexadecimal numbers.
- `miden::standards::fungible_faucets::metadata::token_symbol` values represent basic fungible token symbols, parsed as 1–6 uppercase ASCII characters.

##### Value slots

Single-slot entries are represented by `ValueSlotSchema` and occupy one slot (one word). They use the fields:

- `type` (required): Describes the schema for this slot. It can be either:
  - a string type identifier (simple init-supplied slot), or
  - an array of 4 felt schema descriptors (composite slot schema).
- `default-value` (optional): An overridable default for simple slots. If omitted, the slot is required at instantiation (unless `type = "void"`).

In our TOML example, the first entry defines a composite schema, while the second is an init-supplied value typed as `miden::standards::auth::falcon512_rpo::pub_key`.

##### Storage map slots

[Storage maps](./storage#map-slots) use `MapSlotSchema` and describe key-value pairs where each key and value is itself a `WordSchema`. Map slots support:

- `type` (required): Declares the slot as a map via a map type table (`type = { ... }`), with:
  - `type.key` (required): Declares the schema/type of keys stored in the map.
  - `type.value` (required): Declares the schema/type of values stored in the map.
- `default-values` (optional): Lists default map entries defined by nested `key` and `value` descriptors. Each entry must be fully specified and cannot contain typed fields.

`type.key` / `type.value` accept either a string type identifier (e.g. `"word"`) or a 4-element array of felt schema descriptors.

If `default-values` is omitted, the map is populated at instantiation via [`InitStorageData`](#providing-init-values). When `default-values` are present, they act as defaults: init data can override existing values and optionally add new key-value pairs.

In the example, the third storage entry defines a static map and the fourth entry (`procedure_thresholds`) is populated at instantiation.

##### Typed map

You can type maps at the slot level via `type.key` and `type.value` (each a `WordSchema`):

```toml
[[storage.slots]]
name = "demo::typed_map"
type = { key = "word", value = "miden::standards::auth::falcon512_rpo::pub_key" }
```

This declares that all keys are `word` and all values are `miden::standards::auth::falcon512_rpo::pub_key`, regardless of whether the map contents come from `default-values = [...]` (static) or are supplied at instantiation via `InitStorageData`.

`type.key` / `type.value` are validated when building map entries from `InitStorageData` (and when validating `default-values`).

##### Multi-slot value

Multi-slot values are currently unsupported by component schemas.

#### Providing init values

When a storage entry requires init-supplied values, an implementation must provide their concrete values at instantiation time. This is done through `InitStorageData` (available as `miden_protocol::account::component::InitStorageData`), which can be created programmatically or loaded from TOML using `InitStorageData::from_toml()`.

For example, the init-populated map entry above can be populated from TOML as follows:

```toml
"demo::owner_public_key" = "0x1234"
"demo::protocol_version" = "1"

["demo::token_metadata"]
max_supply = "1000000000"
decimals = "10"

"demo::procedure_thresholds" = [
    {
      key = "0xd2d1b6229d7cfb9f2ada31c5cb61453cf464f91828e124437c708eec55b9cd07",
      value = ["0", "0", "0", "1"]
    },
    {
      key = "0x2217cd9963f742fc2d131d86df08f8a2766ed17b73f1519b8d3143ad1c71d32d",
      value = ["0", "0", "0", "2"]
    }
]
```

All init values must be provided as TOML strings (including numeric values), and are parsed/validated against the schema at instantiation time.

Each element in the array is a fully specified key/value pair. Note that slot names include `::`, so they must be quoted in TOML. This syntax complements the existing `default-values = [...]` form used for static maps, and mirrors how map entries are provided in component metadata. If an init-populated map slot is omitted from `InitStorageData`, it defaults to an empty map.
