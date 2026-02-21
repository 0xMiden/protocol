---
sidebar_position: 3
---

# Notes

A `Note` is the medium through which [Accounts](account/index.md) communicate. A `Note` holds assets and defines how they can be consumed.

## What is the purpose of a note?

In Miden's hybrid UTXO and account-based model notes represent UTXO's which enable parallel transaction execution and privacy through asynchronous local `Note` production and consumption.

## Note core components

A `Note` is composed of several core components, illustrated below:

<p style={{textAlign: 'center'}}>
    <img src={require('./img/note/note.png').default} style={{width: '30%'}} alt="Note diagram"/>
</p>

These components are:

1. [Assets](#assets)
2. [Script](#script)
3. [Storage](#storage)
4. [Serial number](#serial-number)
5. [Metadata](#metadata)

### Assets

:::note
An [asset](asset) container for a `Note`.
:::

A `Note` can contain from 0 up to 256 different assets. These assets represent fungible or non-fungible tokens, enabling flexible asset transfers.

### Script

:::note
The code executed when the `Note` is consumed.
:::

Each `Note` has a script that defines the conditions under which it can be consumed. When accounts consume notes in transactions, `Note` scripts call the account’s interface functions. This enables all sorts of operations beyond simple asset transfers. The Miden VM’s Turing completeness allows for arbitrary logic, making `Note` scripts highly versatile. There is no limit to the amount of code a `Note` can hold.

### Storage

:::note
The storage of the `Note` that it can access during execution.
:::

A `Note` can store up to 1024 items in its storage, which adds up to a maximum of 8 KB of data. The `Note` script can access storage during execution and it is used to parameterize a note's script. For instance, a P2ID note stores the ID of the target account that can consume the note. This makes the P2ID note script reusable by changing the target account ID.

### Serial number

:::note
A unique and immutable identifier for the `Note`.
:::

The serial number has two main purposes. Firstly by adding some randomness to the `Note` it ensures it's uniqueness, secondly in private notes it helps prevent linkability between the note's hash and its nullifier. The serial number should be a random 32 bytes number chosen by the user. If leaked, the note’s nullifier can be easily computed, potentially compromising privacy.

### Metadata

:::note
Additional public `Note` information.
:::

Every note includes metadata:
- the account ID of the sender, i.e. the creator of the note.
- its note type, i.e. private or public.
- the [note tag](#note-discovery) that aids in discovery of the note.
- an optional [note attachment](#attachment).

Regardless of [storage mode](#note-storage-mode), these metadata fields are always public.

### Attachment

An attachment is a variable-size part of a note's metadata:
- It can either be absent (`None`), store a single `Word` or an `Array` of field elements. These are the three _kinds_ of attachments.
- The _scheme_ of an attachment is an optional, 32-bit user-defined value that can be used to detect the presence of certain standardized attachments.

Example use cases for attachments are:
- Communicate the note details of a private note in encrypted form. This means the encrypted note is attached publicly to the otherwise private note.
- For [network transactions](./transaction.md#network-transaction), encode the ID of the network account that should
  consume the note. This is a standardized attachment scheme in miden-standards called `NetworkAccountTarget`.
- Communicate the details of a _private_ note to the receiver so they can derive the note. For example, the payback note of a partially fillable swap note can be private and the receiver already knows a few details: It is a P2ID note, the serial number is derived from the SWAP note's serial number and the note storage is the account ID of the receiver. The receiver only needs to now the exact amount that was filled to derive the full note for consumption. This amount can be encoded in the public attachment of the payback note, which allows this use case to work with private notes and still not require a side-channel.

## Note Lifecycle

<p style={{textAlign: 'center'}}>
    <img src={require('./img/note/note-life-cycle.png').default} style={{width: '70%'}} alt="Note lifecycle"/>
</p>

The `Note` lifecycle proceeds through four primary phases: **creation**, **validation**, **discovery**, and **consumption**. Creation and consumption requires two separate transactions. Throughout this process, notes function as secure, privacy-preserving vehicles for asset transfers and logic execution.

### Note creation

Accounts can create notes in a transaction. The `Note` exists if it is included in the global notes DB.

- **Users:** Executing local or network transactions.
- **Miden operators:** Facilitating on-chain actions, e.g. such as executing user notes against a DEX or other contracts.

#### Note storage mode

As with [accounts](account/index.md), notes can be stored either publicly or privately:

- **Public mode:** The `Note` data is stored in the [note database](state#note-database), making it fully visible on-chain.
- **Private mode:** Only the `Note`’s hash is stored publicly. The `Note`’s actual data remains off-chain, enhancing privacy.

### Note validation

Once created, a `Note` must be validated by a Miden operator. Validation involves checking the transaction proof that produced the `Note` to ensure it meets all protocol requirements.

After validation notes become "live" and eligible for consumption. If creation and consumption happens within the same block, there is no entry in the Notes DB. All other notes, are being added either as a commitment or fully public.

### Note discovery

Clients often need to find specific notes of interest. Miden allows clients to query the `Note` database using `Note` tags. These lightweight, 32-bit data fields serve as best-effort filters, enabling quick lookups for notes related to particular use cases, scripts, or account prefixes.

While note tags can be arbitrarily constructed from 32 bits of data, there are two categories of tags that many notes fit into.

#### Account Targets

A note targeted at an account is a note that is intended or even enforced to be consumed by a specific account. One example is a P2ID note that can only be consumed by a specific account ID. The tag for such a note should make it easy for the receiver to find the note. Therefore, the tag encodes a certain number of bits of the receiver account's ID, by convention. Notably, it may not encode the full 32 bits of the target account's ID to preserve the receiver's privacy. See also the section on privacy below.

#### Use Case Tags

Use case notes are notes that are not intended to be consumed by a specific account, but by anyone willing to fulfill the note's contract. One example is a SWAP note that trades one asset against another. Such a use case note can define the structure of their note tags. A sensible structure for a SWAP note could be:
- encoding the 2 bits of the note's type.
- encoding the note script root, i.e. making it identifiable as a SWAP note, for example by
  using 16 bits of the SWAP script root.
- encoding the SWAP pair, for example by using 8 bits of the offered asset faucet ID and 8 bits
  of the requested asset faucet ID.

This allows clients to search for a public SWAP note that trades USDC against ETH only through the note tag. Since tags are not validated in any way and only act as best-effort filters, further local filtering is almost always necessary. For example, there could easily be a collision on the 8 bits used in SWAP tag's faucet IDs.

#### Privacy vs Efficiency

Using `Note` tags strikes a balance between privacy and efficiency. Without tags, querying a specific `Note` ID reveals a user's interest to the operator. Conversely, downloading and filtering all registered notes locally is highly inefficient. Tags allow users to adjust their level of privacy by choosing how broadly or narrowly they define their search criteria, letting them find the right balance between revealing too much information and incurring excessive computational overhead.

### Note consumption

To consume a `Note`, the consumer must know its data, including the note's storage which is needed to compute the nullifier. Consumption occurs as part of a transaction. Upon successful consumption a nullifier is generated for the consumed notes.

Upon successful verification of the transaction:

1. The Miden operator records the `Note`’s nullifier as "consumed" in the nullifier database.
2. The `Note`’s one-time claim is thus extinguished, preventing reuse.

#### Note recipient restricting consumption

Consumption of a `Note` can be restricted to certain accounts or entities. For instance, the P2ID and P2IDE `Note` scripts target a specific account ID. Alternatively, Miden defines a RECIPIENT (represented as 32 bytes) computed as:

```arduino
hash(hash(hash(serial_num, [0; 4]), script_root), storage_commitment)
```

Only those who know the RECIPIENT’s pre-image can consume the `Note`. For private notes, this ensures an additional layer of control and privacy, as only parties with the correct data can claim the `Note`.

The [transaction prologue](transaction) requires all necessary data to compute the `Note` hash. This setup allows scenario-specific restrictions on who may consume a `Note`.

For a practical example, refer to the [SWAP note script](https://github.com/0xMiden/miden-base/blob/next/crates/miden-standards/asm/standards/notes/swap.masm), where the RECIPIENT ensures that only a defined target can consume the swapped asset.

#### Note nullifier ensuring private consumption

The `Note` nullifier, computed as:

```arduino
hash(serial_num, script_root, storage_commitment, vault_hash)
```

This achieves the following properties:

- Every `Note` can be reduced to a single unique nullifier.
- One cannot derive a note's hash from its nullifier.
- To compute the nullifier, one must know all components of the `Note`: serial_num, script_root, storage_commitment, and vault_hash.

That means if a `Note` is private and the operator stores only the note's hash, only those with the `Note` details know if this `Note` has been consumed already. Zcash first [introduced](https://zcash.github.io/orchard/design/nullifiers.html#nullifiers) this approach.

<p style={{textAlign: 'center'}}>
    <img src={require('./img/note/nullifier.png').default} style={{width: '70%'}} alt="Nullifier diagram"/>
</p>

## Standard Note Types

The miden-base repository provides several standard note scripts that implement common use cases for asset transfers and interactions. These pre-built note types offer secure, tested implementations for typical scenarios.

### P2ID (Pay-to-ID)

The P2ID note script implements a simple pay-to-account-ID pattern. It adds all assets from the note to a specific target account.

**Key characteristics:**

- **Purpose:** Direct asset transfer to a specific account ID
- **Storage:** Requires exactly 2 storage items containing the target account ID
- **Validation:** Ensures the consuming account's ID matches the target account ID specified in the note
- **Requirements:** Target account must expose the `miden::standards::wallets::basic::receive_asset` procedure

**Use case:** Simple, direct payments where you want to send assets to a known account ID.

### P2IDE (Pay-to-ID Extended)

The P2IDE note script extends P2ID with additional features including time-locking and reclaim functionality.

**Key characteristics:**

- **Purpose:** Advanced asset transfer with time-lock and reclaim capabilities
- **Storage:** Requires exactly 4 storage items:
  - Target account ID
  - Reclaim block height (when sender can reclaim)
  - Time-lock block height (when target can consume)
- **Time-lock:** Note cannot be consumed until the specified block height is reached
- **Reclaim:** Original sender can reclaim the note after the reclaim block height if not consumed by target
- **Validation:** Complex logic to handle both target consumption and sender reclaim scenarios
- **Requirements:** Account must expose the `miden::standards::wallets::basic::receive_asset` procedure

**Use cases:**

- Escrow-like payments with time constraints
- Conditional payments that can be reclaimed if not consumed
- Time-delayed transfers

### SWAP

The SWAP note script implements atomic asset swapping functionality.

**Key characteristics:**

- **Purpose:** Atomic asset exchange between two parties
- **Storage:** Requires exactly 16 storage items specifying:
  - Requested asset details
  - Payback note recipient information
  - Note creation parameters (type, tag, attachment)
- **Assets:** Must contain exactly 1 asset to be swapped
- **Mechanism:**
  1. Creates a payback note containing the requested asset for the original note issuer
  2. Adds the note's asset to the consuming account's vault
- **Requirements:** Account must expose both:
  - `miden::standards::wallets::basic::receive_asset` procedure
  - `miden::standards::wallets::basic::move_asset_to_note` procedure

**Use case:** Decentralized asset trading where two parties want to exchange different assets atomically.

### Choosing the Right Note Type

- **Use P2ID** for simple, direct payments to known accounts
- **Use P2IDE** when you need time-locks, escrow functionality, or reclaim capabilities
- **Use SWAP** for atomic asset exchanges between parties
- **Create custom scripts** for specialized use cases not covered by standard types

These standard note types provide a foundation for common operations while maintaining the flexibility to create custom note scripts for specialized requirements.
