---
sidebar_position: 3
---

# Address

## Purpose

An address is an extension to account IDs and other identifiers that facilitates sending and receiving of [notes](../note). It serves four main purposes explained in this section.

### Communicating receiver information

An address is designed for the note receiver to communicate information about themselves to the sender.

The receiver can choose to disclose various pieces of information that control how the note itself is structured.

Consider a few examples that use different address mechanisms:

- The [Pay-to-ID note](../note#p2id-pay-to-id): the note itself can only be consumed if the account ID encoded in the note details matches the ID of the account that tries to consume it. To receive a P2ID note, the receiver should communicate an `AddressId::AccountId` type to the sender.
- A "Pay-to-PoW" note that can only be consumed if the receiver can provide a valid seed such that the hash of the seed results in a value with n leading zero bits. The receiver communicates an `AddressId::PoW` type to the sender, which encodes the target number of leading zero bits (and a salt to avoid re-use of the same seed).
- A "Pay-to-Public-Key" note that stores a public (signature) key and checks if the receiver can provide a valid cryptographic signature for that key. The `AddressId::PublicKey` type must encode the public key.

These different address mechanisms provide different levels of privacy and security:
- `AddressId::AccountId`: the receiver is uniquely identifiable, but they are the only one who can consume the note.
- `AddressId::PoW`: the receiver is not revealed publicly, but potentially many entities can consume the note. The receiver has an advantage by specifying the salt.
- `AddressId::PublicKey`: the receiver `AccountId` is not revealed publicly, only their public key. A fresh `AddressId::PublicKey` can be used for receiving each note, resulting in increased privacy.

:::note
The "Pay-to-PoW" and "Pay-to-Public-Key" notes and the corresponding address types are for illustration purposes only. They are not part of the Miden library.
:::

### Communicating channel information

For notes which are sent privately, the sender needs to communicate the full note details to the receiver. This can be done via a side channel, such as a messenger, email, or via a QR code. We would like to avoid the necessity of operating two-way communication channels for each note. Rather, we operate under the assumption that once the receiver shares their `Address` (directly with the sender, or via a bulletin board, i.e. a one-way channel), they don't need to stay online and wait for the sender to send back the full note details.

Instead, our Miden client connects to a _Note Transport Layer_, which stores encrypted note details together with the associated public metadata for each note. The receiver can query the Note Transport Layer for `NoteTag`s they are interested in. Typically, a `NoteTag` encodes a few leading bits (14 by default) of the receiver's `AccountId`. Querying the Note Transport Layer for 14-bit `NoteTag`s reduces the receiver's privacy, but at the same time allows them to perform less work downloading and trial-decrypting the notes than if fewer bits were encoded.

With an `Address`, e.g. the [`AddressId::AccountId`](./address#address-types) variant, the receiver could specify how many bits of their `AccountId` they want to disclose to the sender and thus choose their level of privacy.

### Account interface discovery

An address allows the sender of the note to easily discover the interface of the receiving account. As explained in the [account interface](./code#interface) section, every account can have a different set of procedures that note scripts can call, which is the _interface_ of the account. In order for the sender of a note to create a note that the receiver can consume, the sender needs to know the interface of the receiving account. This can be communicated via the address, which encodes a mapping of standard interfaces like the basic wallet.

If a sender wants to create a note, it is up to them to check whether the receiver account has an interface that is compatible with that note. The notion of an address doesn't exist at protocol level and so it is up to wallets or clients to implement this interface compatibility check.

### Note encryption

An address can include a public encryption key that enables senders to securely encrypt note payloads for the receiver. This ensures that only the intended recipient, who holds the corresponding private key, can decrypt and read the note contents.

## Structure

An address consists of two parts:
- An identifier that determines what the address fundamentally points to, e.g. an account ID or, in the future, a public key.
- Routing parameters, that customize how a sender creates notes for the receiver, or in other words, how they are routed.

The separation between these two parts is represented by an underscore (`_`) in the encoded address:

```text
mm1arp0azyk9jugtgpnnhle8daav58nczzr_qpgqqwcfx0p
               |                         |
            account ID            routing parameters
```

### Relationship to Identifiers

The routing parameters in an address can encode exactly one account interface, which is a deliberate limitation to keep the size of addresses small. Users can generate multiple addresses for the same identifier like account ID or public key, in order to communicate different interfaces to senders. In other words, there could be multiple different addresses that point to the same account, each encoding a different interface. So, the relationship from addresses to their underlying identifiers is n-to-1.

As an example, these addresses contain the same account ID but different routing parameters:

```text
mm1arp0azyk9jugtgpnnhle8daav58nczzr_qpgqqwcfx0p
mm1arp0azyk9jugtgpnnhle8daav58nczzr_qzsqqd4avz7
mm1arp0azyk9jugtgpnnhle8daav58nczzr_qruqqqgqjmsgjsh3687mt2w0qtqunxt3th442j48qwdnezl0fv6qm3x9c8zqsv7pku
```

The third example above includes an encryption key in the routing parameters, which results in a longer encoded address string.

### Address Types

The supported **address types** are:
- `AddressId::AccountId` (type `232`): An address pointing to an account ID.
  - Choosing `232` as the type byte means that all addresses that encode an account ID start with `mm1a`, where `a` conveniently indicates "account".

:::note
Adding a public key-based address type is planned.
:::

### Routing Parameters

The supported routing parameters are detailed in this section.

#### Address Interface

The address interface informs the sender of the capabilities of the [receiver account's interface](./code#interface).

The supported **address interfaces** are:
- `BasicWallet` (type `0`): The standard basic wallet interface. See the [account code](./code#interface) docs for details.

#### Note Tag Length

The note tag length routing parameter allows specifying the length of the [note tag](../note#note-discovery) that the sender should create. This parameter determines how many bits of the account ID are encoded into note tags of notes targeted to this address. This lets the owner of the account choose their level of privacy. A higher tag length makes the address ID more uniquely identifiable and reduces privacy, while a shorter length increases privacy at the cost of matching more notes published onchain.

#### Encryption Key

The encryption key routing parameter enables secure note payload encryption by allowing the receiver to provide a public encryption key in their address. When present, senders can use this key to encrypt the note payload using sealed box encryption, ensuring that only the receiver can decrypt and read the note contents.

The supported **encryption schemes** are:
- `X25519_XChaCha20Poly1305`: Curve25519-based key exchange with XChaCha20-Poly1305 authenticated encryption
- `K256_XChaCha20Poly1305`: secp256k1-based key exchange with XChaCha20-Poly1305 authenticated encryption
- `X25519_AeadPoseidon2`: Curve25519-based key exchange with Poseidon2-based authenticated encryption
- `K256_AeadPoseidon2`: secp256k1-based key exchange with Poseidon2-based authenticated encryption

The encryption key is optional in an address. If not provided, senders may use alternative encryption mechanisms or send unencrypted notes.

When an encryption key is included in the address, it is encoded in bech32 format alongside other routing parameters. The encoding consists of a 1-byte variant discriminant followed by the public key bytes (32 bytes for Curve25519 keys, 33 bytes for secp256k1 keys in their compressed format).

## Encoding

The two parts of an address are encoded as follows:
- The identifier is encoded in [**bech32**](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki). See the [account ID encoding](id.md#encoding) section for details.
- The routing parameters are encoded in bech32 as well, but without the HRP or `1` separator.
  - This means the routing parameter string's alphabet is consistent with that of the address ID.
  - It also means the routing parameters have their own checksum, which is important so address ID and routing parameters can be separated at any time without causing validation issues.
