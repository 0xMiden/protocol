mod r#type;

pub use r#type::AddressType;

mod routing_parameters;
use alloc::borrow::ToOwned;

pub use routing_parameters::RoutingParameters;

mod interface;
mod network_id;
use alloc::string::String;

pub use interface::AddressInterface;
use miden_processor::DeserializationError;
pub use network_id::{CustomNetworkId, NetworkId};

use crate::crypto::ies::SealingKey;
use crate::errors::AddressError;
use crate::note::NoteTag;
use crate::utils::serde::{ByteWriter, Deserializable, Serializable};

mod address_id;
pub use address_id::AddressId;

/// A user-facing address in Miden.
///
/// An address consists of an [`AddressId`] and optional [`RoutingParameters`].
///
/// A user who wants to receive a note creates an address and sends it to the sender of the note.
/// The sender creates a note intended for the holder of this address ID (e.g., it provides
/// discoverability and potentially access-control) and the routing parameters inform the sender
/// about various aspects like:
/// - what kind of note the receiver's account can consume.
/// - how the receiver discovers the note.
/// - how to encrypt the note for the receiver.
///
/// It can be encoded to a string using [`Self::encode`] and decoded using [`Self::decode`].
/// If routing parameters are present, the ID and parameters are separated by
/// [`Address::SEPARATOR`].
///
/// ## Example
///
/// ```text
/// # account ID
/// mm1apt3l475qemeqqp57xjycfdwcvw0sfhq
/// # account ID + routing parameters (interface & note tag length)
/// mm1apt3l475qemeqqp57xjycfdwcvw0sfhq_qruqqypuyph
/// # account ID + routing parameters (interface, note tag length, encryption key)
/// mm1apt3l475qemeqqp57xjycfdwcvw0sfhq_qruqqqgqjmsgjsh3687mt2w0qtqunxt3th442j48qwdnezl0fv6qm3x9c8zqsv7pku
/// ```
///
/// The encoding of an address without routing parameters matches the encoding of the underlying
/// identifier exactly (e.g. an account ID). This provides compatibility between identifiers and
/// addresses and gives end-users a hint that an address is only an extension of the identifier
/// (e.g. their account's ID) that they are likely to recognize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    id: AddressId,
    routing_params: Option<RoutingParameters>,
}

impl Address {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The separator character in an encoded address between the ID and routing parameters.
    pub const SEPARATOR: char = '_';

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new address from an [`AddressId`] and routing parameters set to `None`.
    ///
    /// To set routing parameters, use [`Self::with_routing_parameters`].
    pub fn new(id: impl Into<AddressId>) -> Self {
        Self { id: id.into(), routing_params: None }
    }

    /// Sets the routing parameters of the address.
    /// Validation of tag length, interface, and encryption key is handled
    /// internally by [`RoutingParameters`]. This method simply attaches the
    /// provided parameters to the address.
    pub fn with_routing_parameters(mut self, routing_params: RoutingParameters) -> Self {
        self.routing_params = Some(routing_params);
        self
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the identifier of the address.
    pub fn id(&self) -> AddressId {
        self.id
    }

    /// Returns the [`AddressInterface`] of the account to which the address points.
    pub fn interface(&self) -> Option<AddressInterface> {
        self.routing_params.as_ref().map(RoutingParameters::interface)
    }

    /// Returns the preferred tag length.
    ///
    /// This is guaranteed to be in range `0..=32` (e.g. the maximum of
    /// [`NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH `]).
    pub fn note_tag_len(&self) -> u8 {
        self.routing_params
            .as_ref()
            .and_then(RoutingParameters::note_tag_len)
            .unwrap_or(NoteTag::DEFAULT_ACCOUNT_TARGET_TAG_LENGTH)
    }

    /// Returns a note tag derived from this address.
    pub fn to_note_tag(&self) -> NoteTag {
        let note_tag_len = self.note_tag_len();

        match self.id {
            AddressId::AccountId(id) => NoteTag::with_custom_account_target(id, note_tag_len)
                .expect(
                    "address should validate that tag len does not exceed \
                     MAX_ACCOUNT_TARGET_TAG_LENGTH  bits",
                ),
        }
    }

    /// Returns the optional public encryption key from routing parameters.
    ///
    /// This key can be used for sealed box encryption when sending notes to this address.
    pub fn encryption_key(&self) -> Option<&SealingKey> {
        self.routing_params.as_ref().and_then(RoutingParameters::encryption_key)
    }

    /// Encodes the [`Address`] into a string.
    ///
    /// ## Encoding
    ///
    /// The encoding of an address into a string is done as follows:
    /// - Encode the underlying [`AddressId`] to a bech32 string.
    /// - If routing parameters are present:
    ///   - Append the [`Address::SEPARATOR`] to that string.
    ///   - Append the encoded routing parameters to that string.
    pub fn encode(&self, network_id: NetworkId) -> String {
        let mut encoded = match self.id {
            AddressId::AccountId(id) => id.to_bech32(network_id),
        };

        if let Some(routing_params) = &self.routing_params {
            encoded.push(Self::SEPARATOR);
            encoded.push_str(&routing_params.encode_to_string());
        }

        encoded
    }

    /// Decodes an address string into the [`NetworkId`] and an [`Address`].
    ///
    /// See [`Address::encode`] for details on the format. The procedure for decoding the string
    /// into the address are the inverse operations of encoding.
    pub fn decode(address_str: &str) -> Result<(NetworkId, Self), AddressError> {
        if address_str.ends_with(Self::SEPARATOR) {
            return Err(AddressError::TrailingSeparator);
        }

        let mut split = address_str.split(Self::SEPARATOR);
        let encoded_identifier = split
            .next()
            .ok_or_else(|| AddressError::decode_error("identifier missing in address string"))?;

        let (network_id, identifier) = AddressId::decode(encoded_identifier)?;

        let mut address = Address::new(identifier);

        if let Some(encoded_routing_params) = split.next() {
            let routing_params = RoutingParameters::decode(encoded_routing_params.to_owned())?;
            address = address.with_routing_parameters(routing_params);
        }

        Ok((network_id, address))
    }
}

impl Serializable for Address {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.id.write_into(target);
        self.routing_params.write_into(target);
    }
}

impl Deserializable for Address {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let identifier: AddressId = source.read()?;
        let routing_params: Option<RoutingParameters> = source.read()?;

        let mut address = Self::new(identifier);

        if let Some(routing_params) = routing_params {
            address = address.with_routing_parameters(routing_params);
        }

        Ok(address)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::str::FromStr;

    use assert_matches::assert_matches;
    use bech32::{Bech32, Bech32m, NoChecksum};

    use super::*;
    use crate::account::{AccountId, AccountStorageMode, AccountType};
    use crate::address::CustomNetworkId;
    use crate::errors::{AccountIdError, Bech32Error};
    use crate::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, AccountIdBuilder};

    /// Tests that an account ID address can be encoded and decoded.
    #[test]
    fn address_encode_decode_roundtrip() -> anyhow::Result<()> {
        // We use this to check that encoding does not panic even when using the longest possible
        // HRP.
        let longest_possible_hrp =
            "01234567890123456789012345678901234567890123456789012345678901234567890123456789012";
        assert_eq!(longest_possible_hrp.len(), 83);

        let rng = &mut rand::rng();
        for network_id in [
            NetworkId::Mainnet,
            NetworkId::Custom(Box::new(CustomNetworkId::from_str("custom").unwrap())),
            NetworkId::Custom(Box::new(CustomNetworkId::from_str(longest_possible_hrp).unwrap())),
        ] {
            for (idx, account_id) in [
                AccountIdBuilder::new()
                    .account_type(AccountType::FungibleFaucet)
                    .build_with_rng(rng),
                AccountIdBuilder::new()
                    .account_type(AccountType::NonFungibleFaucet)
                    .build_with_rng(rng),
                AccountIdBuilder::new()
                    .account_type(AccountType::RegularAccountImmutableCode)
                    .build_with_rng(rng),
                AccountIdBuilder::new()
                    .account_type(AccountType::RegularAccountUpdatableCode)
                    .build_with_rng(rng),
            ]
            .into_iter()
            .enumerate()
            {
                // Encode/Decode without routing parameters should be valid.
                let mut address = Address::new(account_id);

                let bech32_string = address.encode(network_id.clone());
                assert!(
                    !bech32_string.contains(Address::SEPARATOR),
                    "separator should not be present in address without routing params"
                );
                let (decoded_network_id, decoded_address) = Address::decode(&bech32_string)?;

                assert_eq!(network_id, decoded_network_id, "network id failed in {idx}");
                assert_eq!(address, decoded_address, "address failed in {idx}");

                let AddressId::AccountId(decoded_account_id) = address.id();
                assert_eq!(account_id, decoded_account_id);

                // Encode/Decode with routing parameters should be valid.
                address = address.with_routing_parameters(
                    RoutingParameters::new(AddressInterface::BasicWallet)
                        .with_note_tag_len(NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH)?,
                );

                let bech32_string = address.encode(network_id.clone());
                assert!(
                    bech32_string.contains(Address::SEPARATOR),
                    "separator should be present in address without routing params"
                );
                let (decoded_network_id, decoded_address) = Address::decode(&bech32_string)?;

                assert_eq!(network_id, decoded_network_id, "network id failed in {idx}");
                assert_eq!(address, decoded_address, "address failed in {idx}");

                let AddressId::AccountId(decoded_account_id) = address.id();
                assert_eq!(account_id, decoded_account_id);
            }
        }

        Ok(())
    }

    #[test]
    fn address_decoding_fails_on_trailing_separator() -> anyhow::Result<()> {
        let id = AccountIdBuilder::new()
            .account_type(AccountType::FungibleFaucet)
            .build_with_rng(&mut rand::rng());

        let address = Address::new(id);
        let mut encoded_address = address.encode(NetworkId::Devnet);
        encoded_address.push(Address::SEPARATOR);

        let err = Address::decode(&encoded_address).unwrap_err();
        assert_matches!(err, AddressError::TrailingSeparator);

        Ok(())
    }

    /// Tests that an invalid checksum returns an error.
    #[test]
    fn bech32_invalid_checksum() -> anyhow::Result<()> {
        let network_id = NetworkId::Mainnet;
        let account_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
        let address = Address::new(account_id).with_routing_parameters(
            RoutingParameters::new(AddressInterface::BasicWallet).with_note_tag_len(14)?,
        );

        let bech32_string = address.encode(network_id);
        let mut invalid_bech32_1 = bech32_string.clone();
        invalid_bech32_1.remove(0);
        let mut invalid_bech32_2 = bech32_string.clone();
        invalid_bech32_2.remove(7);

        let error = Address::decode(&invalid_bech32_1).unwrap_err();
        assert_matches!(error, AddressError::Bech32DecodeError(Bech32Error::DecodeError(_)));

        let error = Address::decode(&invalid_bech32_2).unwrap_err();
        assert_matches!(error, AddressError::Bech32DecodeError(Bech32Error::DecodeError(_)));

        Ok(())
    }

    /// Tests that an unknown address type returns an error.
    #[test]
    fn bech32_unknown_address_type() {
        let invalid_bech32_address =
            bech32::encode::<Bech32m>(NetworkId::Mainnet.into_hrp(), &[250]).unwrap();

        let error = Address::decode(&invalid_bech32_address).unwrap_err();
        assert_matches!(
            error,
            AddressError::Bech32DecodeError(Bech32Error::UnknownAddressType(250))
        );
    }

    /// Tests that a bech32 using a disallowed checksum returns an error.
    #[test]
    fn bech32_invalid_other_checksum() {
        let account_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
        let address_id_bytes = AddressId::from(account_id).to_bytes();

        // Use Bech32 instead of Bech32m which is disallowed.
        let invalid_bech32_regular =
            bech32::encode::<Bech32>(NetworkId::Mainnet.into_hrp(), &address_id_bytes).unwrap();
        let error = Address::decode(&invalid_bech32_regular).unwrap_err();
        assert_matches!(error, AddressError::Bech32DecodeError(Bech32Error::DecodeError(_)));

        // Use no checksum instead of Bech32m which is disallowed.
        let invalid_bech32_no_checksum =
            bech32::encode::<NoChecksum>(NetworkId::Mainnet.into_hrp(), &address_id_bytes).unwrap();
        let error = Address::decode(&invalid_bech32_no_checksum).unwrap_err();
        assert_matches!(error, AddressError::Bech32DecodeError(Bech32Error::DecodeError(_)));
    }

    /// Tests that a bech32 string encoding data of an unexpected length returns an error.
    #[test]
    fn bech32_invalid_length() {
        let account_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
        let mut address_id_bytes = AddressId::from(account_id).to_bytes();
        // Add one byte to make the length invalid.
        address_id_bytes.push(5);

        let invalid_bech32 =
            bech32::encode::<Bech32m>(NetworkId::Mainnet.into_hrp(), &address_id_bytes).unwrap();

        let error = Address::decode(&invalid_bech32).unwrap_err();
        assert_matches!(
            error,
            AddressError::AccountIdDecodeError(AccountIdError::Bech32DecodeError(
                Bech32Error::InvalidDataLength { .. }
            ))
        );
    }

    /// Tests that an Address can be serialized and deserialized
    #[test]
    fn address_serialization() -> anyhow::Result<()> {
        let rng = &mut rand::rng();

        for account_type in [
            AccountType::FungibleFaucet,
            AccountType::NonFungibleFaucet,
            AccountType::RegularAccountImmutableCode,
            AccountType::RegularAccountUpdatableCode,
        ]
        .into_iter()
        {
            let account_id = AccountIdBuilder::new().account_type(account_type).build_with_rng(rng);
            let address = Address::new(account_id).with_routing_parameters(
                RoutingParameters::new(AddressInterface::BasicWallet)
                    .with_note_tag_len(NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH)?,
            );

            let serialized = address.to_bytes();
            let deserialized = Address::read_from_bytes(&serialized)?;
            assert_eq!(address, deserialized);
        }

        Ok(())
    }

    /// Tests that an address with encryption key can be created and used.
    #[test]
    fn address_with_encryption_key() -> anyhow::Result<()> {
        use crate::crypto::dsa::eddsa_25519_sha512::SecretKey;
        use crate::crypto::ies::{SealingKey, UnsealingKey};

        let rng = &mut rand::rng();
        let account_id = AccountIdBuilder::new()
            .account_type(AccountType::FungibleFaucet)
            .build_with_rng(rng);

        // Create keypair using rand::rng()
        let secret_key = SecretKey::with_rng(rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key.clone());
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key.clone());

        // Create address with encryption key
        let address = Address::new(account_id).with_routing_parameters(
            RoutingParameters::new(AddressInterface::BasicWallet)
                .with_encryption_key(sealing_key.clone()),
        );

        // Verify encryption key is present
        let retrieved_key =
            address.encryption_key().expect("encryption key should be present").clone();
        assert_eq!(retrieved_key, sealing_key);

        // Test seal/unseal round-trip
        let plaintext = b"hello world";
        let sealed_message =
            retrieved_key.seal_bytes(rng, plaintext).expect("sealing should succeed");
        let decrypted =
            unsealing_key.unseal_bytes(sealed_message).expect("unsealing should succeed");
        assert_eq!(decrypted.as_slice(), plaintext);

        Ok(())
    }

    /// Tests that an address with encryption key can be encoded/decoded.
    #[test]
    fn address_encryption_key_encode_decode() -> anyhow::Result<()> {
        use crate::crypto::dsa::eddsa_25519_sha512::SecretKey;

        let rng = &mut rand::rng();
        // Use a local account type (RegularAccountImmutableCode) instead of network
        // (FungibleFaucet)
        let account_id = AccountIdBuilder::new()
            .account_type(AccountType::RegularAccountImmutableCode)
            .storage_mode(AccountStorageMode::Public)
            .build_with_rng(rng);

        // Create keypair
        let secret_key = SecretKey::with_rng(rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);

        // Create address with encryption key
        let address = Address::new(account_id).with_routing_parameters(
            RoutingParameters::new(AddressInterface::BasicWallet)
                .with_encryption_key(sealing_key.clone()),
        );

        // Encode and decode
        let encoded = address.encode(NetworkId::Mainnet);
        let (decoded_network, decoded_address) = Address::decode(&encoded)?;

        assert_eq!(decoded_network, NetworkId::Mainnet);
        assert_eq!(address, decoded_address);

        // Verify encryption key is preserved
        let decoded_key = decoded_address
            .encryption_key()
            .expect("encryption key should be present")
            .clone();
        assert_eq!(decoded_key, sealing_key);

        Ok(())
    }

    #[test]
    fn address_allows_max_note_tag_len() -> anyhow::Result<()> {
        let account_id = AccountIdBuilder::new()
            .account_type(AccountType::RegularAccountImmutableCode)
            .build_with_rng(&mut rand::rng());

        let address = Address::new(account_id).with_routing_parameters(
            RoutingParameters::new(AddressInterface::BasicWallet).with_note_tag_len(32)?,
        );

        assert_eq!(address.note_tag_len(), 32);

        Ok(())
    }
}
