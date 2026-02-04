use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};

use crate::address::AddressInterface;
use crate::crypto::dsa::{ecdsa_k256_keccak, eddsa_25519_sha512};
use crate::crypto::ies::SealingKey;
use crate::errors::{AddressError, Bech32Error};
use crate::note::NoteTag;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::utils::sync::LazyLock;

/// The HRP used for encoding routing parameters.
///
/// This HRP is only used internally, but needs to be well-defined for other routing parameter
/// encode/decode implementations.
///
/// `mrp` stands for Miden Routing Parameters.
static ROUTING_PARAMETERS_HRP: LazyLock<Hrp> =
    LazyLock::new(|| Hrp::parse("mrp").expect("hrp should be valid"));

/// The separator character used in bech32.
const BECH32_SEPARATOR: &str = "1";

/// The value to encode the absence of a note tag routing parameter (i.e. `None`).
///
/// The note tag length occupies 6 bits (values 0..=63). Valid tag lengths are 0..=32,
/// so we reserve the maximum 6-bit value (63) to represent `None`.
///
/// If the note tag length is absent from routing parameters, the note tag length for the address
/// will be set to the default default tag length of the address' ID component.
const ABSENT_NOTE_TAG_LEN: u8 = 63;

/// The routing parameter key for the receiver profile.
const RECEIVER_PROFILE_PARAM_KEY: u8 = 0;

/// The routing parameter key for the encryption key.
const ENCRYPTION_KEY_PARAM_KEY: u8 = 1;

/// The expected length of Ed25519/X25519 public keys in bytes.
const X25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The expected length of K256 (secp256k1) public keys in bytes (compressed format).
const K256_PUBLIC_KEY_LENGTH: usize = 33;

/// Discriminants for encryption key variants.
const ENCRYPTION_KEY_X25519_XCHACHA20POLY1305: u8 = 0;
const ENCRYPTION_KEY_K256_XCHACHA20POLY1305: u8 = 1;
const ENCRYPTION_KEY_X25519_AEAD_RPO: u8 = 2;
const ENCRYPTION_KEY_K256_AEAD_RPO: u8 = 3;

/// Parameters that define how a sender should route a note to the [`AddressId`](super::AddressId)
/// in an [`Address`](super::Address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingParameters {
    interface: AddressInterface,
    note_tag_len: Option<u8>,
    encryption_key: Option<SealingKey>,
}

impl RoutingParameters {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates new [`RoutingParameters`] from an [`AddressInterface`] and all other parameters
    /// initialized to `None`.
    pub fn new(interface: AddressInterface) -> Self {
        Self {
            interface,
            note_tag_len: None,
            encryption_key: None,
        }
    }

    /// Sets the note tag length routing parameter.
    ///
    /// The tag length determines how many bits of the address ID are encoded into [`NoteTag`]s of
    /// notes targeted to this address. This lets the receiver choose their level of privacy. A
    /// higher tag length makes the address ID more uniquely identifiable and reduces privacy,
    /// while a shorter length increases privacy at the cost of matching more notes published
    /// onchain.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tag length exceeds the maximum of [`NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH `].
    pub fn with_note_tag_len(mut self, note_tag_len: u8) -> Result<Self, AddressError> {
        if note_tag_len > NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH {
            return Err(AddressError::TagLengthTooLarge(note_tag_len));
        }

        self.note_tag_len = Some(note_tag_len);
        Ok(self)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the note tag length preference.
    ///
    /// This is guaranteed to be in range `0..=32` (i.e. at most
    /// [`NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH `]).
    pub fn note_tag_len(&self) -> Option<u8> {
        self.note_tag_len
    }

    /// Returns the [`AddressInterface`] of the account to which the address points.
    pub fn interface(&self) -> AddressInterface {
        self.interface
    }

    /// Returns the public encryption key.
    pub fn encryption_key(&self) -> Option<&SealingKey> {
        self.encryption_key.as_ref()
    }

    /// Sets the encryption key routing parameter.
    ///
    /// This allows senders to encrypt note payloads using sealed box encryption
    /// for the recipient of this address.
    pub fn with_encryption_key(mut self, key: SealingKey) -> Self {
        self.encryption_key = Some(key);
        self
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Encodes [`RoutingParameters`] to a byte vector.
    pub(crate) fn encode_to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::new();

        // Append the receiver profile key and the encoded value to the vector.
        encoded.push(RECEIVER_PROFILE_PARAM_KEY);
        encoded.extend(encode_receiver_profile(self.interface, self.note_tag_len));

        // Append the encryption key if present.
        if let Some(encryption_key) = &self.encryption_key {
            encoded.push(ENCRYPTION_KEY_PARAM_KEY);
            encode_encryption_key(encryption_key, &mut encoded);
        }

        encoded
    }

    /// Encodes [`RoutingParameters`] to a bech32 string _without_ the leading hrp and separator.
    pub(crate) fn encode_to_string(&self) -> String {
        let encoded = self.encode_to_bytes();

        let bech32_str =
            bech32::encode::<Bech32m>(*ROUTING_PARAMETERS_HRP, &encoded).expect("TODO");
        let encoded_str = bech32_str
            .strip_prefix(ROUTING_PARAMETERS_HRP.as_str())
            .expect("bech32 str should start with the hrp");
        let encoded_str = encoded_str
            .strip_prefix(BECH32_SEPARATOR)
            .expect("encoded str should start with bech32 separator `1`");
        encoded_str.to_owned()
    }

    /// Decodes [`RoutingParameters`] from a bech32 string _without_ the leading hrp and separator.
    pub(crate) fn decode(mut bech32_string: String) -> Result<Self, AddressError> {
        // ------ Decode bech32 string into bytes ------

        // Reinsert the expected HRP into the string that is stripped during encoding.
        bech32_string.insert_str(0, BECH32_SEPARATOR);
        bech32_string.insert_str(0, ROUTING_PARAMETERS_HRP.as_str());

        // We use CheckedHrpString with an explicit checksum algorithm so we don't allow the
        // `Bech32` or `NoChecksum` algorithms.
        let checked_string =
            CheckedHrpstring::new::<Bech32m>(&bech32_string).map_err(|source| {
                // The CheckedHrpStringError does not implement core::error::Error, only
                // std::error::Error, so for now we convert it to a String. Even if it will
                // implement the trait in the future, we should include it as an opaque
                // error since the crate does not have a stable release yet.
                AddressError::decode_error_with_source(
                    "failed to decode routing parameters bech32 string",
                    Bech32Error::DecodeError(source.to_string().into()),
                )
            })?;

        Self::decode_from_bytes(checked_string.byte_iter())
    }

    /// Decodes [`RoutingParameters`] from a byte iterator.
    pub(crate) fn decode_from_bytes(
        mut byte_iter: impl ExactSizeIterator<Item = u8>,
    ) -> Result<Self, AddressError> {
        let mut interface = None;
        let mut note_tag_len = None;
        let mut encryption_key = None;

        while let Some(key) = byte_iter.next() {
            match key {
                RECEIVER_PROFILE_PARAM_KEY => {
                    if interface.is_some() {
                        return Err(AddressError::decode_error(
                            "duplicate receiver profile routing parameter",
                        ));
                    }
                    let receiver_profile = decode_receiver_profile(&mut byte_iter)?;
                    interface = Some(receiver_profile.0);
                    note_tag_len = receiver_profile.1;
                },
                ENCRYPTION_KEY_PARAM_KEY => {
                    if encryption_key.is_some() {
                        return Err(AddressError::decode_error(
                            "duplicate encryption key routing parameter",
                        ));
                    }
                    encryption_key = Some(decode_encryption_key(&mut byte_iter)?);
                },
                other => {
                    return Err(AddressError::UnknownRoutingParameterKey(other));
                },
            }
        }

        let interface = interface.ok_or_else(|| {
            AddressError::decode_error("interface must be present in routing parameters")
        })?;

        let mut routing_parameters = RoutingParameters::new(interface);
        routing_parameters.note_tag_len = note_tag_len;
        routing_parameters.encryption_key = encryption_key;

        Ok(routing_parameters)
    }
}

impl Serializable for RoutingParameters {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let bytes = self.encode_to_bytes();
        // Due to the bech32 constraint of max 633 bytes, a u16 is sufficient.
        let num_bytes = bytes.len() as u16;

        target.write_u16(num_bytes);
        target.write_many(bytes);
    }
}

impl Deserializable for RoutingParameters {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_bytes = source.read_u16()?;
        let bytes: Vec<u8> = source.read_many(num_bytes as usize)?;

        Self::decode_from_bytes(bytes.into_iter())
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// ENCODING / DECODING HELPERS
// ================================================================================================

/// Returns receiver profile bytes constructed from the provided interface and note tag length.
fn encode_receiver_profile(interface: AddressInterface, note_tag_len: Option<u8>) -> [u8; 2] {
    let note_tag_len = note_tag_len.unwrap_or(ABSENT_NOTE_TAG_LEN);

    let interface = interface as u16;
    debug_assert_eq!(interface >> 10, 0, "address interface should fit into 10 bits");

    // The interface takes up 10 bits and the tag length 6 bits, so we can merge them
    // together.
    let tag_len = (note_tag_len as u16) << 10;
    let receiver_profile: u16 = tag_len | interface;
    receiver_profile.to_be_bytes()
}

/// Reads the receiver profile from the provided bytes.
fn decode_receiver_profile(
    byte_iter: &mut impl ExactSizeIterator<Item = u8>,
) -> Result<(AddressInterface, Option<u8>), AddressError> {
    if byte_iter.len() < 2 {
        return Err(AddressError::decode_error("expected two bytes to decode receiver profile"));
    };

    let byte0 = byte_iter.next().expect("byte0 should exist");
    let byte1 = byte_iter.next().expect("byte1 should exist");
    let receiver_profile = u16::from_be_bytes([byte0, byte1]);

    let tag_len = (receiver_profile >> 10) as u8;
    let note_tag_len = match tag_len {
        ABSENT_NOTE_TAG_LEN => None,
        0..=32 => Some(tag_len),
        _ => {
            return Err(AddressError::decode_error(format!("invalid note tag length {}", tag_len)));
        },
    };

    let addr_interface = receiver_profile & 0b0000_0011_1111_1111;
    let addr_interface = AddressInterface::try_from(addr_interface).map_err(|err| {
        AddressError::decode_error_with_source("failed to decode address interface", err)
    })?;

    Ok((addr_interface, note_tag_len))
}

/// Append encryption key variant discriminant and key to the provided vector of bytes.
fn encode_encryption_key(key: &SealingKey, encoded: &mut Vec<u8>) {
    match key {
        SealingKey::X25519XChaCha20Poly1305(pk) => {
            encoded.push(ENCRYPTION_KEY_X25519_XCHACHA20POLY1305);
            encoded.extend(&pk.to_bytes());
        },
        SealingKey::K256XChaCha20Poly1305(pk) => {
            encoded.push(ENCRYPTION_KEY_K256_XCHACHA20POLY1305);
            encoded.extend(&pk.to_bytes());
        },
        SealingKey::X25519AeadRpo(pk) => {
            encoded.push(ENCRYPTION_KEY_X25519_AEAD_RPO);
            encoded.extend(&pk.to_bytes());
        },
        SealingKey::K256AeadRpo(pk) => {
            encoded.push(ENCRYPTION_KEY_K256_AEAD_RPO);
            encoded.extend(&pk.to_bytes());
        },
    }
}

/// Reads the encryption key from the provided bytes.
fn decode_encryption_key(
    byte_iter: &mut impl ExactSizeIterator<Item = u8>,
) -> Result<SealingKey, AddressError> {
    // Read variant discriminant
    let Some(variant) = byte_iter.next() else {
        return Err(AddressError::decode_error(
            "expected at least 1 byte for encryption key variant",
        ));
    };

    // Reconstruct the appropriate PublicEncryptionKey variant
    let public_encryption_key = match variant {
        ENCRYPTION_KEY_X25519_XCHACHA20POLY1305 => {
            SealingKey::X25519XChaCha20Poly1305(read_x25519_pub_key(byte_iter)?)
        },
        ENCRYPTION_KEY_K256_XCHACHA20POLY1305 => {
            SealingKey::K256XChaCha20Poly1305(read_k256_pub_key(byte_iter)?)
        },
        ENCRYPTION_KEY_X25519_AEAD_RPO => {
            SealingKey::X25519AeadRpo(read_x25519_pub_key(byte_iter)?)
        },
        ENCRYPTION_KEY_K256_AEAD_RPO => SealingKey::K256AeadRpo(read_k256_pub_key(byte_iter)?),
        other => {
            return Err(AddressError::decode_error(format!(
                "unknown encryption key variant: {}",
                other
            )));
        },
    };

    Ok(public_encryption_key)
}

fn read_x25519_pub_key(
    byte_iter: &mut impl ExactSizeIterator<Item = u8>,
) -> Result<eddsa_25519_sha512::PublicKey, AddressError> {
    if byte_iter.len() < X25519_PUBLIC_KEY_LENGTH {
        return Err(AddressError::decode_error(format!(
            "expected {} bytes to decode X25519 public key",
            X25519_PUBLIC_KEY_LENGTH
        )));
    }
    let key_bytes: [u8; X25519_PUBLIC_KEY_LENGTH] = read_byte_array(byte_iter);
    eddsa_25519_sha512::PublicKey::read_from_bytes(&key_bytes).map_err(|err| {
        AddressError::decode_error_with_source("failed to decode X25519 public key", err)
    })
}

fn read_k256_pub_key(
    byte_iter: &mut impl ExactSizeIterator<Item = u8>,
) -> Result<ecdsa_k256_keccak::PublicKey, AddressError> {
    if byte_iter.len() < K256_PUBLIC_KEY_LENGTH {
        return Err(AddressError::decode_error(format!(
            "expected {} bytes to decode K256 public key",
            K256_PUBLIC_KEY_LENGTH
        )));
    }
    let key_bytes: [u8; K256_PUBLIC_KEY_LENGTH] = read_byte_array(byte_iter);
    ecdsa_k256_keccak::PublicKey::read_from_bytes(&key_bytes).map_err(|err| {
        AddressError::decode_error_with_source("failed to decode K256 public key", err)
    })
}

/// Reads bytes from the provided iterator into an array of length N and returns this array.
///
/// Assumes that there are at least N bytes in the iterator.
fn read_byte_array<const N: usize>(byte_iter: &mut impl ExactSizeIterator<Item = u8>) -> [u8; N] {
    let mut array = [0u8; N];
    for byte in array.iter_mut() {
        *byte = byte_iter.next().expect("iterator should have enough bytes");
    }
    array
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use bech32::{Bech32m, Checksum, Hrp};

    use super::*;

    /// Checks the assumptions about the total length allowed in bech32 encoding.
    ///
    /// The assumption is that encoding should error if the total length of the hrp + data (encoded
    /// in GF(32)) + the separator + the checksum exceeds Bech32m::CODE_LENGTH.
    #[test]
    fn bech32_code_length_assertions() -> anyhow::Result<()> {
        let hrp = Hrp::parse("mrp").unwrap();
        let separator_len = BECH32_SEPARATOR.len();
        // The fixed number of characters included in a bech32 string.
        let fixed_num_bytes = hrp.as_str().len() + separator_len + Bech32m::CHECKSUM_LENGTH;
        let num_allowed_chars = Bech32m::CODE_LENGTH - fixed_num_bytes;
        // Multiply by the 5 bits per base32 character and divide by 8 bits per byte.
        let num_allowed_bytes = num_allowed_chars * 5 / 8;

        // The number of bytes that routing parameters effectively have available.
        assert_eq!(num_allowed_bytes, 633);

        // This amount of data is the max that should be okay to encode.
        let data_ok = vec![5; num_allowed_bytes];
        // One more byte than the max allowed amount should result in an error.
        let data_too_long = vec![5; num_allowed_bytes + 1];

        assert!(bech32::encode::<Bech32m>(hrp, &data_ok).is_ok());
        assert!(bech32::encode::<Bech32m>(hrp, &data_too_long).is_err());

        Ok(())
    }

    /// Tests bech32 encoding and decoding roundtrip with various tag lengths.
    #[test]
    fn routing_parameters_bech32_encode_decode_roundtrip() -> anyhow::Result<()> {
        // Test case 1: No explicit tag length
        let params_no_tag = RoutingParameters::new(AddressInterface::BasicWallet);
        let encoded = params_no_tag.encode_to_string();
        let decoded = RoutingParameters::decode(encoded)?;
        assert_eq!(params_no_tag, decoded);
        assert_eq!(decoded.note_tag_len(), None);

        // Test case 2: Explicit tag length 0
        let params_tag_0 =
            RoutingParameters::new(AddressInterface::BasicWallet).with_note_tag_len(0)?;
        let encoded = params_tag_0.encode_to_string();
        let decoded = RoutingParameters::decode(encoded)?;
        assert_eq!(params_tag_0, decoded);
        assert_eq!(decoded.note_tag_len(), Some(0));

        // Test case 3: Explicit tag length 6
        let params_tag_6 =
            RoutingParameters::new(AddressInterface::BasicWallet).with_note_tag_len(6)?;
        let encoded = params_tag_6.encode_to_string();
        let decoded = RoutingParameters::decode(encoded)?;
        assert_eq!(params_tag_6, decoded);
        assert_eq!(decoded.note_tag_len(), Some(6));

        // Test case 4: Explicit tag length set to max
        let params_tag_max = RoutingParameters::new(AddressInterface::BasicWallet)
            .with_note_tag_len(NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH)?;
        let encoded = params_tag_max.encode_to_string();
        let decoded = RoutingParameters::decode(encoded)?;
        assert_eq!(params_tag_max, decoded);
        assert_eq!(decoded.note_tag_len(), Some(NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH));

        Ok(())
    }

    /// Tests serialization and deserialization roundtrip with various tag lengths.
    #[test]
    fn routing_parameters_serialization() -> anyhow::Result<()> {
        // Test case 1: No explicit tag length
        let params_no_tag = RoutingParameters::new(AddressInterface::BasicWallet);
        let serialized = params_no_tag.to_bytes();
        let deserialized = RoutingParameters::read_from_bytes(&serialized)?;
        assert_eq!(params_no_tag, deserialized);
        assert_eq!(deserialized.note_tag_len(), None);

        // Test case 2: Explicit tag length 0
        let params_tag_0 =
            RoutingParameters::new(AddressInterface::BasicWallet).with_note_tag_len(0)?;
        let serialized = params_tag_0.to_bytes();
        let deserialized = RoutingParameters::read_from_bytes(&serialized)?;
        assert_eq!(params_tag_0, deserialized);
        assert_eq!(deserialized.note_tag_len(), Some(0));

        // Test case 3: Explicit tag length 6
        let params_tag_6 =
            RoutingParameters::new(AddressInterface::BasicWallet).with_note_tag_len(6)?;
        let serialized = params_tag_6.to_bytes();
        let deserialized = RoutingParameters::read_from_bytes(&serialized)?;
        assert_eq!(params_tag_6, deserialized);
        assert_eq!(deserialized.note_tag_len(), Some(6));

        // Test case 4: Explicit tag length set to max
        let params_tag_max = RoutingParameters::new(AddressInterface::BasicWallet)
            .with_note_tag_len(NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH)?;
        let serialized = params_tag_max.to_bytes();
        let deserialized = RoutingParameters::read_from_bytes(&serialized)?;
        assert_eq!(params_tag_max, deserialized);
        assert_eq!(deserialized.note_tag_len(), Some(NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH));

        Ok(())
    }

    /// Tests encoding/decoding and serialization for all encryption key variants.
    #[test]
    fn routing_parameters_all_encryption_key_variants() -> anyhow::Result<()> {
        // Helper function to test both encoding/decoding and serialization
        fn test_encryption_key_roundtrip(encryption_key: SealingKey) -> anyhow::Result<()> {
            let routing_params = RoutingParameters::new(AddressInterface::BasicWallet)
                .with_encryption_key(encryption_key.clone());

            // Test bech32 encoding/decoding
            let encoded = routing_params.encode_to_string();
            let decoded = RoutingParameters::decode(encoded)?;
            assert_eq!(routing_params, decoded);
            assert_eq!(decoded.encryption_key(), Some(&encryption_key));

            // Test serialization/deserialization
            let serialized = routing_params.to_bytes();
            let deserialized = RoutingParameters::read_from_bytes(&serialized)?;
            assert_eq!(routing_params, deserialized);
            assert_eq!(deserialized.encryption_key(), Some(&encryption_key));

            Ok(())
        }

        // Test X25519XChaCha20Poly1305
        {
            use crate::crypto::dsa::eddsa_25519_sha512::SecretKey;
            let secret_key = SecretKey::with_rng(&mut rand::rng());
            let public_key = secret_key.public_key();
            let encryption_key = SealingKey::X25519XChaCha20Poly1305(public_key);
            test_encryption_key_roundtrip(encryption_key)?;
        }

        // Test K256XChaCha20Poly1305
        {
            use crate::crypto::dsa::ecdsa_k256_keccak::SecretKey;
            let secret_key = SecretKey::with_rng(&mut rand::rng());
            let public_key = secret_key.public_key();
            let encryption_key = SealingKey::K256XChaCha20Poly1305(public_key);
            test_encryption_key_roundtrip(encryption_key)?;
        }

        // Test X25519AeadRpo
        {
            use crate::crypto::dsa::eddsa_25519_sha512::SecretKey;
            let secret_key = SecretKey::with_rng(&mut rand::rng());
            let public_key = secret_key.public_key();
            let encryption_key = SealingKey::X25519AeadRpo(public_key);
            test_encryption_key_roundtrip(encryption_key)?;
        }

        // Test K256AeadRpo
        {
            use crate::crypto::dsa::ecdsa_k256_keccak::SecretKey;
            let secret_key = SecretKey::with_rng(&mut rand::rng());
            let public_key = secret_key.public_key();
            let encryption_key = SealingKey::K256AeadRpo(public_key);
            test_encryption_key_roundtrip(encryption_key)?;
        }

        Ok(())
    }
}
