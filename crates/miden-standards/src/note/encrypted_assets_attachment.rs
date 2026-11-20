use alloc::vec::Vec;

use miden_protocol::account::{StorageMap, StorageMapKey, StorageSlot, StorageSlotName};
use miden_protocol::asset::Asset;
use miden_protocol::crypto::ecdh::ecgfp5::{PublicKey, SecretKey};
use miden_protocol::crypto::ies::ecgfp5_eidos::{self, Envelope};
use miden_protocol::errors::{AssetError, NoteError};
use miden_protocol::note::{
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteDetailsCommitment,
    NoteId,
    NoteMetadata,
    NoteRecipient,
    NoteScriptRoot,
    Nullifier,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::note::StandardNoteAttachment;

// CONSTANTS
// ================================================================================================

static ISSUER_KEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::attachments::encrypted_assets::issuer_key")
        .expect("storage slot name should be valid")
});

/// The map key of the public key commitment in the issuer key slot.
const ISSUER_KEY_COMMITMENT_INDEX: u32 = 0;

/// The map key of the first four elements of the public key in the issuer key slot.
const ISSUER_KEY_HEAD_INDEX: u32 = 1;

/// The map key of the fifth element of the public key in the issuer key slot.
const ISSUER_KEY_TAIL_INDEX: u32 = 2;

// ENCRYPTED ASSETS ATTACHMENT
// ================================================================================================

/// The plaintext of an encrypted asset attachment, which lets the issuer of an asset track the
/// private notes that carry it.
///
/// A faucet's `on_before_note_sealed` callback builds the attachment of a private note with
/// `miden::standards::attachments::encrypted_assets::build_attachment`, which encrypts the note's
/// details to the [`EncryptedAssetsIssuerKey`] in the faucet's storage. The plaintext of a note
/// with `n` assets holds `3 + 2n` words, with the assets in note order:
///
/// ```text
/// [SERIAL_NUM, SCRIPT_ROOT, STORAGE_COMMITMENT,
///  ASSET_ID_0, ASSET_VALUE_0, ..., ASSET_ID_{n-1}, ASSET_VALUE_{n-1}]
/// ```
///
/// The attachment content is the EcGFp5/Eidos envelope of the plaintext under [`Self::CONTEXT`],
/// `[R(5), tag(2), plaintext_len, ciphertext(2 * plaintext_len)]`, which is `8 + 4n` words. It
/// carries no identifier of the issuer key.
///
/// The issuer decrypts the attachment with [`Self::decrypt`] and computes the note's ID and
/// nullifier from the plaintext and the note's [`NoteMetadata`]. An ID that matches the note's ID
/// shows that the plaintext describes the note. A note that holds the assets of several faucets
/// that build the attachment carries one attachment per faucet, so the issuer tries each
/// attachment with [`Self::ATTACHMENT_SCHEME`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedAssetsAttachment {
    serial_num: Word,
    script_root: NoteScriptRoot,
    storage_commitment: Word,
    assets: NoteAssets,
}

impl EncryptedAssetsAttachment {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The standardized scheme of encrypted asset attachments.
    pub const ATTACHMENT_SCHEME: NoteAttachmentScheme =
        StandardNoteAttachment::EncryptedAssets.attachment_scheme();

    /// The version of the encrypted asset attachment format.
    pub const FORMAT_VERSION: u8 = 1;

    /// The context under which the plaintext is encrypted: the attachment scheme and the format
    /// version.
    pub const CONTEXT: [Felt; 2] = [
        Felt::from_u16(Self::ATTACHMENT_SCHEME.as_u16()),
        Felt::from_u8(Self::FORMAT_VERSION),
    ];

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns the plaintext for a note with the provided details.
    pub fn new(
        serial_num: Word,
        script_root: NoteScriptRoot,
        storage_commitment: Word,
        assets: NoteAssets,
    ) -> Self {
        Self {
            serial_num,
            script_root,
            storage_commitment,
            assets,
        }
    }

    /// Decrypts the provided encrypted asset attachment with the issuer's secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the attachment scheme is not [`Self::ATTACHMENT_SCHEME`].
    /// - the attachment content is not an envelope.
    /// - the envelope does not decrypt with `issuer_secret_key` under [`Self::CONTEXT`].
    /// - the plaintext does not decode, see [`Self::try_from_elements`].
    pub fn decrypt(
        attachment: &NoteAttachment,
        issuer_secret_key: &SecretKey,
    ) -> Result<Self, EncryptedAssetsAttachmentError> {
        if attachment.attachment_scheme() != Self::ATTACHMENT_SCHEME {
            return Err(EncryptedAssetsAttachmentError::AttachmentSchemeMismatch(
                attachment.attachment_scheme(),
            ));
        }

        let envelope = Envelope::from_elements(attachment.as_elements())
            .map_err(EncryptedAssetsAttachmentError::InvalidEnvelope)?;
        let plaintext = ecgfp5_eidos::open(issuer_secret_key, &Self::CONTEXT, &envelope)
            .map_err(EncryptedAssetsAttachmentError::DecryptionFailed)?;

        Self::try_from_elements(&plaintext)
    }

    /// Decodes the plaintext from its elements.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the number of elements is not `12 + 8n` for some number of assets `n`.
    /// - an asset is invalid, or the assets do not form valid [`NoteAssets`].
    pub fn try_from_elements(elements: &[Felt]) -> Result<Self, EncryptedAssetsAttachmentError> {
        let invalid_length = EncryptedAssetsAttachmentError::InvalidPlaintextLength(elements.len());

        let (words, []) = elements.as_chunks::<{ Word::NUM_ELEMENTS }>() else {
            return Err(invalid_length);
        };
        let Some((&[serial_num, script_root, storage_commitment], asset_words)) =
            words.split_first_chunk::<3>()
        else {
            return Err(invalid_length);
        };
        let (asset_words, []) = asset_words.as_chunks::<2>() else {
            return Err(invalid_length);
        };

        let assets = asset_words
            .iter()
            .map(|&[id, value]| Asset::from_id_and_value_words(Word::new(id), Word::new(value)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(EncryptedAssetsAttachmentError::InvalidAsset)?;
        let assets =
            NoteAssets::new(assets).map_err(EncryptedAssetsAttachmentError::InvalidAssets)?;

        Ok(Self::new(
            Word::new(serial_num),
            NoteScriptRoot::from_raw(Word::new(script_root)),
            Word::new(storage_commitment),
            assets,
        ))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the serial number of the note.
    pub fn serial_num(&self) -> Word {
        self.serial_num
    }

    /// Returns the script root of the note.
    pub fn script_root(&self) -> NoteScriptRoot {
        self.script_root
    }

    /// Returns the storage commitment of the note.
    pub fn storage_commitment(&self) -> Word {
        self.storage_commitment
    }

    /// Returns the assets of the note.
    pub fn assets(&self) -> &NoteAssets {
        &self.assets
    }

    /// Computes the ID of a note with these details and the provided metadata.
    pub fn note_id(&self, metadata: &NoteMetadata) -> NoteId {
        let recipient_digest = NoteRecipient::compute_digest(
            self.serial_num,
            self.script_root,
            self.storage_commitment,
        );
        let details_commitment =
            NoteDetailsCommitment::from_raw_commitments(recipient_digest, self.assets.commitment());

        NoteId::new(details_commitment, metadata)
    }

    /// Computes the nullifier of a note with these details and the provided metadata.
    pub fn nullifier(&self, metadata: &NoteMetadata) -> Nullifier {
        Nullifier::new(
            self.script_root,
            self.storage_commitment,
            self.assets.commitment(),
            self.serial_num,
            metadata.to_metadata_word(),
            metadata.attachments_commitment(),
        )
    }

    /// Returns the elements of the plaintext.
    pub fn to_elements(&self) -> Vec<Felt> {
        [self.serial_num, self.script_root.as_word(), self.storage_commitment]
            .into_iter()
            .flatten()
            .chain(self.assets.to_elements())
            .collect()
    }
}

// ENCRYPTED ASSETS ISSUER KEY
// ================================================================================================

/// The public key to which `miden::standards::attachments::encrypted_assets::build_attachment`
/// encrypts the [`EncryptedAssetsAttachment`] of a private note.
///
/// A faucet stores the key in the map slot
/// `miden::standards::attachments::encrypted_assets::issuer_key`, which holds the following
/// entries:
///
/// ```text
/// [0, 0, 0, 0] => PUBLIC_KEY_COMMITMENT
/// [1, 0, 0, 0] => [public_key_0, public_key_1, public_key_2, public_key_3]
/// [2, 0, 0, 0] => [public_key_4, 0, 0, 0]
/// ```
///
/// where `PUBLIC_KEY_COMMITMENT` is [`PublicKey::to_commitment`] and `public_key_i` are the
/// elements of [`PublicKey::to_elements`]. To rotate the key, the issuer replaces these entries
/// and keeps its previous secret keys to decrypt the attachments built before the rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedAssetsIssuerKey {
    public_key: PublicKey,
}

impl EncryptedAssetsIssuerKey {
    /// Returns a new issuer key from the provided public key.
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Returns the [`StorageSlotName`] of the issuer key slot.
    pub fn slot_name() -> &'static StorageSlotName {
        &ISSUER_KEY_SLOT_NAME
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Consumes the issuer key and returns the [`StorageSlot`] that holds it.
    pub fn into_storage_slot(self) -> StorageSlot {
        let [e0, e1, e2, e3, e4] = self.public_key.to_elements();
        let entries = [
            (
                StorageMapKey::from_index(ISSUER_KEY_COMMITMENT_INDEX),
                self.public_key.to_commitment(),
            ),
            (StorageMapKey::from_index(ISSUER_KEY_HEAD_INDEX), Word::new([e0, e1, e2, e3])),
            (
                StorageMapKey::from_index(ISSUER_KEY_TAIL_INDEX),
                Word::new([e4, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            ),
        ];
        let storage_map = StorageMap::with_entries(entries)
            .expect("issuer key entries should have distinct keys");

        StorageSlot::with_map(Self::slot_name().clone(), storage_map)
    }
}

// ENCRYPTED ASSETS ATTACHMENT ERROR
// ================================================================================================

/// Errors that can occur when decrypting or decoding an [`EncryptedAssetsAttachment`].
#[derive(Debug, thiserror::Error)]
pub enum EncryptedAssetsAttachmentError {
    #[error(
        "attachment scheme {0} does not match expected scheme {expected}",
        expected = EncryptedAssetsAttachment::ATTACHMENT_SCHEME
    )]
    AttachmentSchemeMismatch(NoteAttachmentScheme),
    #[error("attachment content is not an encryption envelope")]
    InvalidEnvelope(#[source] ecgfp5_eidos::Error),
    #[error("failed to decrypt the envelope")]
    DecryptionFailed(#[source] ecgfp5_eidos::Error),
    #[error("plaintext of {0} elements does not hold a note's details")]
    InvalidPlaintextLength(usize),
    #[error("plaintext holds an invalid asset")]
    InvalidAsset(#[source] AssetError),
    #[error("plaintext holds invalid note assets")]
    InvalidAssets(#[source] NoteError),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use miden_protocol::account::{StorageMapKey, StorageSlotContent};
    use miden_protocol::asset::{FungibleAsset, NonFungibleAsset};
    use miden_protocol::crypto::ecdh::ecgfp5::SecretKey;
    use miden_protocol::errors::NoteError;
    use miden_protocol::note::{NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteScriptRoot};
    use miden_protocol::{Felt, Word};

    use super::{
        EncryptedAssetsAttachment,
        EncryptedAssetsAttachmentError,
        EncryptedAssetsIssuerKey,
    };

    /// The plaintext holds the serial number, script root and storage commitment, followed by the
    /// assets in note order, and decodes back to the same plaintext.
    #[test]
    fn plaintext_elements_follow_the_attachment_layout() -> anyhow::Result<()> {
        let serial_num = Word::from([1, 2, 3, 4u32]);
        let script_root = Word::from([5, 6, 7, 8u32]);
        let storage_commitment = Word::from([9, 10, 11, 12u32]);
        let assets =
            NoteAssets::new(vec![FungibleAsset::mock(10), NonFungibleAsset::mock(&[1, 2, 3])])?;
        let plaintext = EncryptedAssetsAttachment::new(
            serial_num,
            NoteScriptRoot::from_raw(script_root),
            storage_commitment,
            assets.clone(),
        );

        let elements = plaintext.to_elements();
        assert_eq!(elements.len(), 12 + 8 * assets.num_assets());
        assert_eq!(elements[..4], *serial_num.as_elements());
        assert_eq!(elements[4..8], *script_root.as_elements());
        assert_eq!(elements[8..12], *storage_commitment.as_elements());
        assert_eq!(elements[12..], assets.to_elements());

        assert_eq!(EncryptedAssetsAttachment::try_from_elements(&elements)?, plaintext);

        Ok(())
    }

    /// A plaintext that is shorter than the header or ends within an asset does not decode.
    #[rstest::rstest]
    #[case::empty(0)]
    #[case::partial_header(11)]
    #[case::partial_asset(16)]
    #[case::unaligned(13)]
    fn plaintext_of_invalid_length_does_not_decode(#[case] num_elements: usize) {
        let elements = vec![Felt::ZERO; num_elements];

        assert_matches!(
            EncryptedAssetsAttachment::try_from_elements(&elements),
            Err(EncryptedAssetsAttachmentError::InvalidPlaintextLength(len)) if len == num_elements
        );
    }

    /// A plaintext with more assets than a note can hold does not decode.
    #[test]
    fn plaintext_with_too_many_assets_does_not_decode() {
        let num_assets = NoteAssets::MAX_NUM_ASSETS + 1;
        let elements: Vec<Felt> = [Word::empty(); 3]
            .into_iter()
            .flatten()
            .chain((0..num_assets).flat_map(|i| NonFungibleAsset::mock(&[i as u8]).as_elements()))
            .collect();

        assert_matches!(
            EncryptedAssetsAttachment::try_from_elements(&elements),
            Err(EncryptedAssetsAttachmentError::InvalidAssets(NoteError::TooManyAssets(n)))
                if n == num_assets
        );
    }

    /// An attachment of another scheme, or one whose content is not an envelope, does not decrypt.
    #[test]
    fn decrypt_rejects_other_scheme_and_malformed_envelope() -> anyhow::Result<()> {
        let secret_key = SecretKey::from_bytes(&[1; 40])?;

        let other_scheme = NoteAttachment::with_word(NoteAttachmentScheme::new(64)?, Word::empty());
        assert_matches!(
            EncryptedAssetsAttachment::decrypt(&other_scheme, &secret_key),
            Err(EncryptedAssetsAttachmentError::AttachmentSchemeMismatch(scheme))
                if scheme == other_scheme.attachment_scheme()
        );

        let malformed =
            NoteAttachment::with_word(EncryptedAssetsAttachment::ATTACHMENT_SCHEME, Word::empty());
        assert_matches!(
            EncryptedAssetsAttachment::decrypt(&malformed, &secret_key),
            Err(EncryptedAssetsAttachmentError::InvalidEnvelope(_))
        );

        Ok(())
    }

    /// The issuer key slot maps index 0 to the public key commitment and indices 1 and 2 to the
    /// five public key elements.
    #[test]
    fn issuer_key_storage_slot_holds_commitment_and_public_key() -> anyhow::Result<()> {
        let public_key = SecretKey::from_bytes(&[1; 40])?.public_key();
        let [e0, e1, e2, e3, e4] = public_key.to_elements();

        let slot = EncryptedAssetsIssuerKey::new(public_key).into_storage_slot();

        assert_eq!(slot.name(), EncryptedAssetsIssuerKey::slot_name());
        let StorageSlotContent::Map(map) = slot.content() else {
            anyhow::bail!("issuer key slot should be a map slot");
        };
        assert_eq!(map.num_entries(), 3);
        assert_eq!(map.get(&StorageMapKey::from_index(0)), public_key.to_commitment());
        assert_eq!(map.get(&StorageMapKey::from_index(1)), Word::new([e0, e1, e2, e3]));
        assert_eq!(
            map.get(&StorageMapKey::from_index(2)),
            Word::new([e4, Felt::ZERO, Felt::ZERO, Felt::ZERO])
        );

        Ok(())
    }
}
