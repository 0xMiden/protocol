use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachments,
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::sync::LazyLock;
use rand::{Rng, RngExt};

use crate::StandardsLib;
use crate::note::costs::{
    ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_CONSUMPTION_CYCLES,
    NoteConsumptionCost,
};
use crate::note::{EncryptedAssetsIssuerKey, NetworkAccountTarget};

// NOTE SCRIPT
// ================================================================================================

/// Path to the ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG note script procedure in the standards library.
const ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::encrypted_assets_issuer_key_config::main";

// Initialize the ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG note script only once.
static ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path).expect(
        "Standards library contains ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG note script procedure",
    )
});

// ENCRYPTED ASSETS ISSUER KEY CONFIG NOTE
// ================================================================================================

/// An EncryptedAssetsIssuerKeyConfig note: rotates the [`EncryptedAssetsIssuerKey`] of the faucet
/// that consumes it by calling its `set_issuer_key` procedure.
///
/// The new key is carried in the note's storage as the elements of its public key (see the
/// [`Note`] conversion below). Because the storage is fixed at note creation and bound into the
/// note commitment, the authorized party is the note sender: the consuming faucet's
/// `set_issuer_key` procedure authorizes the sender through the account-wide
/// [`Authority`](crate::account::access::Authority) component.
///
/// The note is always public (for network execution) and tagged for `target` - the faucet carrying
/// the `EncryptedAssetsIssuerKey` component whose key is being rotated. The `sender` is the account
/// authorized for the rotation per the faucet's `Authority` configuration (the owner under
/// [`OwnerControlled`](crate::account::access::Authority::OwnerControlled), or a role member under
/// [`RbacControlled`](crate::account::access::Authority::RbacControlled)).
///
/// The note is bound to the target account by a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment: the script asserts that
/// the consuming account matches that target before calling `set_issuer_key`, so the note cannot
/// be consumed by a third-party account that merely accepts its sender.
///
/// The note must be public: the script rejects a non-public note. See
/// [the module docs](crate::note::config#note-type) for the layers that enforce it.
///
/// Construct one with the [builder](EncryptedAssetsIssuerKeyConfigNote::builder); convert it into
/// a protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct EncryptedAssetsIssuerKeyConfigNote {
    sender: AccountId,
    target: AccountId,
    issuer_key: EncryptedAssetsIssuerKey,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl EncryptedAssetsIssuerKeyConfigNote {
    /// Builds a new [`EncryptedAssetsIssuerKeyConfigNote`] setting `issuer_key` on `target`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `target` is not a public account (the note is bound to it via a `NetworkAccountTarget`,
    ///   which requires a public target).
    /// - the attachments carry a `NetworkAccountTarget` for an account other than `target`.
    /// - the attachments exceed their protocol limit (see [`NoteAttachments::new`]); the target
    ///   attachment occupies one of the available slots when the caller does not supply it.
    #[builder]
    pub fn new(
        #[builder(field)] mut attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        issuer_key: EncryptedAssetsIssuerKey,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // Bind the note to `target`: the note script asserts, before calling `set_issuer_key`,
        // that the consuming account matches this `NetworkAccountTarget`.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the EncryptedAssetsIssuerKeyConfig note to its target account",
                err,
            )
        })?;

        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            target,
            issuer_key,
            serial_number,
            attachments,
        })
    }
}

impl EncryptedAssetsIssuerKeyConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of an EncryptedAssetsIssuerKeyConfig note: the elements of the new
    /// issuer public key.
    ///
    /// Must be kept in sync with `NUM_STORAGE_ITEMS` in the note script, which asserts the count.
    pub const NUM_STORAGE_ITEMS: usize = 5;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the EncryptedAssetsIssuerKeyConfig note.
    pub fn script() -> NoteScript {
        ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_SCRIPT.clone()
    }

    /// Returns the EncryptedAssetsIssuerKeyConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the rotation).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed faucet: the account the note is tagged for and bound
    /// to via its `NetworkAccountTarget` attachment (only this account can consume the note).
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the issuer key the note sets on the faucet.
    pub fn issuer_key(&self) -> EncryptedAssetsIssuerKey {
        self.issuer_key
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: encrypted_assets_issuer_key_config_note_builder::State>
    EncryptedAssetsIssuerKeyConfigNoteBuilder<S>
{
    /// Adds a single attachment to the note.
    pub fn attachment(mut self, attachment: impl Into<NoteAttachment>) -> Self {
        self.attachments.push(attachment.into());
        self
    }

    /// Adds multiple attachments to the note.
    pub fn attachments(
        mut self,
        attachments: impl IntoIterator<Item = impl Into<NoteAttachment>>,
    ) -> Self {
        self.attachments.extend(attachments.into_iter().map(Into::into));
        self
    }
}

impl<S: encrypted_assets_issuer_key_config_note_builder::State>
    EncryptedAssetsIssuerKeyConfigNoteBuilder<S>
where
    S::SerialNumber: encrypted_assets_issuer_key_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl Rng,
    ) -> EncryptedAssetsIssuerKeyConfigNoteBuilder<
        encrypted_assets_issuer_key_config_note_builder::SetSerialNumber<S>,
    > {
        self.serial_number(rng.random())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<EncryptedAssetsIssuerKeyConfigNote> for Note {
    fn from(note: EncryptedAssetsIssuerKeyConfigNote) -> Self {
        // EncryptedAssetsIssuerKeyConfig notes carry no assets and are always public for network
        // execution; the new issuer key lives in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let storage = NoteStorage::new(note.issuer_key.public_key().to_elements().to_vec())
            .expect("number of storage items should not exceed max storage items");
        let recipient = NoteRecipient::new(
            note.serial_number,
            EncryptedAssetsIssuerKeyConfigNote::script(),
            storage,
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for EncryptedAssetsIssuerKeyConfigNote {
    fn consumption_cycles() -> u32 {
        ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::ecdh::ecgfp5::SecretKey;
    use miden_protocol::crypto::rand::EidosRandomCoin;

    use super::*;
    use crate::note::StandardNote;

    fn account_id(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([seed; 32])
    }

    fn issuer_key() -> anyhow::Result<EncryptedAssetsIssuerKey> {
        Ok(EncryptedAssetsIssuerKey::new(SecretKey::from_bytes(&[8; 40])?.public_key()))
    }

    /// The builder produces a public, asset-less note tagged for the managed faucet.
    #[test]
    fn builder_builds_encrypted_assets_issuer_key_config_note() -> anyhow::Result<()> {
        let mut rng = EidosRandomCoin::new(Word::empty());
        let faucet = account_id(1);
        let sender = account_id(2);
        let issuer_key = issuer_key()?;

        let note = EncryptedAssetsIssuerKeyConfigNote::builder()
            .sender(sender)
            .target(faucet)
            .issuer_key(issuer_key)
            .generate_serial_number(&mut rng)
            .build()?;

        assert_eq!(note.sender(), sender);
        assert_eq!(note.target(), faucet);
        assert_eq!(note.issuer_key(), issuer_key);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(faucet));
        assert_eq!(note.assets().num_assets(), 0);

        Ok(())
    }

    /// The built note carries a `NetworkAccountTarget` attachment bound to the faucet, so the note
    /// script can reject consumption by any other account.
    #[test]
    fn note_is_bound_to_target_account() -> anyhow::Result<()> {
        let faucet = account_id(1);
        let note = EncryptedAssetsIssuerKeyConfigNote::builder()
            .sender(account_id(2))
            .target(faucet)
            .issuer_key(issuer_key()?)
            .serial_number(Word::empty())
            .build()?;

        let built = Note::from(note);
        let target = NetworkAccountTarget::try_from(built.attachments())?;
        assert_eq!(target.target_id(), faucet);

        Ok(())
    }

    /// Storage is the elements of the issuer public key.
    #[test]
    fn storage_layout() -> anyhow::Result<()> {
        let issuer_key = issuer_key()?;

        let note = EncryptedAssetsIssuerKeyConfigNote::builder()
            .sender(account_id(2))
            .target(account_id(1))
            .issuer_key(issuer_key)
            .serial_number(Word::empty())
            .build()?;

        let built = Note::from(note);
        assert_eq!(built.storage().items(), issuer_key.public_key().to_elements());
        assert_eq!(
            built.storage().items().len(),
            EncryptedAssetsIssuerKeyConfigNote::NUM_STORAGE_ITEMS
        );

        Ok(())
    }

    /// The config-note script root is registered in the [`StandardNote`](crate::note::StandardNote)
    /// reverse lookup.
    #[test]
    fn script_root_is_registered_standard_note() -> anyhow::Result<()> {
        let standard =
            StandardNote::from_script_root(EncryptedAssetsIssuerKeyConfigNote::script_root())
                .ok_or_else(|| anyhow::anyhow!("config note script root should be registered"))?;
        assert_eq!(standard.name(), "ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG");

        Ok(())
    }
}
