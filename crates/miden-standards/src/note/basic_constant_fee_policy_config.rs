use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
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
use miden_protocol::{Felt, Word};

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the BASIC_CONSTANT_FEE_POLICY_CONFIG note script procedure in the standards library.
const BASIC_CONSTANT_FEE_POLICY_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::basic_constant_fee_policy_config::main";

// Initialize the BASIC_CONSTANT_FEE_POLICY_CONFIG note script only once.
static BASIC_CONSTANT_FEE_POLICY_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(BASIC_CONSTANT_FEE_POLICY_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains BASIC_CONSTANT_FEE_POLICY_CONFIG note script procedure")
});

// BASIC CONSTANT FEE POLICY CONFIG NOTE
// ================================================================================================

/// A BasicConstantFeePolicyConfig note: schedules a fee for a note script root in a
/// [`BasicConstantFeePolicy`](crate::account::fees::BasicConstantFeePolicy)'s fee schedule by
/// calling the [`BasicConstantFeeManager`](crate::account::fees::BasicConstantFeeManager)'s
/// `set_note_fee` procedure on the account that consumes it.
///
/// The note script root and fee asset are carried in the note's storage (see [`NoteStorage`]
/// conversion below). Because the storage is fixed at note creation and bound into the note
/// commitment, the authorized party is the note sender: the consuming account's `set_note_fee`
/// procedure authorizes the sender through the account-wide `Authority` component. The fee asset's
/// ID must match the account's configured fee asset ID.
///
/// The fee schedule and the fee asset ID live on an
/// [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount), so this note is consumed by a
/// network account, whose note-script allowlist must include this note's own script root.
///
/// Construct one with the [builder](BasicConstantFeePolicyConfigNote::builder); convert it into a
/// protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct BasicConstantFeePolicyConfigNote {
    sender: AccountId,
    account: AccountId,
    note_script_root: NoteScriptRoot,
    fee_asset: FungibleAsset,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl BasicConstantFeePolicyConfigNote {
    /// Builds a new [`BasicConstantFeePolicyConfigNote`] scheduling `fee_asset` for
    /// `note_script_root` on `account`.
    ///
    /// # Errors
    ///
    /// Returns an error if the attachments exceed their protocol limit (see
    /// [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        account: AccountId,
        note_script_root: NoteScriptRoot,
        fee_asset: FungibleAsset,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            account,
            note_script_root,
            fee_asset,
            serial_number,
            attachments,
        })
    }
}

impl BasicConstantFeePolicyConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a BasicConstantFeePolicyConfig note: the note script root word
    /// plus the fee asset (its ID and value words).
    pub const NUM_STORAGE_ITEMS: usize = 12;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the BasicConstantFeePolicyConfig note.
    pub fn script() -> NoteScript {
        BASIC_CONSTANT_FEE_POLICY_CONFIG_SCRIPT.clone()
    }

    /// Returns the BasicConstantFeePolicyConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        BASIC_CONSTANT_FEE_POLICY_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the note script root the fee is scheduled for.
    pub fn note_script_root(&self) -> NoteScriptRoot {
        self.note_script_root
    }

    /// Returns the fee asset scheduled for the note script root.
    pub fn fee_asset(&self) -> FungibleAsset {
        self.fee_asset
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the note storage values encoding the action, laid out as
    /// `[NOTE_SCRIPT_ROOT, FEE_ASSET_ID, FEE_ASSET_VALUE]`.
    fn to_storage_values(&self) -> Vec<Felt> {
        let mut values = Vec::with_capacity(Self::NUM_STORAGE_ITEMS);
        values.extend_from_slice(self.note_script_root.as_word().as_elements());
        values.extend_from_slice(self.fee_asset.to_id_word().as_elements());
        values.extend_from_slice(self.fee_asset.to_value_word().as_elements());
        values
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: basic_constant_fee_policy_config_note_builder::State>
    BasicConstantFeePolicyConfigNoteBuilder<S>
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

impl<S: basic_constant_fee_policy_config_note_builder::State>
    BasicConstantFeePolicyConfigNoteBuilder<S>
where
    S::SerialNumber: basic_constant_fee_policy_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> BasicConstantFeePolicyConfigNoteBuilder<
        basic_constant_fee_policy_config_note_builder::SetSerialNumber<S>,
    > {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<BasicConstantFeePolicyConfigNote> for Note {
    fn from(note: BasicConstantFeePolicyConfigNote) -> Self {
        // BasicConstantFeePolicyConfig notes carry no assets and are always public for network
        // execution; the note script root and fee asset live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.account));
        let storage = NoteStorage::new(note.to_storage_values())
            .expect("number of storage items should not exceed max storage items");
        let recipient = NoteRecipient::new(
            note.serial_number,
            BasicConstantFeePolicyConfigNote::script(),
            storage,
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    use super::*;

    fn account_id(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([seed; 32])
    }

    fn note_root(seed: u32) -> NoteScriptRoot {
        NoteScriptRoot::from_array([seed, seed + 1, seed + 2, seed + 3])
    }

    fn fee_asset(amount: u64) -> FungibleAsset {
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), amount).unwrap()
    }

    /// The builder produces a public, asset-less note tagged for the managed account.
    #[test]
    fn builder_builds_basic_constant_fee_policy_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let account = account_id(1);
        let sender = account_id(2);

        let note = BasicConstantFeePolicyConfigNote::builder()
            .sender(sender)
            .account(account)
            .note_script_root(note_root(10))
            .fee_asset(fee_asset(500))
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender);
        assert_eq!(note.account(), account);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(account));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// Storage is `[NOTE_SCRIPT_ROOT, FEE_ASSET_ID, FEE_ASSET_VALUE]`.
    #[test]
    fn storage_layout() {
        let root = note_root(10);
        let asset = fee_asset(777);

        let note = BasicConstantFeePolicyConfigNote::builder()
            .sender(account_id(2))
            .account(account_id(1))
            .note_script_root(root)
            .fee_asset(asset)
            .serial_number(Word::empty())
            .build()
            .unwrap();

        let built = Note::from(note);
        let mut expected = Vec::from(root.as_word().as_elements());
        expected.extend_from_slice(asset.to_id_word().as_elements());
        expected.extend_from_slice(asset.to_value_word().as_elements());
        assert_eq!(built.storage().items(), expected.as_slice());
        assert_eq!(
            built.storage().items().len(),
            BasicConstantFeePolicyConfigNote::NUM_STORAGE_ITEMS
        );
    }

    /// The config-note script root is registered in the [`StandardNote`](crate::note::StandardNote)
    /// reverse lookup.
    #[test]
    fn script_root_is_registered_standard_note() {
        use crate::note::StandardNote;

        let standard =
            StandardNote::from_script_root(BasicConstantFeePolicyConfigNote::script_root())
                .expect("config note script root should be a registered standard note");
        assert_eq!(standard.name(), "BASIC_CONSTANT_FEE_POLICY_CONFIG");
    }
}
