use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::BlockNumber;
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
use crate::account::faucets::{Description, ExternalLink, LogoURI};
use crate::note::NetworkAccountTarget;
use crate::note::costs::{FAUCET_METADATA_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the FAUCET_METADATA_CONFIG note script procedure in the standards library.
const FAUCET_METADATA_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::faucet_metadata_config::main";

// Initialize the FAUCET_METADATA_CONFIG note script only once.
static FAUCET_METADATA_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(FAUCET_METADATA_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains FAUCET_METADATA_CONFIG note script procedure")
});

// FUNGIBLE FAUCET CONFIG
// ================================================================================================

/// Number of felts encoding a metadata string: 7 Words. Keep in sync with
/// `faucet_metadata_config.masm`.
const STRING_NUM_ELEMENTS: usize = 28;

/// A token metadata management action that a [`FaucetMetadataConfigNote`] triggers on the faucet
/// that consumes it.
///
/// The action, together with its arguments, is encoded into the note's storage (see [`NoteStorage`]
/// conversion below) and is fixed at note creation, bound into the note commitment. The consuming
/// faucet's metadata setters authorize the action through the account-wide
/// [`Authority`](crate::account::access::Authority) component.
///
/// The three string actions apply to both faucet kinds, since
/// [`FungibleFaucet`](crate::account::faucets::FungibleFaucet) and
/// [`NonFungibleFaucet`](crate::account::faucets::NonFungibleFaucet) re-export the same setters
/// from the shared `miden::standards::faucets` module. [`Self::SetMaxSupply`] is fungible-only, and
/// aborts on a non-fungible faucet, which does not expose `set_max_supply`.
///
/// The three string actions carry their new value as the 28 felts the faucet stores it in. The note
/// script commits to those felts and publishes them in the advice map, which is how the called
/// setter receives them — nothing outside the note has to supply advice inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaucetMetadataConfig {
    /// Set the faucet's maximum supply. Fungible faucets only. Requires the max supply to be
    /// configured as mutable, and the new cap to be at least the current token supply.
    SetMaxSupply { max_supply: AssetAmount },
    /// Set the token description. Requires the description to be configured as mutable.
    SetDescription { description: Description },
    /// Set the token logo URI. Requires the logo URI to be configured as mutable.
    SetLogoUri { logo_uri: LogoURI },
    /// Set the token external link. Requires the external link to be configured as mutable.
    SetExternalLink { external_link: ExternalLink },
}

impl FaucetMetadataConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Config note selectors stored in the first storage item. Keep in sync with
    // `faucet_metadata_config.masm`.
    const SELECTOR_SET_MAX_SUPPLY: u8 = 0;
    const SELECTOR_SET_DESCRIPTION: u8 = 1;
    const SELECTOR_SET_LOGO_URI: u8 = 2;
    const SELECTOR_SET_EXTERNAL_LINK: u8 = 3;

    /// Returns the selector encoding this action in the first storage item.
    const fn selector(&self) -> u8 {
        match self {
            FaucetMetadataConfig::SetMaxSupply { .. } => Self::SELECTOR_SET_MAX_SUPPLY,
            FaucetMetadataConfig::SetDescription { .. } => Self::SELECTOR_SET_DESCRIPTION,
            FaucetMetadataConfig::SetLogoUri { .. } => Self::SELECTOR_SET_LOGO_URI,
            FaucetMetadataConfig::SetExternalLink { .. } => Self::SELECTOR_SET_EXTERNAL_LINK,
        }
    }

    /// Returns the note storage values encoding this action.
    ///
    /// `SetMaxSupply` lays out as `[selector, new_max_supply]`. The string actions lay out as
    /// `[selector, 0, 0, 0, value(28)]`: the selector is padded out to a full word with three
    /// zeros, so the payload starts word-aligned, as the note script's `poseidon2::hash_elements`
    /// call requires.
    fn to_storage_values(&self) -> Vec<Felt> {
        let selector = Felt::from(self.selector());

        match self {
            FaucetMetadataConfig::SetMaxSupply { max_supply } => {
                vec![selector, Felt::from(*max_supply)]
            },
            FaucetMetadataConfig::SetDescription { description } => {
                string_storage_values(selector, &description.to_words())
            },
            FaucetMetadataConfig::SetLogoUri { logo_uri } => {
                string_storage_values(selector, &logo_uri.to_words())
            },
            FaucetMetadataConfig::SetExternalLink { external_link } => {
                string_storage_values(selector, &external_link.to_words())
            },
        }
    }
}

/// Lays out a string action as `[selector, 0, 0, 0, value(28)]`.
fn string_storage_values(selector: Felt, value: &[Word]) -> Vec<Felt> {
    let mut items = Vec::with_capacity(FaucetMetadataConfigNote::MAX_NUM_STORAGE_ITEMS);
    items.push(selector);
    items.extend([Felt::ZERO; 3]);
    items.extend(value.iter().flat_map(Word::as_elements).copied());

    debug_assert_eq!(items.len(), 4 + STRING_NUM_ELEMENTS);

    items
}

impl From<FaucetMetadataConfig> for NoteStorage {
    fn from(config: FaucetMetadataConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// FUNGIBLE FAUCET CONFIG NOTE
// ================================================================================================

/// A FaucetMetadataConfig note: triggers a token metadata admin action on the faucet that consumes
/// it.
///
/// A single note script dispatches on a selector in the note's storage to one of the faucet's
/// metadata setters (`set_max_supply`, `set_description`, `set_logo_uri`, `set_external_link`).
/// Authorization is enforced by those procedures through the account-wide
/// [`Authority`](crate::account::access::Authority) component, so the note carries no assets.
///
/// See [`FaucetMetadataConfig`] for which actions apply to which faucet kind.
///
/// The note is always public and tagged for `target` — the faucet whose metadata is being managed.
///
/// The note is bound to `target` by a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment: the script asserts
/// that the consuming account matches that target before dispatching, so the note cannot be
/// consumed by a third-party account that merely accepts its sender.
///
/// Construct one with the [builder](FaucetMetadataConfigNote::builder); convert it into a protocol
/// [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct FaucetMetadataConfigNote {
    sender: AccountId,
    target: AccountId,
    config: FaucetMetadataConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl FaucetMetadataConfigNote {
    /// Builds a new [`FaucetMetadataConfigNote`] that applies `config` to `target`.
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
        expiration_block_num: Option<BlockNumber>,
        config: FaucetMetadataConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The note script asserts that the consuming account matches this target before
        // dispatching.
        NetworkAccountTarget::ensure_presence(&mut attachments, target, expiration_block_num)
            .map_err(|err| {
                NoteError::other_with_source(
                    "failed to bind the FaucetMetadataConfig note to its target account",
                    err,
                )
            })?;

        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            target,
            config,
            serial_number,
            attachments,
        })
    }
}

impl FaucetMetadataConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Upper bound on the number of storage items of a FaucetMetadataConfig note.
    ///
    /// The layout is variable: `SetMaxSupply` uses 2 items (`[selector, new_max_supply]`), while
    /// the three string actions use 32 (`[selector, 0, 0, 0, value(28)]`).
    pub const MAX_NUM_STORAGE_ITEMS: usize = 4 + STRING_NUM_ELEMENTS;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the FaucetMetadataConfig note.
    pub fn script() -> NoteScript {
        FAUCET_METADATA_CONFIG_SCRIPT.clone()
    }

    /// Returns the FaucetMetadataConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        FAUCET_METADATA_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the authorizing party under an owner- or
    /// role-controlled `Authority`).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed faucet (the account the note is tagged for).
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the metadata action carried by the note.
    pub fn config(&self) -> &FaucetMetadataConfig {
        &self.config
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

impl<S: faucet_metadata_config_note_builder::State> FaucetMetadataConfigNoteBuilder<S> {
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

impl<S: faucet_metadata_config_note_builder::State> FaucetMetadataConfigNoteBuilder<S>
where
    S::SerialNumber: faucet_metadata_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> FaucetMetadataConfigNoteBuilder<faucet_metadata_config_note_builder::SetSerialNumber<S>>
    {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FaucetMetadataConfigNote> for Note {
    fn from(note: FaucetMetadataConfigNote) -> Self {
        // FaucetMetadataConfig notes carry no assets and are always public; the action and its
        // arguments live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            FaucetMetadataConfigNote::script(),
            NoteStorage::from(note.config),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

impl NoteConsumptionCost for FaucetMetadataConfigNote {
    fn consumption_cycles() -> u32 {
        FAUCET_METADATA_CONFIG_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::RandomCoin;

    use super::*;

    fn account_id(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([seed; 32])
    }

    fn description() -> Description {
        Description::new("A described token").expect("description should be valid")
    }

    /// The builder produces a public, asset-less note tagged for the managed faucet.
    #[test]
    fn builder_builds_faucet_metadata_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let faucet = account_id(1);
        let owner = account_id(2);

        let note = FaucetMetadataConfigNote::builder()
            .sender(owner)
            .target(faucet)
            .config(FaucetMetadataConfig::SetDescription { description: description() })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), owner);
        assert_eq!(note.target(), faucet);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(faucet));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// `SetMaxSupply` storage is `[selector, new_max_supply]`.
    #[test]
    fn set_max_supply_storage_layout() {
        let max_supply = AssetAmount::new(1_000).unwrap();
        let storage = NoteStorage::from(FaucetMetadataConfig::SetMaxSupply { max_supply });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(FaucetMetadataConfig::SELECTOR_SET_MAX_SUPPLY),
                Felt::from(max_supply),
            ]
        );
    }

    /// A string action reserves the first storage word for the selector so the 7-Word payload that
    /// follows starts word-aligned.
    #[test]
    fn set_description_storage_layout() {
        let description = description();
        let storage = NoteStorage::from(FaucetMetadataConfig::SetDescription {
            description: description.clone(),
        });

        let items = storage.items();
        assert_eq!(items.len(), FaucetMetadataConfigNote::MAX_NUM_STORAGE_ITEMS);
        assert_eq!(items[0], Felt::from(FaucetMetadataConfig::SELECTOR_SET_DESCRIPTION));
        assert_eq!(&items[1..4], &[Felt::ZERO; 3]);

        let payload: Vec<Felt> =
            description.to_words().iter().flat_map(Word::as_elements).copied().collect();
        assert_eq!(&items[4..], payload.as_slice());
    }

    /// Every string action carries the same layout, differing only in the selector.
    #[test]
    fn string_action_selectors() {
        let logo_uri = LogoURI::new("https://example.com/logo.png").unwrap();
        let storage = NoteStorage::from(FaucetMetadataConfig::SetLogoUri { logo_uri });
        assert_eq!(storage.items()[0], Felt::from(FaucetMetadataConfig::SELECTOR_SET_LOGO_URI));

        let external_link = ExternalLink::new("https://example.com").unwrap();
        let storage = NoteStorage::from(FaucetMetadataConfig::SetExternalLink { external_link });
        assert_eq!(
            storage.items()[0],
            Felt::from(FaucetMetadataConfig::SELECTOR_SET_EXTERNAL_LINK)
        );
    }
}
