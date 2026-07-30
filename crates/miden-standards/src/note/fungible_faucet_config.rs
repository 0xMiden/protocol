use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::AssetAmount;
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
use crate::note::costs::{FUNGIBLE_FAUCET_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the FUNGIBLE_FAUCET_CONFIG note script procedure in the standards library.
const FUNGIBLE_FAUCET_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::fungible_faucet_config::main";

// Initialize the FUNGIBLE_FAUCET_CONFIG note script only once.
static FUNGIBLE_FAUCET_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(FUNGIBLE_FAUCET_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains FUNGIBLE_FAUCET_CONFIG note script procedure")
});

// FUNGIBLE FAUCET CONFIG
// ================================================================================================

/// Number of felts encoding a metadata string: 7 Words. Keep in sync with
/// `fungible_faucet_config.masm`.
const STRING_NUM_ELEMENTS: usize = 28;

/// A token metadata management action of the
/// [`FungibleFaucet`](crate::account::faucets::FungibleFaucet) component that a
/// [`FungibleFaucetConfigNote`] triggers on the account that consumes it.
///
/// The action, together with its arguments, is encoded into the note's storage (see [`NoteStorage`]
/// conversion below). Because the storage is fixed at note creation and bound into the note
/// commitment, the authorized party is the note sender: the consuming account's `FungibleFaucet`
/// procedures authorize the sender through the account-wide `Authority` component.
///
/// The three string actions carry their new value as the 28 felts the faucet stores it in. The note
/// script commits to those felts and publishes them in the advice map, which is how the called
/// setter receives them — nothing outside the note has to supply advice inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FungibleFaucetConfig {
    /// Set the faucet's maximum supply. Requires the max supply to be configured as mutable, and
    /// the new cap to be at least the current token supply.
    SetMaxSupply { max_supply: AssetAmount },
    /// Set the token description. Requires the description to be configured as mutable.
    SetDescription { description: Description },
    /// Set the token logo URI. Requires the logo URI to be configured as mutable.
    SetLogoUri { logo_uri: LogoURI },
    /// Set the token external link. Requires the external link to be configured as mutable.
    SetExternalLink { external_link: ExternalLink },
}

impl FungibleFaucetConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Config note selectors stored in the first storage item. Keep in sync with
    // `fungible_faucet_config.masm`.
    const SELECTOR_SET_MAX_SUPPLY: u8 = 0;
    const SELECTOR_SET_DESCRIPTION: u8 = 1;
    const SELECTOR_SET_LOGO_URI: u8 = 2;
    const SELECTOR_SET_EXTERNAL_LINK: u8 = 3;

    /// Returns the selector encoding this action in the first storage item.
    const fn selector(&self) -> u8 {
        match self {
            FungibleFaucetConfig::SetMaxSupply { .. } => Self::SELECTOR_SET_MAX_SUPPLY,
            FungibleFaucetConfig::SetDescription { .. } => Self::SELECTOR_SET_DESCRIPTION,
            FungibleFaucetConfig::SetLogoUri { .. } => Self::SELECTOR_SET_LOGO_URI,
            FungibleFaucetConfig::SetExternalLink { .. } => Self::SELECTOR_SET_EXTERNAL_LINK,
        }
    }

    /// Returns the note storage values encoding this action.
    ///
    /// `SetMaxSupply` lays out as `[selector, new_max_supply]`. The string actions lay out as
    /// `[selector, 0, 0, 0, value(28)]`: the selector occupies the whole first storage word so that
    /// the payload starts word-aligned, which the note script's `poseidon2::hash_elements` call
    /// requires.
    fn to_storage_values(&self) -> Vec<Felt> {
        let selector = Felt::from(self.selector());

        match self {
            FungibleFaucetConfig::SetMaxSupply { max_supply } => {
                vec![selector, Felt::from(*max_supply)]
            },
            FungibleFaucetConfig::SetDescription { description } => {
                string_storage_values(selector, &description.to_words())
            },
            FungibleFaucetConfig::SetLogoUri { logo_uri } => {
                string_storage_values(selector, &logo_uri.to_words())
            },
            FungibleFaucetConfig::SetExternalLink { external_link } => {
                string_storage_values(selector, &external_link.to_words())
            },
        }
    }
}

/// Lays out a string action as `[selector, 0, 0, 0, value(28)]`.
fn string_storage_values(selector: Felt, value: &[Word]) -> Vec<Felt> {
    let mut items = Vec::with_capacity(FungibleFaucetConfigNote::MAX_NUM_STORAGE_ITEMS);
    items.push(selector);
    items.extend([Felt::ZERO; 3]);
    items.extend(value.iter().flat_map(Word::as_elements).copied());

    debug_assert_eq!(items.len(), 4 + STRING_NUM_ELEMENTS);

    items
}

impl From<FungibleFaucetConfig> for NoteStorage {
    fn from(config: FungibleFaucetConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// FUNGIBLE FAUCET CONFIG NOTE
// ================================================================================================

/// A FungibleFaucetConfig note: triggers a
/// [`FungibleFaucet`](crate::account::faucets::FungibleFaucet) token metadata admin action on the
/// account that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// metadata setters (`set_max_supply`, `set_description`, `set_logo_uri`, `set_external_link`).
/// Authorization is enforced by those procedures through the account-wide `Authority` component
/// against the note sender, so the note carries no assets and its authorization is bound to
/// `sender` at creation time.
///
/// The note is always public and tagged for `target` — the faucet carrying the `FungibleFaucet`
/// component whose metadata is being managed. The `sender` is the account authorized for the action
/// per the target's `Authority` configuration (the owner under `Authority::OwnerControlled`, or a
/// role member under `Authority::RbacControlled`).
///
/// Construct one with the [builder](FungibleFaucetConfigNote::builder); convert it into a protocol
/// [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct FungibleFaucetConfigNote {
    sender: AccountId,
    target: AccountId,
    config: FungibleFaucetConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl FungibleFaucetConfigNote {
    /// Builds a new [`FungibleFaucetConfigNote`] that applies `config` to `target`.
    ///
    /// # Errors
    ///
    /// Returns an error if the attachments exceed their protocol limit (see
    /// [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        config: FungibleFaucetConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
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

impl FungibleFaucetConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Upper bound on the number of storage items of a FungibleFaucetConfig note.
    ///
    /// The layout is variable: `SetMaxSupply` uses 2 items (`[selector, new_max_supply]`), while
    /// the three string actions use 32 (`[selector, 0, 0, 0, value(28)]`).
    pub const MAX_NUM_STORAGE_ITEMS: usize = 4 + STRING_NUM_ELEMENTS;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the FungibleFaucetConfig note.
    pub fn script() -> NoteScript {
        FUNGIBLE_FAUCET_CONFIG_SCRIPT.clone()
    }

    /// Returns the FungibleFaucetConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        FUNGIBLE_FAUCET_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed faucet (the account the note is tagged for).
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the metadata action carried by the note.
    pub fn config(&self) -> &FungibleFaucetConfig {
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

impl<S: fungible_faucet_config_note_builder::State> FungibleFaucetConfigNoteBuilder<S> {
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

impl<S: fungible_faucet_config_note_builder::State> FungibleFaucetConfigNoteBuilder<S>
where
    S::SerialNumber: fungible_faucet_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> FungibleFaucetConfigNoteBuilder<fungible_faucet_config_note_builder::SetSerialNumber<S>>
    {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FungibleFaucetConfigNote> for Note {
    fn from(note: FungibleFaucetConfigNote) -> Self {
        // FungibleFaucetConfig notes carry no assets and are always public; the action and its
        // arguments live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            FungibleFaucetConfigNote::script(),
            NoteStorage::from(note.config),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

impl NoteConsumptionCost for FungibleFaucetConfigNote {
    fn consumption_cycles() -> u32 {
        FUNGIBLE_FAUCET_CONFIG_CONSUMPTION_CYCLES
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
    fn builder_builds_fungible_faucet_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let faucet = account_id(1);
        let owner = account_id(2);

        let note = FungibleFaucetConfigNote::builder()
            .sender(owner)
            .target(faucet)
            .config(FungibleFaucetConfig::SetDescription { description: description() })
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
        let storage = NoteStorage::from(FungibleFaucetConfig::SetMaxSupply { max_supply });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(FungibleFaucetConfig::SELECTOR_SET_MAX_SUPPLY),
                Felt::from(max_supply),
            ]
        );
    }

    /// A string action reserves the first storage word for the selector so the 7-Word payload that
    /// follows starts word-aligned.
    #[test]
    fn set_description_storage_layout() {
        let description = description();
        let storage = NoteStorage::from(FungibleFaucetConfig::SetDescription {
            description: description.clone(),
        });

        let items = storage.items();
        assert_eq!(items.len(), FungibleFaucetConfigNote::MAX_NUM_STORAGE_ITEMS);
        assert_eq!(items[0], Felt::from(FungibleFaucetConfig::SELECTOR_SET_DESCRIPTION));
        assert_eq!(&items[1..4], &[Felt::ZERO; 3]);

        let payload: Vec<Felt> =
            description.to_words().iter().flat_map(Word::as_elements).copied().collect();
        assert_eq!(&items[4..], payload.as_slice());
    }

    /// Every string action carries the same layout, differing only in the selector.
    #[test]
    fn string_action_selectors() {
        let logo_uri = LogoURI::new("https://example.com/logo.png").unwrap();
        let storage = NoteStorage::from(FungibleFaucetConfig::SetLogoUri { logo_uri });
        assert_eq!(storage.items()[0], Felt::from(FungibleFaucetConfig::SELECTOR_SET_LOGO_URI));

        let external_link = ExternalLink::new("https://example.com").unwrap();
        let storage = NoteStorage::from(FungibleFaucetConfig::SetExternalLink { external_link });
        assert_eq!(
            storage.items()[0],
            Felt::from(FungibleFaucetConfig::SELECTOR_SET_EXTERNAL_LINK)
        );
    }
}
