use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::AssetAmount;
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
use rand::{Rng, RngExt};

use crate::StandardsLib;
use crate::note::NetworkAccountTarget;
use crate::note::costs::{NoteConsumptionCost, SUPPLY_RESTRICTION_CONFIG_CONSUMPTION_CYCLES};

// NOTE SCRIPT
// ================================================================================================

/// Path to the SUPPLY_RESTRICTION_CONFIG note script procedure in the standards library.
const SUPPLY_RESTRICTION_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::supply_restriction_config::main";

// Initialize the SUPPLY_RESTRICTION_CONFIG note script only once.
static SUPPLY_RESTRICTION_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(SUPPLY_RESTRICTION_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains SUPPLY_RESTRICTION_CONFIG note script procedure")
});

// SUPPLY RESTRICTION CONFIG
// ================================================================================================

/// A management action of the
/// [`SupplyRestrictionManager`](crate::account::policies::SupplyRestrictionManager) component.
///
/// The action, together with its arguments, is encoded into the note's storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyRestrictionConfig {
    /// Freeze `amount` of the balance of `account`. The token supply does not change.
    Freeze { account: AccountId, amount: AssetAmount },
    /// Unfreeze `amount` of the frozen balance of `account`.
    Unfreeze { account: AccountId, amount: AssetAmount },
    /// Confiscate `amount` of the balance of `account` for good and remove it from the token
    /// supply.
    Confiscate { account: AccountId, amount: AssetAmount },
}

impl SupplyRestrictionConfig {
    // VARIANTS
    // --------------------------------------------------------------------------------------------

    // Config note variants stored in the first storage item.
    const VARIANT_FREEZE: u8 = 0;
    const VARIANT_UNFREEZE: u8 = 1;
    const VARIANT_CONFISCATE: u8 = 2;

    /// Returns the variant encoding this action.
    const fn variant(self) -> u8 {
        match self {
            SupplyRestrictionConfig::Freeze { .. } => Self::VARIANT_FREEZE,
            SupplyRestrictionConfig::Unfreeze { .. } => Self::VARIANT_UNFREEZE,
            SupplyRestrictionConfig::Confiscate { .. } => Self::VARIANT_CONFISCATE,
        }
    }

    /// Returns the account and amount the action operates on.
    const fn arguments(self) -> (AccountId, AssetAmount) {
        match self {
            SupplyRestrictionConfig::Freeze { account, amount }
            | SupplyRestrictionConfig::Unfreeze { account, amount }
            | SupplyRestrictionConfig::Confiscate { account, amount } => (account, amount),
        }
    }

    /// Returns the note storage values encoding this action, laid out as `[variant,
    /// account_suffix, account_prefix, amount]`.
    fn to_storage_values(self) -> Vec<Felt> {
        let (account, amount) = self.arguments();
        vec![
            Felt::from(self.variant()),
            account.suffix(),
            account.prefix().as_felt(),
            Felt::from(amount),
        ]
    }
}

impl From<SupplyRestrictionConfig> for NoteStorage {
    fn from(config: SupplyRestrictionConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// SUPPLY RESTRICTION CONFIG NOTE
// ================================================================================================

/// A SupplyRestrictionConfig note: triggers a
/// [`SupplyRestrictionManager`](crate::account::policies::SupplyRestrictionManager) admin action on
/// the account that consumes it.
///
/// The note is always public and tagged for `target` — the faucet carrying the
/// [`SupplyRestrictionManager`](crate::account::policies::SupplyRestrictionManager) component.
///
/// The note is bound to `target` by a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment: the script asserts
/// that the consuming account matches that target before dispatching.
#[derive(Debug, Clone)]
pub struct SupplyRestrictionConfigNote {
    sender: AccountId,
    target: AccountId,
    config: SupplyRestrictionConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl SupplyRestrictionConfigNote {
    /// Builds a new [`SupplyRestrictionConfigNote`] that applies `config` to `target`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `target` is not a public account.
    /// - the attachments carry a `NetworkAccountTarget` for an account other than `target`.
    /// - the attachments exceed their protocol limit (see [`NoteAttachments::new`]); the target
    ///   attachment occupies one of the available slots when the caller does not supply it.
    #[builder]
    pub fn new(
        #[builder(field)] mut attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        config: SupplyRestrictionConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The note script asserts that the consuming account matches this target before
        // dispatching.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the SupplyRestrictionConfig note to its target account",
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

impl SupplyRestrictionConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a SupplyRestrictionConfig note: a variant followed by the account
    /// ID and the amount the action operates on.
    pub const NUM_STORAGE_ITEMS: usize = 4;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the SupplyRestrictionConfig note.
    pub fn script() -> NoteScript {
        SUPPLY_RESTRICTION_CONFIG_SCRIPT.clone()
    }

    /// Returns the SupplyRestrictionConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        SUPPLY_RESTRICTION_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the authorizing party under an owner- or
    /// role-controlled `Authority`).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the admin action carried by the note.
    pub fn config(&self) -> SupplyRestrictionConfig {
        self.config
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

impl<S: supply_restriction_config_note_builder::State> SupplyRestrictionConfigNoteBuilder<S> {
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

impl<S: supply_restriction_config_note_builder::State> SupplyRestrictionConfigNoteBuilder<S>
where
    S::SerialNumber: supply_restriction_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl Rng,
    ) -> SupplyRestrictionConfigNoteBuilder<
        supply_restriction_config_note_builder::SetSerialNumber<S>,
    > {
        self.serial_number(rng.random())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<SupplyRestrictionConfigNote> for Note {
    fn from(note: SupplyRestrictionConfigNote) -> Self {
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            SupplyRestrictionConfigNote::script(),
            NoteStorage::from(note.config),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for SupplyRestrictionConfigNote {
    fn consumption_cycles() -> u32 {
        SUPPLY_RESTRICTION_CONFIG_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::EidosRandomCoin;

    use super::*;

    fn account_id(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([seed; 32])
    }

    /// The builder produces a public, asset-less note tagged for the faucet.
    #[test]
    fn builder_builds_supply_restriction_config_note() {
        let mut rng = EidosRandomCoin::new(Word::empty());
        let faucet = account_id(1);
        let owner = account_id(2);
        let holder = account_id(3);

        let note = SupplyRestrictionConfigNote::builder()
            .sender(owner)
            .target(faucet)
            .config(SupplyRestrictionConfig::Freeze {
                account: holder,
                amount: AssetAmount::from(100u32),
            })
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

    /// Every action's storage is `[variant, account_suffix, account_prefix, amount]`.
    #[test]
    fn storage_layout() {
        let holder = account_id(3);
        let amount = AssetAmount::from(100u32);

        for (config, variant) in [
            (
                SupplyRestrictionConfig::Freeze { account: holder, amount },
                SupplyRestrictionConfig::VARIANT_FREEZE,
            ),
            (
                SupplyRestrictionConfig::Unfreeze { account: holder, amount },
                SupplyRestrictionConfig::VARIANT_UNFREEZE,
            ),
            (
                SupplyRestrictionConfig::Confiscate { account: holder, amount },
                SupplyRestrictionConfig::VARIANT_CONFISCATE,
            ),
        ] {
            let storage = NoteStorage::from(config);

            assert_eq!(
                storage.num_items() as usize,
                SupplyRestrictionConfigNote::NUM_STORAGE_ITEMS
            );
            assert_eq!(
                storage.items(),
                &[
                    Felt::from(variant),
                    holder.suffix(),
                    holder.prefix().as_felt(),
                    Felt::from(amount),
                ]
            );
        }
    }
}
