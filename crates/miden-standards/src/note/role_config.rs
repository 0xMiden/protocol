use alloc::vec::Vec;

use miden_protocol::account::{AccountId, RoleSymbol};
use miden_protocol::assembly::Path;
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

/// Path to the ROLE_CONFIG note script procedure in the standards library.
const ROLE_CONFIG_SCRIPT_PATH: &str = "::miden::standards::notes::role_config::main";

// Initialize the ROLE_CONFIG note script only once.
static ROLE_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(ROLE_CONFIG_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains ROLE_CONFIG note script procedure")
});

// ROLE CONFIG ACTION
// ================================================================================================

/// A management action of the
/// [`RoleBasedAccessControl`](crate::account::access::RoleBasedAccessControl) component that a
/// [`RoleConfigNote`] triggers on the account that consumes it.
///
/// The action, together with its arguments, is encoded into the note's storage (see
/// [`NoteStorage`] conversion below). Because the storage is fixed at note creation and bound into
/// the note commitment, the authorized party is the note sender: the consuming account's `rbac`
/// procedures authorize against `active_note::get_sender`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleConfigAction {
    /// Grant `role` to `account`. Only a member of the role's effective admin role is authorized.
    GrantRole { role: RoleSymbol, account: AccountId },
    /// Revoke `role` from `account`. Only a member of the role's effective admin role is
    /// authorized.
    RevokeRole { role: RoleSymbol, account: AccountId },
    /// Set the admin role of `role` to `admin_role`. A value of `None` reverts `role` to
    /// management by the default `ADMIN` role. Only a member of the role's current effective admin
    /// role is authorized.
    SetRoleAdmin {
        role: RoleSymbol,
        admin_role: Option<RoleSymbol>,
    },
    /// Renounce `role` held by the note sender.
    RenounceRole { role: RoleSymbol },
}

impl RoleConfigAction {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Action selectors stored in the first storage item. Keep in sync with `role_config.masm`.
    const SELECTOR_GRANT_ROLE: u8 = 0;
    const SELECTOR_REVOKE_ROLE: u8 = 1;
    const SELECTOR_SET_ROLE_ADMIN: u8 = 2;
    const SELECTOR_RENOUNCE_ROLE: u8 = 3;

    /// Returns the note storage values encoding this action, laid out as `[selector, ..args]`.
    fn to_storage_values(&self) -> Vec<Felt> {
        match self {
            RoleConfigAction::GrantRole { role, account } => {
                vec![
                    Felt::from(Self::SELECTOR_GRANT_ROLE),
                    role.as_element(),
                    account.suffix(),
                    account.prefix().as_felt(),
                ]
            },
            RoleConfigAction::RevokeRole { role, account } => {
                vec![
                    Felt::from(Self::SELECTOR_REVOKE_ROLE),
                    role.as_element(),
                    account.suffix(),
                    account.prefix().as_felt(),
                ]
            },
            RoleConfigAction::SetRoleAdmin { role, admin_role } => {
                // A missing admin role is encoded as 0, the value `rbac::set_role_admin` treats as
                // "revert to the default ADMIN role".
                let admin_role = admin_role.as_ref().map_or(Felt::ZERO, RoleSymbol::as_element);
                vec![Felt::from(Self::SELECTOR_SET_ROLE_ADMIN), role.as_element(), admin_role]
            },
            RoleConfigAction::RenounceRole { role } => {
                vec![Felt::from(Self::SELECTOR_RENOUNCE_ROLE), role.as_element()]
            },
        }
    }
}

impl From<RoleConfigAction> for NoteStorage {
    fn from(action: RoleConfigAction) -> Self {
        NoteStorage::new(action.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// ROLE CONFIG NOTE
// ================================================================================================

/// A RoleConfig note: triggers a
/// [`RoleBasedAccessControl`](crate::account::access::RoleBasedAccessControl) management action on
/// the account that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// management procedures (`grant_role`, `revoke_role`, `set_role_admin`, `renounce_role`). All
/// authorization is enforced by those procedures against the note sender, so the note carries no
/// assets and its authorization is bound to `sender` at creation time.
///
/// The note is tagged for `account` — the account carrying the `RoleBasedAccessControl` component
/// whose role graph is being managed. The `sender` is the account authorized for the selected
/// action: a member of the role's effective admin role for `GrantRole` / `RevokeRole` /
/// `SetRoleAdmin`, or the role holder itself for `RenounceRole`.
///
/// Construct one with the [builder](RoleConfigNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct RoleConfigNote {
    sender: AccountId,
    account: AccountId,
    action: RoleConfigAction,
    serial_number: Word,
    note_type: NoteType,
    attachments: NoteAttachments,
}

#[bon::bon]
impl RoleConfigNote {
    /// Builds a new [`RoleConfigNote`] that triggers `action` on `account`.
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
        action: RoleConfigAction,
        serial_number: Word,
        #[builder(default)] note_type: NoteType,
    ) -> Result<Self, NoteError> {
        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            account,
            action,
            serial_number,
            note_type,
            attachments,
        })
    }
}

impl RoleConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Upper bound on the number of storage items of a RoleConfig note.
    ///
    /// The layout is variable: `GrantRole` / `RevokeRole` use 4 items (`[selector, role_symbol,
    /// account_suffix, account_prefix]`), `SetRoleAdmin` uses 3, and `RenounceRole` uses 2.
    pub const MAX_NUM_STORAGE_ITEMS: usize = 4;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the RoleConfig note.
    pub fn script() -> NoteScript {
        ROLE_CONFIG_SCRIPT.clone()
    }

    /// Returns the RoleConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        ROLE_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the management action carried by the note.
    pub fn action(&self) -> &RoleConfigAction {
        &self.action
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the note's type.
    pub fn note_type(&self) -> NoteType {
        self.note_type
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: role_config_note_builder::State> RoleConfigNoteBuilder<S> {
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

impl<S: role_config_note_builder::State> RoleConfigNoteBuilder<S>
where
    S::SerialNumber: role_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> RoleConfigNoteBuilder<role_config_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<RoleConfigNote> for Note {
    fn from(note: RoleConfigNote) -> Self {
        // RoleConfig notes carry no assets; the action and its arguments live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, note.note_type)
            .with_tag(NoteTag::with_account_target(note.account));
        let recipient = NoteRecipient::new(
            note.serial_number,
            RoleConfigNote::script(),
            NoteStorage::from(note.action),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
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

    fn role(name: &str) -> RoleSymbol {
        RoleSymbol::new(name).expect("role symbol should be valid")
    }

    /// The builder produces an asset-less note tagged for the managed account.
    #[test]
    fn builder_builds_role_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let admin = account_id(2);
        let grantee = account_id(3);

        let note = RoleConfigNote::builder()
            .sender(admin)
            .account(managed)
            .action(RoleConfigAction::GrantRole { role: role("MINTER"), account: grantee })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), admin);
        assert_eq!(note.account(), managed);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Private);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(managed));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// `GrantRole` storage is `[selector, role_symbol, account_suffix, account_prefix]`.
    #[test]
    fn grant_role_storage_layout() {
        let grantee = account_id(3);
        let minter = role("MINTER");
        let storage = NoteStorage::from(RoleConfigAction::GrantRole {
            role: minter.clone(),
            account: grantee,
        });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(RoleConfigAction::SELECTOR_GRANT_ROLE),
                minter.as_element(),
                grantee.suffix(),
                grantee.prefix().as_felt(),
            ]
        );
    }

    /// `SetRoleAdmin` with `None` encodes a zero admin role (revert to the default `ADMIN` role).
    #[test]
    fn set_role_admin_default_storage_layout() {
        let minter = role("MINTER");
        let storage = NoteStorage::from(RoleConfigAction::SetRoleAdmin {
            role: minter.clone(),
            admin_role: None,
        });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(RoleConfigAction::SELECTOR_SET_ROLE_ADMIN),
                minter.as_element(),
                Felt::ZERO,
            ]
        );
    }

    /// `SetRoleAdmin` with `Some` encodes the delegated admin role symbol.
    #[test]
    fn set_role_admin_delegated_storage_layout() {
        let minter = role("MINTER");
        let admin = role("MINT_ADMIN");
        let storage = NoteStorage::from(RoleConfigAction::SetRoleAdmin {
            role: minter.clone(),
            admin_role: Some(admin.clone()),
        });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(RoleConfigAction::SELECTOR_SET_ROLE_ADMIN),
                minter.as_element(),
                admin.as_element(),
            ]
        );
    }

    /// `RenounceRole` storage is `[selector, role_symbol]`.
    #[test]
    fn renounce_role_storage_layout() {
        let minter = role("MINTER");
        let storage = NoteStorage::from(RoleConfigAction::RenounceRole { role: minter.clone() });

        assert_eq!(
            storage.items(),
            &[Felt::from(RoleConfigAction::SELECTOR_RENOUNCE_ROLE), minter.as_element()]
        );
    }
}
