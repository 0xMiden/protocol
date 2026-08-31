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
use crate::note::costs::{NoteConsumptionCost, RBAC_CONFIG_CONSUMPTION_CYCLES};
use crate::note::{AccountTargetNetworkNote, NetworkAccountTarget};

// NOTE SCRIPT
// ================================================================================================

/// Path to the RBAC_CONFIG note script procedure in the standards library.
const RBAC_CONFIG_SCRIPT_PATH: &str = "::miden::standards::notes::rbac_config::main";

// Initialize the RBAC_CONFIG note script only once.
static RBAC_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(RBAC_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains RBAC_CONFIG note script procedure")
});

// RBAC CONFIG
// ================================================================================================

/// A management action of the
/// [`RoleBasedAccessControl`](crate::account::access::RoleBasedAccessControl) component that an
/// [`RbacConfigNote`] triggers on the account that consumes it.
///
/// The action, together with its arguments, is encoded into the note's storage (see
/// [`NoteStorage`] conversion below). Because the storage is fixed at note creation and bound into
/// the note commitment, the authorized party is the note sender: the consuming account's `rbac`
/// procedures authorize against `active_note::get_sender`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbacConfig {
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

impl RbacConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Config note selectors stored in the first storage item. Keep in sync with `rbac_config.masm`.
    const SELECTOR_GRANT_ROLE: u8 = 0;
    const SELECTOR_REVOKE_ROLE: u8 = 1;
    const SELECTOR_SET_ROLE_ADMIN: u8 = 2;
    const SELECTOR_RENOUNCE_ROLE: u8 = 3;

    /// Returns the note storage values encoding this action, laid out as `[selector, ..args]`.
    fn to_storage_values(&self) -> Vec<Felt> {
        match self {
            RbacConfig::GrantRole { role, account } => {
                vec![
                    Felt::from(Self::SELECTOR_GRANT_ROLE),
                    role.as_element(),
                    account.suffix(),
                    account.prefix().as_felt(),
                ]
            },
            RbacConfig::RevokeRole { role, account } => {
                vec![
                    Felt::from(Self::SELECTOR_REVOKE_ROLE),
                    role.as_element(),
                    account.suffix(),
                    account.prefix().as_felt(),
                ]
            },
            RbacConfig::SetRoleAdmin { role, admin_role } => {
                // A missing admin role is encoded as 0, the value `rbac::set_role_admin` treats as
                // "revert to the default ADMIN role".
                let admin_role = admin_role.as_ref().map_or(Felt::ZERO, RoleSymbol::as_element);
                vec![Felt::from(Self::SELECTOR_SET_ROLE_ADMIN), role.as_element(), admin_role]
            },
            RbacConfig::RenounceRole { role } => {
                vec![Felt::from(Self::SELECTOR_RENOUNCE_ROLE), role.as_element()]
            },
        }
    }
}

impl From<RbacConfig> for NoteStorage {
    fn from(config: RbacConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// RBAC CONFIG NOTE
// ================================================================================================

/// An RbacConfig note: triggers a
/// [`RoleBasedAccessControl`](crate::account::access::RoleBasedAccessControl) management action on
/// the account that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// management procedures (`grant_role`, `revoke_role`, `set_role_admin`, `renounce_role`). All
/// authorization is enforced by those procedures against the note sender, so the note carries no
/// assets and its authorization is bound to `sender` at creation time.
///
/// The note is always public and tagged for `account` — the account carrying the
/// `RoleBasedAccessControl` component whose role graph is being managed. The `sender` is the
/// account authorized for the selected action: a member of the role's effective admin role for
/// `GrantRole` / `RevokeRole` / `SetRoleAdmin`, or the role holder itself for `RenounceRole`.
///
/// The note is bound to the target `account` by a [`NetworkAccountTarget`] attachment: the script
/// asserts that the consuming account matches that target before dispatching, so the note cannot be
/// consumed by a third-party account that merely accepts its sender. The binding also
/// makes the note a valid [`AccountTargetNetworkNote`], routing it to `account` for network
/// execution.
///
/// The note must be public: the script rejects a non-public note, so the action cannot be
/// hidden from the chain by a hand-crafted private note with the same script and storage.
///
/// Construct one with the [builder](RbacConfigNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
///
/// ## Security considerations
///
/// A created note is an unordered, unexpiring, uncancellable instruction — treat it as a
/// standing capability and do not create role-management notes ahead of need. Consumption order
/// is chosen by whoever consumes the note, so when rotating a role, wait for the successor's
/// grant to commit before issuing any revoke or renounce (a note that fails because its sender
/// currently lacks the role stays pending and revives if the sender regains it).
#[derive(Debug, Clone)]
pub struct RbacConfigNote {
    sender: AccountId,
    target: AccountId,
    config: RbacConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl RbacConfigNote {
    /// Builds a new [`RbacConfigNote`] that applies `config` to `account`.
    ///
    /// The note is bound to `account` by a [`NetworkAccountTarget`] attachment that the builder
    /// appends unless the caller already supplied one for `account`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `account` is not a public account (the note is bound to it via a `NetworkAccountTarget`,
    ///   which requires a public target).
    /// - the attachments carry a `NetworkAccountTarget` for an account other than `account`.
    /// - the attachments exceed their protocol limit (see [`NoteAttachments::new`]); the target
    ///   attachment occupies one of the available slots when the caller does not supply it.
    #[builder]
    pub fn new(
        #[builder(field)] mut attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        config: RbacConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The note script asserts that the consuming account matches this target before
        // dispatching.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the RbacConfig note to its target account",
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

impl RbacConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Upper bound on the number of storage items of an RbacConfig note.
    ///
    /// The layout is variable: `GrantRole` / `RevokeRole` use 4 items (`[selector, role_symbol,
    /// account_suffix, account_prefix]`), `SetRoleAdmin` uses 3, and `RenounceRole` uses 2.
    pub const MAX_NUM_STORAGE_ITEMS: usize = 4;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the RbacConfig note.
    pub fn script() -> NoteScript {
        RBAC_CONFIG_SCRIPT.clone()
    }

    /// Returns the RbacConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        RBAC_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the management action carried by the note.
    pub fn config(&self) -> &RbacConfig {
        &self.config
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the attachments carried by the note, which always include a
    /// [`NetworkAccountTarget`].
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: rbac_config_note_builder::State> RbacConfigNoteBuilder<S> {
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

impl<S: rbac_config_note_builder::State> RbacConfigNoteBuilder<S>
where
    S::SerialNumber: rbac_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> RbacConfigNoteBuilder<rbac_config_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<RbacConfigNote> for Note {
    fn from(note: RbacConfigNote) -> Self {
        // RbacConfig notes carry no assets and are always public for network execution; the action
        // and its arguments live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            RbacConfigNote::script(),
            NoteStorage::from(note.config),
        );
        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

impl From<RbacConfigNote> for AccountTargetNetworkNote {
    fn from(note: RbacConfigNote) -> Self {
        AccountTargetNetworkNote::new(Note::from(note))
            .expect("RbacConfig note is public and carries a network account target attachment")
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for RbacConfigNote {
    fn consumption_cycles() -> u32 {
        RBAC_CONFIG_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::note::NoteAttachmentScheme;

    use super::*;
    use crate::note::{NetworkAccountTargetError, NetworkNoteExt, NoteExecutionHint};

    fn account_id(seed: u8) -> AccountId {
        typed_account_id(seed, AccountType::Public)
    }

    fn typed_account_id(seed: u8, account_type: AccountType) -> AccountId {
        AccountId::builder().account_type(account_type).build_with_seed([seed; 32])
    }

    fn role(name: &str) -> RoleSymbol {
        RoleSymbol::new(name).expect("role symbol should be valid")
    }

    /// The builder produces a public, asset-less note tagged for the managed account.
    #[test]
    fn builder_builds_rbac_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let admin = account_id(2);
        let grantee = account_id(3);

        let note = RbacConfigNote::builder()
            .sender(admin)
            .target(managed)
            .config(RbacConfig::GrantRole { role: role("MINTER"), account: grantee })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), admin);
        assert_eq!(note.target(), managed);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(managed));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// The builder attaches the network target for the managed account, so the note is a network
    /// note without the caller having to add the attachment.
    #[test]
    fn builder_attaches_network_target() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);

        let note = RbacConfigNote::builder()
            .sender(account_id(2))
            .target(managed)
            .config(RbacConfig::RenounceRole { role: role("MINTER") })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.attachments().num_attachments(), 1);

        let network_note = AccountTargetNetworkNote::from(note);
        assert_eq!(network_note.target_account_id(), managed);
        assert_eq!(network_note.execution_hint(), NoteExecutionHint::Always);
        assert!(network_note.as_note().is_network_note());
    }

    /// Caller-supplied attachments are kept in their order, with the bound network target appended.
    #[test]
    fn builder_keeps_caller_attachments() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let custom_scheme = NoteAttachmentScheme::new(64).unwrap();
        let custom = NoteAttachment::with_word(custom_scheme, Word::from([7u32, 0, 0, 0]));

        let note = RbacConfigNote::builder()
            .attachment(custom.clone())
            .sender(account_id(2))
            .target(managed)
            .config(RbacConfig::RenounceRole { role: role("MINTER") })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        // The target is appended, so the caller's attachment comes first.
        assert_eq!(note.attachments().num_attachments(), 2);
        assert_eq!(note.attachments().get(0), Some(&custom));

        let network_note = AccountTargetNetworkNote::from(note);
        assert_eq!(network_note.target_account_id(), managed);
    }

    /// A caller-supplied `NetworkAccountTarget` for another account is rejected rather than
    /// silently coexisting with the note's own target.
    #[test]
    fn builder_rejects_target_for_other_account() {
        let mut rng = RandomCoin::new(Word::empty());
        let rogue_target =
            NetworkAccountTarget::new(account_id(3), NoteExecutionHint::None).unwrap();

        let err = RbacConfigNote::builder()
            .attachment(rogue_target)
            .sender(account_id(2))
            .target(account_id(1))
            .config(RbacConfig::RenounceRole { role: role("MINTER") })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap_err();

        assert_matches!(err, NoteError::Other { source, .. } => {
            assert_matches!(
              *source.unwrap().downcast().unwrap(),
              NetworkAccountTargetError::TargetMismatch { .. }
            )
        });
    }

    /// A non-public managed account cannot be a network target, so the builder rejects it.
    #[test]
    fn builder_rejects_non_public_account() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = typed_account_id(1, AccountType::Private);

        let err = RbacConfigNote::builder()
            .sender(account_id(2))
            .target(managed)
            .config(RbacConfig::RenounceRole { role: role("MINTER") })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap_err();

        assert_matches!(err, NoteError::Other { source, .. } => {
            assert_matches!(
              *source.unwrap().downcast().unwrap(),
              NetworkAccountTargetError::TargetNotPublic { .. }
            )
        });
    }

    /// `GrantRole` storage is `[selector, role_symbol, account_suffix, account_prefix]`.
    #[test]
    fn grant_role_storage_layout() {
        let grantee = account_id(3);
        let minter = role("MINTER");
        let storage =
            NoteStorage::from(RbacConfig::GrantRole { role: minter.clone(), account: grantee });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(RbacConfig::SELECTOR_GRANT_ROLE),
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
        let storage =
            NoteStorage::from(RbacConfig::SetRoleAdmin { role: minter.clone(), admin_role: None });

        assert_eq!(
            storage.items(),
            &[Felt::from(RbacConfig::SELECTOR_SET_ROLE_ADMIN), minter.as_element(), Felt::ZERO]
        );
    }

    /// `SetRoleAdmin` with `Some` encodes the delegated admin role symbol.
    #[test]
    fn set_role_admin_delegated_storage_layout() {
        let minter = role("MINTER");
        let admin = role("MINT_ADMIN");
        let storage = NoteStorage::from(RbacConfig::SetRoleAdmin {
            role: minter.clone(),
            admin_role: Some(admin.clone()),
        });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(RbacConfig::SELECTOR_SET_ROLE_ADMIN),
                minter.as_element(),
                admin.as_element(),
            ]
        );
    }

    /// `RenounceRole` storage is `[selector, role_symbol]`.
    #[test]
    fn renounce_role_storage_layout() {
        let minter = role("MINTER");
        let storage = NoteStorage::from(RbacConfig::RenounceRole { role: minter.clone() });

        assert_eq!(
            storage.items(),
            &[Felt::from(RbacConfig::SELECTOR_RENOUNCE_ROLE), minter.as_element()]
        );
    }
}
