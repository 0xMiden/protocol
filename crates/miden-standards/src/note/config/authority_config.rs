use alloc::vec::Vec;

use miden_protocol::account::{AccountId, AccountProcedureRoot, RoleSymbol};
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
use crate::note::costs::{AUTHORITY_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};
use crate::note::{AccountTargetNetworkNote, NetworkAccountTarget, NumStorageItems};

// NOTE SCRIPT
// ================================================================================================

/// Path to the AUTHORITY_CONFIG note script procedure in the standards library.
const AUTHORITY_CONFIG_SCRIPT_PATH: &str = "::miden::standards::notes::authority_config::main";

// Initialize the AUTHORITY_CONFIG note script only once.
static AUTHORITY_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(AUTHORITY_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains AUTHORITY_CONFIG note script procedure")
});

// AUTHORITY CONFIG
// ================================================================================================

/// A management action of the [`Authority`](crate::account::access::Authority) component that an
/// [`AuthorityConfigNote`] triggers on the account that consumes it.
///
/// The action, together with its arguments, is encoded into the note's storage (see
/// [`NoteStorage`] conversion below). Because the storage is fixed at note creation and bound into
/// the note commitment, the authorized party is the note sender: the consuming account's
/// `authority` procedures authorize against `active_note::get_sender`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityConfig {
    /// Freeze the account's authority-gated surface. Only the emergency authority is authorized:
    /// the owner under [`Authority::OwnerControlled`](crate::account::access::Authority), or the
    /// holder of the role mapped to `freeze` (`ADMIN` when unmapped) under
    /// [`Authority::RbacControlled`](crate::account::access::Authority).
    Freeze,
    /// Unfreeze the account's authority-gated surface. Authorized like [`Self::Freeze`], resolving
    /// the role mapped to `unfreeze` instead.
    Unfreeze,
    /// Require `role` to invoke the authority-gated procedure with root `procedure_root`, or unmap
    /// the procedure with `None` so it falls back to the `ADMIN` role. Requires an
    /// [`Authority::RbacControlled`](crate::account::access::Authority) authority; the sender must
    /// hold the role mapped to `set_procedure_role` and administer the procedure's current role.
    SetProcedureRole {
        procedure_root: AccountProcedureRoot,
        role: Option<RoleSymbol>,
    },
}

impl AuthorityConfig {
    // VARIANTS
    // --------------------------------------------------------------------------------------------

    // Config note variants stored in the first storage item. Keep in sync with
    // `authority_config.masm`.
    const VARIANT_FREEZE: u8 = 0;
    const VARIANT_UNFREEZE: u8 = 1;
    const VARIANT_SET_PROCEDURE_ROLE: u8 = 2;

    /// Returns the note storage values encoding this action, laid out as `[variant, ..args]`.
    ///
    /// `SetProcedureRole` lays out as `[variant, role_symbol, 0, 0, procedure_root(4)]`: the first
    /// word is padded out so the procedure root starts word-aligned.
    fn to_storage_values(&self) -> Vec<Felt> {
        match self {
            AuthorityConfig::Freeze => vec![Felt::from(Self::VARIANT_FREEZE)],
            AuthorityConfig::Unfreeze => vec![Felt::from(Self::VARIANT_UNFREEZE)],
            AuthorityConfig::SetProcedureRole { procedure_root, role } => {
                // A missing role is encoded as 0, the value `authority::set_procedure_role` treats
                // as "unmap the procedure".
                let role = role.as_ref().map_or(Felt::ZERO, RoleSymbol::as_element);
                let mut values = Vec::with_capacity(AuthorityConfigNote::MAX_NUM_STORAGE_ITEMS);
                values.extend([
                    Felt::from(Self::VARIANT_SET_PROCEDURE_ROLE),
                    role,
                    Felt::ZERO,
                    Felt::ZERO,
                ]);
                values.extend_from_slice(procedure_root.as_word().as_elements());
                values
            },
        }
    }
}

impl From<AuthorityConfig> for NoteStorage {
    fn from(config: AuthorityConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// AUTHORITY CONFIG NOTE
// ================================================================================================

/// An AuthorityConfig note: triggers an [`Authority`](crate::account::access::Authority)
/// management action on the account that consumes it.
///
/// A single note script dispatches on the note variant in its storage to one of the component's
/// management procedures (`freeze`, `unfreeze`, `set_procedure_role`). All authorization is
/// enforced by those procedures against the note sender, so the note carries no assets and its
/// authorization is bound to `sender` at creation time.
///
/// The note is always public and tagged for `account` — the account carrying the `Authority`
/// component whose emergency switch or procedure roles are being managed. The `sender` is the
/// account authorized for the selected action: the emergency authority for `Freeze` / `Unfreeze`,
/// or a holder of the role mapped to `set_procedure_role` that also administers the procedure's
/// current role for `SetProcedureRole`.
///
/// The note is bound to the target `account` by a [`NetworkAccountTarget`] attachment: the script
/// asserts that the consuming account matches that target before dispatching, so the note cannot be
/// consumed by a third-party account that merely accepts its sender. The binding also
/// makes the note a valid [`AccountTargetNetworkNote`], routing it to `account` for network
/// execution.
///
/// The note must be public: the script rejects a non-public note. See
/// [the module docs](crate::note::config#note-type) for the layers that enforce it.
///
/// Construct one with the [builder](AuthorityConfigNote::builder); convert it into a protocol
/// [`Note`] infallibly via `Note::from`.
///
/// ## Security considerations
///
/// A created note is an unordered, unexpiring, uncancellable instruction — treat it as a
/// standing capability and do not create authority notes ahead of need. An `Unfreeze` note
/// created in advance re-opens the account whenever anyone consumes it, defeating a later
/// emergency freeze; a note that fails because its sender currently lacks the authorization stays
/// pending and revives if the sender regains it.
#[derive(Debug, Clone)]
pub struct AuthorityConfigNote {
    sender: AccountId,
    target: AccountId,
    config: AuthorityConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl AuthorityConfigNote {
    /// Builds a new [`AuthorityConfigNote`] that applies `config` to `account`.
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
        config: AuthorityConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The note script asserts that the consuming account matches this target before
        // dispatching.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the AuthorityConfig note to its target account",
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

impl AuthorityConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Upper bound on the number of storage items of an AuthorityConfig note.
    ///
    /// The layout is variable: `Freeze` / `Unfreeze` use 1 item (`[variant]`), while
    /// `SetProcedureRole` uses 8 (`[variant, role_symbol, 0, 0, procedure_root(4)]`).
    pub const MAX_NUM_STORAGE_ITEMS: usize = 4 + AccountProcedureRoot::NUM_ELEMENTS;

    /// The numbers of storage items the AuthorityConfig note script accepts.
    ///
    /// `Freeze` / `Unfreeze` use 1 item, `SetProcedureRole` uses
    /// [`Self::MAX_NUM_STORAGE_ITEMS`], and no size in between is valid. Keep in sync with the
    /// `NUM_ITEMS_*` constants in `authority_config.masm`.
    pub const NUM_STORAGE_ITEMS: NumStorageItems = NumStorageItems::AnyOf(&[
        NumStorageItems::Exact(1),
        NumStorageItems::Exact(Self::MAX_NUM_STORAGE_ITEMS),
    ]);

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the AuthorityConfig note.
    pub fn script() -> NoteScript {
        AUTHORITY_CONFIG_SCRIPT.clone()
    }

    /// Returns the AuthorityConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        AUTHORITY_CONFIG_SCRIPT.root()
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
    pub fn config(&self) -> &AuthorityConfig {
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

impl<S: authority_config_note_builder::State> AuthorityConfigNoteBuilder<S> {
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

impl<S: authority_config_note_builder::State> AuthorityConfigNoteBuilder<S>
where
    S::SerialNumber: authority_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> AuthorityConfigNoteBuilder<authority_config_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<AuthorityConfigNote> for Note {
    fn from(note: AuthorityConfigNote) -> Self {
        // AuthorityConfig notes carry no assets and are always public for network execution; the
        // action and its arguments live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            AuthorityConfigNote::script(),
            NoteStorage::from(note.config),
        );
        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

impl From<AuthorityConfigNote> for AccountTargetNetworkNote {
    fn from(note: AuthorityConfigNote) -> Self {
        AccountTargetNetworkNote::new(Note::from(note)).expect(
            "AuthorityConfig note is public and carries a network account target attachment",
        )
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for AuthorityConfigNote {
    fn consumption_cycles() -> u32 {
        AUTHORITY_CONFIG_CONSUMPTION_CYCLES
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
    use crate::account::access::Authority;
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
    fn builder_builds_authority_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let owner = account_id(2);

        let note = AuthorityConfigNote::builder()
            .sender(owner)
            .target(managed)
            .config(AuthorityConfig::Freeze)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), owner);
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

        let note = AuthorityConfigNote::builder()
            .sender(account_id(2))
            .target(managed)
            .config(AuthorityConfig::Unfreeze)
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

        let note = AuthorityConfigNote::builder()
            .attachment(custom.clone())
            .sender(account_id(2))
            .target(managed)
            .config(AuthorityConfig::Freeze)
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

        let err = AuthorityConfigNote::builder()
            .attachment(rogue_target)
            .sender(account_id(2))
            .target(account_id(1))
            .config(AuthorityConfig::Freeze)
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

        let err = AuthorityConfigNote::builder()
            .sender(account_id(2))
            .target(managed)
            .config(AuthorityConfig::Freeze)
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

    /// `Freeze` / `Unfreeze` storage is a single variant item.
    #[test]
    fn switch_storage_layout() {
        let freeze = NoteStorage::from(AuthorityConfig::Freeze);
        assert_eq!(freeze.items(), &[Felt::from(AuthorityConfig::VARIANT_FREEZE)]);

        let unfreeze = NoteStorage::from(AuthorityConfig::Unfreeze);
        assert_eq!(unfreeze.items(), &[Felt::from(AuthorityConfig::VARIANT_UNFREEZE)]);
    }

    /// `SetProcedureRole` with `Some` pads the variant and role symbol out to a full word so the
    /// procedure root that follows is word-aligned.
    #[test]
    fn set_procedure_role_storage_layout() {
        let procedure_root = Authority::freeze_root();
        let freezer = role("FREEZER");
        let storage = NoteStorage::from(AuthorityConfig::SetProcedureRole {
            procedure_root,
            role: Some(freezer.clone()),
        });

        let mut expected = vec![
            Felt::from(AuthorityConfig::VARIANT_SET_PROCEDURE_ROLE),
            freezer.as_element(),
            Felt::ZERO,
            Felt::ZERO,
        ];
        expected.extend_from_slice(procedure_root.as_word().as_elements());
        assert_eq!(storage.items(), expected.as_slice());
        assert_eq!(storage.items().len(), AuthorityConfigNote::MAX_NUM_STORAGE_ITEMS);
    }

    /// `SetProcedureRole` with `None` encodes a zero role symbol (unmap the procedure).
    #[test]
    fn set_procedure_role_unmap_storage_layout() {
        let procedure_root = Authority::freeze_root();
        let storage =
            NoteStorage::from(AuthorityConfig::SetProcedureRole { procedure_root, role: None });

        assert_eq!(storage.items()[1], Felt::ZERO);
        assert_eq!(storage.items().len(), AuthorityConfigNote::MAX_NUM_STORAGE_ITEMS);
    }

    /// The config-note script root is registered in the [`StandardNote`](crate::note::StandardNote)
    /// reverse lookup.
    #[test]
    fn script_root_is_registered_standard_note() {
        use crate::note::StandardNote;

        let standard = StandardNote::from_script_root(AuthorityConfigNote::script_root())
            .expect("config note script root should be a registered standard note");
        assert_eq!(standard.name(), "AUTHORITY_CONFIG");
    }
}
