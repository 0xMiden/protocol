use alloc::vec;

use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountType,
    RoleSymbol,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::pausable_rbac_library;
use crate::procedure_digest;

// PAUSABLE RBAC ACCOUNT COMPONENT
// ================================================================================================

static ROLES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::components::utils::pausable_rbac::roles")
        .expect("storage slot name should be valid")
});

procedure_digest!(
    PAUSABLE_RBAC_PAUSE,
    PausableRbac::NAME,
    PausableRbac::PAUSE_PROC_NAME,
    pausable_rbac_library
);

procedure_digest!(
    PAUSABLE_RBAC_UNPAUSE,
    PausableRbac::NAME,
    PausableRbac::UNPAUSE_PROC_NAME,
    pausable_rbac_library
);

procedure_digest!(
    PAUSABLE_RBAC_IS_PAUSED,
    PausableRbac::NAME,
    PausableRbac::IS_PAUSED_PROC_NAME,
    pausable_rbac_library
);

/// Account component that exposes `pause` / `unpause` / `is_paused` admin procedures gated
/// by separate roles in [`crate::account::access::RoleBasedAccessControl`].
///
/// Pause requires the `PAUSER` role; unpause requires the `UNPAUSER` role. Splitting the
/// privilege into two distinct roles allows separation of duties between the parties that
/// can pause and those that can unpause.
///
/// ## Role identifiers — Pattern 2 (storage-driven from Rust constants)
///
/// The role symbols are not user-configurable; they are fixed Rust constants
/// (`PAUSER` and `UNPAUSER`). However, the encoded [`RoleSymbol`] felts are written
/// into this component's storage slot at install time, and MASM reads them from
/// storage rather than embedding literal felts. This keeps a single Rust source-of-
/// truth for the role identifiers and is robust against any future change to
/// `RoleSymbol` encoding — both the storage layout and any [`Self::pauser_role`] /
/// [`Self::unpauser_role`] callers always go through the canonical Rust encoder.
///
/// Authorize accounts at runtime via `rbac::grant_role` with [`Self::pauser_role`] and
/// [`Self::unpauser_role`].
///
/// ## Companion components required
///
/// - [`crate::account::access::RoleBasedAccessControl`] — provides role membership storage and the
///   `assert_sender_has_role` procedure used to validate the sender.
/// - [`crate::account::pausable::Pausable`] — provides the `is_paused` storage slot that pause /
///   unpause write to.
///
/// ## Storage
///
/// - [`Self::roles_slot()`]: single word containing `[pauser_role, unpauser_role, 0, 0]`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PausableRbac;

impl PausableRbac {
    /// Component library path (merged account module name).
    pub const NAME: &'static str = "miden::standards::components::utils::pausable_rbac";

    pub const PAUSE_PROC_NAME: &'static str = "pause";
    pub const UNPAUSE_PROC_NAME: &'static str = "unpause";
    pub const IS_PAUSED_PROC_NAME: &'static str = "is_paused";

    /// Single Rust source-of-truth for the role-symbol strings. Both [`Self::pauser_role`]
    /// and the storage initializer in [`From<Self>`] derive their [`RoleSymbol`] from
    /// these via the same canonical encoder, so encoding changes propagate consistently.
    const PAUSER_ROLE_NAME: &'static str = "PAUSER";
    const UNPAUSER_ROLE_NAME: &'static str = "UNPAUSER";

    /// Returns the encoded [`RoleSymbol`] required to call `pause`. Use with
    /// [`miden_standards::account::access::RoleBasedAccessControl`]'s `grant_role` to
    /// authorize an account.
    pub fn pauser_role() -> RoleSymbol {
        RoleSymbol::new(Self::PAUSER_ROLE_NAME).expect("PAUSER fits in RoleSymbol")
    }

    /// Returns the encoded [`RoleSymbol`] required to call `unpause`.
    pub fn unpauser_role() -> RoleSymbol {
        RoleSymbol::new(Self::UNPAUSER_ROLE_NAME).expect("UNPAUSER fits in RoleSymbol")
    }

    /// Storage slot name for the roles word.
    pub fn roles_slot() -> &'static StorageSlotName {
        &ROLES_SLOT_NAME
    }

    /// Schema entry for the roles slot (documentation / tooling).
    pub fn roles_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::roles_slot().clone(),
            StorageSlotSchema::value(
                "Encoded role symbols for pause/unpause; word layout \
                 [pauser_role, unpauser_role, 0, 0]",
                [
                    FeltSchema::felt("pauser_role"),
                    FeltSchema::felt("unpauser_role"),
                    FeltSchema::felt("reserved_0"),
                    FeltSchema::felt("reserved_1"),
                ],
            ),
        )
    }

    /// Returns the digest of the `pause` procedure exposed by this component.
    pub fn pause_digest() -> Word {
        *PAUSABLE_RBAC_PAUSE
    }

    /// Returns the digest of the `unpause` procedure exposed by this component.
    pub fn unpause_digest() -> Word {
        *PAUSABLE_RBAC_UNPAUSE
    }

    /// Returns the digest of the `is_paused` procedure exposed by this component.
    pub fn is_paused_digest() -> Word {
        *PAUSABLE_RBAC_IS_PAUSED
    }

    /// Returns the [`AccountComponentMetadata`] describing this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::roles_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description(
                "Role-gated pause admin: wraps pausable::pause/unpause with separate PAUSER \
                 and UNPAUSER role checks via RoleBasedAccessControl::assert_sender_has_role. \
                 Requires the RoleBasedAccessControl and Pausable companion components.",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<PausableRbac> for AccountComponent {
    fn from(_: PausableRbac) -> Self {
        // Encode role symbols at install time using the canonical Rust encoder and write
        // them into the component's storage slot. MASM reads from storage rather than
        // embedding literal felts so the encoding stays in lockstep with Rust.
        let roles_word = Word::from([
            PausableRbac::pauser_role().into(),
            PausableRbac::unpauser_role().into(),
            miden_protocol::Felt::ZERO,
            miden_protocol::Felt::ZERO,
        ]);

        let roles_slot = StorageSlot::with_value(PausableRbac::roles_slot().clone(), roles_word);

        AccountComponent::new(
            pausable_rbac_library(),
            vec![roles_slot],
            PausableRbac::component_metadata(),
        )
        .expect(
            "PausableRbac component should satisfy the requirements of a valid account component",
        )
    }
}
