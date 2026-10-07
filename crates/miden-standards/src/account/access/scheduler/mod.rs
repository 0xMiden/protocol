use alloc::collections::BTreeSet;
use alloc::vec;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountProcedureRoot,
    AccountStorage,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountError;
use miden_protocol::note::NoteId;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use thiserror::Error;

use crate::account::account_component_code;
use crate::procedure_root;

mod manager;
pub use manager::SchedulerManager;

// CONSTANTS
// ================================================================================================

account_component_code!(SCHEDULER_CODE, "miden-standards-access-scheduler.masp");

static CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::scheduler::config")
        .expect("storage slot name should be valid")
});

static SCHEDULED_PROCEDURES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::scheduler::scheduled_procedures")
        .expect("storage slot name should be valid")
});

static PROPOSALS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::scheduler::proposals")
        .expect("storage slot name should be valid")
});

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`Scheduler::NAME`],
/// which mirrors the standards-side MASM module path.
const SCHEDULER_LIBRARY_PATH: &str = "miden::standards::components::access::scheduler";

procedure_root!(
    SCHEDULER_GET_MIN_DELAY,
    SCHEDULER_LIBRARY_PATH,
    Scheduler::GET_MIN_DELAY_PROC_NAME,
    Scheduler::code()
);

// SCHEDULER COMPONENT
// ================================================================================================

/// Operation scheduler: a mandatory waiting period in front of selected authority-gated
/// procedures.
///
/// Administrative actions on network accounts arrive as notes, so the note is the operation. A
/// proposal records "note X may be consumed no earlier than T" in the account's storage; when a
/// gated procedure's root is flagged as scheduled, `authority::assert_authorized` looks the note
/// being consumed up in that ledger and proceeds only once T has passed, consuming the proposal.
/// Cancelling removes the proposal. The [`NoteId`] binds script, arguments, serial number, assets
/// and sender, so what was proposed and what is consumed are provably the same note.
///
/// Proposing grants no authority: the note's own procedure still checks the sender's role when the
/// note is consumed. The scheduler only decides *when* an already-authorized action may happen.
///
/// This component installs the storage. Administration - `schedule`, `cancel`, `set_min_delay`,
/// `set_procedure_scheduling` - is exposed by [`SchedulerManager`], gated by the account-wide
/// [`Authority`][crate::account::access::Authority]. Under RBAC each of those procedures can carry
/// its own role; the intended shape is a cancel-only `CANCELLER` role that can stop other people's
/// proposals without being able to propose, execute or grant anything itself.
///
/// Storage layout:
/// - Value slot: `[min_delay, 0, 0, 0]`, the waiting period in seconds.
/// - Map slot: `procedure_root` → `[is_scheduled, 0, 0, 0]`, the procedures requiring a proposal.
/// - Map slot: `note_id` → `[ready_at, proposer_suffix, proposer_prefix, 0]`, the proposals.
///
/// `min_delay` lives in the account rather than the note because a note that declared its own
/// delay would let its author choose zero. Staleness of a proposed-but-never-consumed note is left
/// to the note's own expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scheduler {
    min_delay: u32,
    scheduled_procedures: BTreeSet<AccountProcedureRoot>,
}

impl Scheduler {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::access::scheduler";

    const GET_MIN_DELAY_PROC_NAME: &'static str = "get_min_delay";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a scheduler with the given waiting period, in seconds, and no scheduled procedures.
    pub fn new(min_delay: u32) -> Self {
        Self {
            min_delay,
            scheduled_procedures: BTreeSet::new(),
        }
    }

    /// Flags the given procedures as requiring a proposal.
    ///
    /// # Errors
    ///
    /// Returns an error if any procedure is one of the [`SchedulerManager`] entrypoints, mirroring
    /// the onchain `set_procedure_scheduling` check: flagging `schedule` makes proposals
    /// unreachable, flagging `cancel` makes a non-proposer cancellation wait out the delay, and
    /// `set_min_delay` and `set_procedure_scheduling` are already scheduled unconditionally.
    pub fn with_scheduled_procedures(
        mut self,
        procedures: impl IntoIterator<Item = AccountProcedureRoot>,
    ) -> Result<Self, SchedulerError> {
        for procedure in procedures {
            if SchedulerManager::procedure_roots().contains(&procedure) {
                return Err(SchedulerError::CannotScheduleOwnProcedure(procedure));
            }
            self.scheduled_procedures.insert(procedure);
        }
        Ok(self)
    }

    /// Flags a single procedure as requiring a proposal.
    ///
    /// # Errors
    ///
    /// Returns an error if the procedure is one of the [`SchedulerManager`] entrypoints, see
    /// [`Self::with_scheduled_procedures`].
    pub fn with_scheduled_procedure(
        self,
        procedure: AccountProcedureRoot,
    ) -> Result<Self, SchedulerError> {
        self.with_scheduled_procedures([procedure])
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the waiting period, in seconds.
    pub fn min_delay(&self) -> u32 {
        self.min_delay
    }

    /// Returns the procedures flagged as requiring a proposal.
    pub fn scheduled_procedures(&self) -> &BTreeSet<AccountProcedureRoot> {
        &self.scheduled_procedures
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &SCHEDULER_CODE
    }

    /// Returns the procedure root of the `get_min_delay` view procedure.
    pub fn get_min_delay_root() -> AccountProcedureRoot {
        *SCHEDULER_GET_MIN_DELAY
    }

    /// Returns the [`StorageSlotName`] holding the waiting period.
    pub fn config_slot() -> &'static StorageSlotName {
        &CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] holding the scheduled-procedures map.
    pub fn scheduled_procedures_slot() -> &'static StorageSlotName {
        &SCHEDULED_PROCEDURES_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] holding the proposals map.
    pub fn proposals_slot() -> &'static StorageSlotName {
        &PROPOSALS_SLOT_NAME
    }

    /// Reads the waiting period from account storage.
    pub fn try_read_min_delay(storage: &AccountStorage) -> Result<u32, SchedulerError> {
        let word = storage
            .get_item(Self::config_slot())
            .map_err(SchedulerError::MissingStorageSlot)?;
        if word[1..4].iter().any(|felt| *felt != Felt::ZERO) {
            return Err(SchedulerError::NonCanonicalValue);
        }
        u32::try_from(word[0].as_canonical_u64()).map_err(|_| SchedulerError::NonCanonicalValue)
    }

    /// Reads whether `procedure_root` requires a proposal.
    pub fn is_scheduled_procedure(
        storage: &AccountStorage,
        procedure_root: &AccountProcedureRoot,
    ) -> Result<bool, SchedulerError> {
        let word = storage
            .get_map_item(
                Self::scheduled_procedures_slot(),
                StorageMapKey::new(procedure_root.as_word()),
            )
            .map_err(SchedulerError::MissingStorageSlot)?;
        Ok(word != Word::empty())
    }

    /// Reads the readiness timestamp of the proposal for `note_id`, or `None` if the note has no
    /// proposal.
    pub fn try_read_ready_at(
        storage: &AccountStorage,
        note_id: NoteId,
    ) -> Result<Option<u32>, SchedulerError> {
        let word = storage
            .get_map_item(Self::proposals_slot(), StorageMapKey::new(note_id.as_word()))
            .map_err(SchedulerError::MissingStorageSlot)?;
        if word[0] == Felt::ZERO {
            return Ok(None);
        }
        u32::try_from(word[0].as_canonical_u64())
            .map(Some)
            .map_err(|_| SchedulerError::NonCanonicalValue)
    }

    /// Returns the [`AccountComponentMetadata`] describing this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            (
                CONFIG_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Scheduler configuration",
                    [
                        FeltSchema::u32("min_delay"),
                        FeltSchema::new_void(),
                        FeltSchema::new_void(),
                        FeltSchema::new_void(),
                    ],
                ),
            ),
            (
                SCHEDULED_PROCEDURES_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Procedures requiring a proposal (procedure root -> is_scheduled)",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
            (
                PROPOSALS_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Proposals (note id -> ready_at and proposer)",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Scheduler: a mandatory waiting period in front of flagged authority-gated \
                 procedures, keyed by the id of the administrative note that carries them out",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<Scheduler> for AccountComponent {
    fn from(scheduler: Scheduler) -> Self {
        let config = StorageSlot::with_value(
            CONFIG_SLOT_NAME.clone(),
            Word::from([scheduler.min_delay, 0, 0, 0]),
        );

        let flags = scheduler
            .scheduled_procedures
            .into_iter()
            .map(|root| (StorageMapKey::new(root.as_word()), Word::from([1u32, 0, 0, 0])));
        let scheduled_procedures = StorageSlot::with_map(
            SCHEDULED_PROCEDURES_SLOT_NAME.clone(),
            StorageMap::with_entries(flags).expect("scheduled-procedures map should be valid"),
        );

        // Every account starts with no proposals; entries are written by `schedule`.
        let proposals = StorageSlot::with_map(PROPOSALS_SLOT_NAME.clone(), StorageMap::new());

        AccountComponent::new(
            Scheduler::code().clone(),
            vec![config, scheduled_procedures, proposals],
            Scheduler::component_metadata(),
        )
        .expect("scheduler component should satisfy the requirements of a valid account component")
    }
}

// SCHEDULER ERROR
// ================================================================================================

/// Errors raised when configuring a [`Scheduler`] or reading its state from storage.
#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("scheduler procedure {0} cannot be scheduled")]
    CannotScheduleOwnProcedure(AccountProcedureRoot),
    #[error("failed to read scheduler slot from storage")]
    MissingStorageSlot(#[source] AccountError),
    #[error("scheduler storage value is not in canonical form")]
    NonCanonicalValue,
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn seeded_state_is_written_to_storage() -> anyhow::Result<()> {
        let flagged = AccountProcedureRoot::from_raw(Word::from([1u32, 2, 3, 4]));
        let other = AccountProcedureRoot::from_raw(Word::from([9u32, 9, 9, 9]));
        let component: AccountComponent =
            Scheduler::new(3_600).with_scheduled_procedure(flagged)?.into();
        let storage = AccountStorage::new(component.storage_slots().to_vec())?;

        assert_eq!(Scheduler::try_read_min_delay(&storage)?, 3_600);
        assert!(Scheduler::is_scheduled_procedure(&storage, &flagged)?);
        assert!(!Scheduler::is_scheduled_procedure(&storage, &other)?);
        assert_eq!(
            Scheduler::try_read_ready_at(&storage, NoteId::from_raw(Word::from([5u32, 6, 7, 8])))?,
            None
        );

        Ok(())
    }

    /// The builder rejects the scheduler's own entrypoints, like the onchain setter: a scheduled
    /// `schedule` could never create the proposal it would itself require.
    #[rstest::rstest]
    #[case::schedule(SchedulerManager::schedule_root())]
    #[case::cancel(SchedulerManager::cancel_root())]
    #[case::set_min_delay(SchedulerManager::set_min_delay_root())]
    #[case::set_procedure_scheduling(SchedulerManager::set_procedure_scheduling_root())]
    fn own_procedures_cannot_be_scheduled(#[case] root: AccountProcedureRoot) {
        let other = AccountProcedureRoot::from_raw(Word::from([1u32, 2, 3, 4]));

        assert_matches!(
            Scheduler::new(3_600).with_scheduled_procedures([other, root]),
            Err(SchedulerError::CannotScheduleOwnProcedure(rejected)) if rejected == root
        );
        assert_matches!(
            Scheduler::new(3_600).with_scheduled_procedure(root),
            Err(SchedulerError::CannotScheduleOwnProcedure(rejected)) if rejected == root
        );
    }
}
