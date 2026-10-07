use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// SCHEDULER MANAGER COMPONENT
// ================================================================================================

account_component_code!(SCHEDULER_MANAGER_CODE, "miden-standards-access-scheduler-manager.masp");

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`SchedulerManager::NAME`], which mirrors the standards-side MASM module path.
const SCHEDULER_MANAGER_LIBRARY_PATH: &str =
    "miden::standards::components::access::scheduler::manager";

procedure_root!(
    SCHEDULER_MANAGER_SCHEDULE,
    SCHEDULER_MANAGER_LIBRARY_PATH,
    SchedulerManager::SCHEDULE_PROC_NAME,
    SchedulerManager::code()
);

procedure_root!(
    SCHEDULER_MANAGER_CANCEL,
    SCHEDULER_MANAGER_LIBRARY_PATH,
    SchedulerManager::CANCEL_PROC_NAME,
    SchedulerManager::code()
);

procedure_root!(
    SCHEDULER_MANAGER_SET_MIN_DELAY,
    SCHEDULER_MANAGER_LIBRARY_PATH,
    SchedulerManager::SET_MIN_DELAY_PROC_NAME,
    SchedulerManager::code()
);

procedure_root!(
    SCHEDULER_MANAGER_SET_PROCEDURE_SCHEDULING,
    SCHEDULER_MANAGER_LIBRARY_PATH,
    SchedulerManager::SET_PROCEDURE_SCHEDULING_PROC_NAME,
    SchedulerManager::code()
);

/// Account component exposing the scheduler's admin procedures, gated by the account-wide
/// [`Authority`][crate::account::access::Authority] via `exec.authority::assert_authorized`.
///
/// - `schedule` proposes a note; the proposer is recorded so it can withdraw its own proposal.
/// - `cancel` withdraws a proposal: allowed to the proposer, or to whoever `Authority` authorizes
///   for `cancel` - under RBAC the role mapped to [`Self::cancel_root`], e.g. `CANCELLER`.
/// - `set_min_delay` and `set_procedure_scheduling` are themselves scheduled unconditionally, so
///   weakening the timelock waits out the current delay first. The scheduler's own procedures
///   cannot be flagged.
///
/// Companion components required:
/// - [`Authority`][crate::account::access::Authority] - provides the auth dispatch.
/// - [`super::Scheduler`] - provides the storage slots.
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedulerManager;

impl SchedulerManager {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::access::scheduler::manager";

    const SCHEDULE_PROC_NAME: &'static str = "schedule";
    const CANCEL_PROC_NAME: &'static str = "cancel";
    const SET_MIN_DELAY_PROC_NAME: &'static str = "set_min_delay";
    const SET_PROCEDURE_SCHEDULING_PROC_NAME: &'static str = "set_procedure_scheduling";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &SCHEDULER_MANAGER_CODE
    }

    /// Returns the procedure root of `schedule`.
    pub fn schedule_root() -> AccountProcedureRoot {
        *SCHEDULER_MANAGER_SCHEDULE
    }

    /// Returns the procedure root of `cancel`.
    pub fn cancel_root() -> AccountProcedureRoot {
        *SCHEDULER_MANAGER_CANCEL
    }

    /// Returns the procedure root of `set_min_delay`.
    pub fn set_min_delay_root() -> AccountProcedureRoot {
        *SCHEDULER_MANAGER_SET_MIN_DELAY
    }

    /// Returns the procedure root of `set_procedure_scheduling`.
    pub fn set_procedure_scheduling_root() -> AccountProcedureRoot {
        *SCHEDULER_MANAGER_SET_PROCEDURE_SCHEDULING
    }

    /// Returns the roots of the scheduler's own entrypoints, which can never be scheduled.
    pub(super) fn procedure_roots() -> [AccountProcedureRoot; 4] {
        [
            Self::schedule_root(),
            Self::cancel_root(),
            Self::set_min_delay_root(),
            Self::set_procedure_scheduling_root(),
        ]
    }
}

impl From<SchedulerManager> for AccountComponent {
    fn from(_: SchedulerManager) -> Self {
        let metadata = AccountComponentMetadata::new(SchedulerManager::NAME).with_description(
            "SchedulerManager: schedule / cancel / set_min_delay / set_procedure_scheduling admin \
             procedures gated by the account-wide Authority component. Requires the Scheduler \
             companion component for storage and the Authority component for auth dispatch.",
        );
        AccountComponent::new(SchedulerManager::code().clone(), vec![], metadata).expect(
            "scheduler manager component should satisfy the requirements of a valid account component",
        )
    }
}
