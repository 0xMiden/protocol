use alloc::vec::Vec;

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    AccountComponent,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Hasher, Word};

// Slots and schemas reused from `AuthMultisig` to keep the storage layout in sync. The statics
// are exposed as `pub(super)` in the sibling `multisig` module; we reference them directly so
// the sharing is visible at the use site rather than hidden behind delegating methods.
use super::super::multisig::{
    APPROVER_PUBKEYS_SLOT_NAME,
    APPROVER_SCHEME_ID_SLOT_NAME,
    EXECUTED_TRANSACTIONS_SLOT_NAME,
    THRESHOLD_CONFIG_SLOT_NAME,
};
use super::ProcedurePolicy;
use super::config::DelayedExecutionPolicy;
use super::spending_limits::SpendingLimitsPolicy;
use crate::account::account_component_package;
use crate::account::auth::{Approver, ApproverSet};
use crate::{MULTISIG_SMART_CANCEL_PROPOSAL_DOMAIN, procedure_root};

account_component_package!(MULTISIG_SMART_PACKAGE, "miden-standards-auth-multisig-smart.masp");

// The library path the component is compiled under (its project.toml `namespace`), which is what
// procedure roots are exported under. This differs from [`AuthMultisigSmart::NAME`] by the
// `components` segment.
const MULTISIG_SMART_LIBRARY_PATH: &str = "miden::standards::components::auth::multisig_smart";

// Procedure-root statics for the component's control-plane procedures. Callers need these to
// attach a per-procedure policy to them, which is how an account raises the threshold guarding a
// sensitive procedure above its default (e.g. requiring 4-of-5 to rotate the approver set).
procedure_root!(
    MULTISIG_SMART_UPDATE_DELAYED_EXECUTION_POLICY,
    MULTISIG_SMART_LIBRARY_PATH,
    AuthMultisigSmart::UPDATE_DELAYED_EXECUTION_POLICY_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_UPDATE_SIGNERS_AND_THRESHOLD,
    MULTISIG_SMART_LIBRARY_PATH,
    AuthMultisigSmart::UPDATE_SIGNERS_AND_THRESHOLD_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_SET_PROCEDURE_POLICY,
    MULTISIG_SMART_LIBRARY_PATH,
    AuthMultisigSmart::SET_PROCEDURE_POLICY_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_PROPOSE_TRANSACTION,
    MULTISIG_SMART_LIBRARY_PATH,
    AuthMultisigSmart::PROPOSE_TRANSACTION_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_CANCEL_TRANSACTION_PROPOSAL,
    MULTISIG_SMART_LIBRARY_PATH,
    AuthMultisigSmart::CANCEL_TRANSACTION_PROPOSAL_PROC_NAME,
    AuthMultisigSmart::code()
);

// Procedure roots of the spending-limit configuration procedures. Callers need them to attach a
// per-procedure policy, since each of them can weaken the spending limit.
procedure_root!(
    MULTISIG_SMART_UPDATE_SPENDING_LIMITS_POLICY,
    MULTISIG_SMART_LIBRARY_PATH,
    AuthMultisigSmart::UPDATE_SPENDING_LIMITS_POLICY_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_UPDATE_SPENDING_ORACLE,
    MULTISIG_SMART_LIBRARY_PATH,
    AuthMultisigSmart::UPDATE_SPENDING_ORACLE_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_SET_SPENDING_LIMIT,
    MULTISIG_SMART_LIBRARY_PATH,
    AuthMultisigSmart::SET_SPENDING_LIMIT_PROC_NAME,
    AuthMultisigSmart::code()
);

// CONSTANTS
// ================================================================================================

// Only the smart-specific slots need their own constants here. The four slots reused from
// `AuthMultisig` (threshold config, approver public keys, approver scheme ids, executed
// transactions) are imported from that sibling module above.
static PROCEDURE_POLICIES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::procedure_policies")
        .expect("storage slot name should be valid")
});

static DELAY_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::delay_config")
        .expect("storage slot name should be valid")
});

static TX_PROPOSALS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::tx_proposals")
        .expect("storage slot name should be valid")
});

static SPENDING_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::spending_config")
        .expect("storage slot name should be valid")
});

static SPENDING_ORACLE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::spending_oracle")
        .expect("storage slot name should be valid")
});

static SPENDING_BASE_ASSET_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::spending_base_asset")
        .expect("storage slot name should be valid")
});

static SPENDING_LIMIT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::spending_limit")
        .expect("storage slot name should be valid")
});

static SPENDING_TRACKER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::spending_tracker")
        .expect("storage slot name should be valid")
});

// MULTISIG SMART AUTHENTICATION COMPONENT
// ================================================================================================

/// Configuration for [`AuthMultisigSmart`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMultisigSmartConfig {
    approver_set: ApproverSet,
    procedure_policies: Vec<(AccountProcedureRoot, ProcedurePolicy)>,
    delayed_execution_policy: DelayedExecutionPolicy,
    spending_limits_policy: Option<SpendingLimitsPolicy>,
}

impl AuthMultisigSmartConfig {
    /// Creates a new configuration from the given approver set and delayed execution policy.
    ///
    /// `delayed_execution_policy` is required — `AuthMultisigSmart` always runs with a configured
    /// timelock policy; see [`DelayedExecutionPolicy::new`] for its validation rules.
    pub fn new(
        approver_set: ApproverSet,
        delayed_execution_policy: DelayedExecutionPolicy,
    ) -> Self {
        Self {
            approver_set,
            procedure_policies: Vec::new(),
            delayed_execution_policy,
            spending_limits_policy: None,
        }
    }

    /// Attaches a spending-limit policy.
    ///
    /// Without one the spending-limit slots still exist, with a zero window length that disables
    /// the policy. The procedures that edit this configuration need policies of their own; see the
    /// `Security` section on [`AuthMultisigSmart`].
    pub fn with_spending_limits_policy(mut self, policy: SpendingLimitsPolicy) -> Self {
        self.spending_limits_policy = Some(policy);
        self
    }

    /// Attaches a per-procedure smart policy map.
    ///
    /// The procedures that edit this configuration need policies of their own; see the `Security`
    /// section on [`AuthMultisigSmart`]. Policies on `propose_transaction` and
    /// `cancel_transaction_proposal` are rejected, as the auth procedure would ignore them.
    pub fn with_proc_policies(
        mut self,
        proc_policies: Vec<(AccountProcedureRoot, ProcedurePolicy)>,
    ) -> Result<Self, AccountError> {
        validate_proc_policies(self.approver_set.approvers().len() as u32, &proc_policies)?;
        self.procedure_policies = proc_policies;
        Ok(self)
    }

    pub fn approver_set(&self) -> &ApproverSet {
        &self.approver_set
    }

    pub fn approvers(&self) -> &[Approver] {
        self.approver_set.approvers()
    }

    pub fn default_threshold(&self) -> u32 {
        self.approver_set.threshold().get()
    }

    pub fn procedure_policies(&self) -> &[(AccountProcedureRoot, ProcedurePolicy)] {
        &self.procedure_policies
    }

    pub fn delayed_execution_policy(&self) -> DelayedExecutionPolicy {
        self.delayed_execution_policy
    }

    pub fn spending_limits_policy(&self) -> Option<&SpendingLimitsPolicy> {
        self.spending_limits_policy.as_ref()
    }
}

fn validate_proc_policies(
    num_approvers: u32,
    proc_policies: &[(AccountProcedureRoot, ProcedurePolicy)],
) -> Result<(), AccountError> {
    // Reject duplicate procedure roots. Catching it here turns the failure into a regular
    // `AccountError` returned from `with_proc_policies` / `AuthMultisigSmart::new`.
    let mut policy_roots = alloc::collections::BTreeSet::new();
    for (proc_root, _) in proc_policies {
        if !policy_roots.insert(*proc_root) {
            return Err(AccountError::other(
                "duplicate procedure roots are not allowed in the procedure policy map",
            ));
        }
        // Mirrors `set_procedure_policy`: the delay actions verify their own signatures, so a
        // policy on them would be ignored.
        if *proc_root == AuthMultisigSmart::propose_transaction_root()
            || *proc_root == AuthMultisigSmart::cancel_transaction_proposal_root()
        {
            return Err(AccountError::other(
                "procedure policies cannot be set on propose_transaction or cancel_transaction_proposal",
            ));
        }
    }

    for (_, policy) in proc_policies {
        if let Some(immediate_threshold) = policy.immediate_threshold()
            && immediate_threshold > num_approvers
        {
            return Err(AccountError::other(
                "procedure policy immediate threshold cannot exceed number of approvers",
            ));
        }
        if let Some(delay_threshold) = policy.delay_threshold()
            && delay_threshold > num_approvers
        {
            return Err(AccountError::other(
                "procedure policy delay threshold cannot exceed number of approvers",
            ));
        }
    }

    Ok(())
}

/// An [`AccountComponent`] implementing a multisig auth component with smart-policy slots.
///
/// Procedures whose policy requires delayed execution must first be proposed (recorded in the
/// proposals map) and can only execute once the timelock has elapsed. Both `propose_transaction`
/// and the eventual execution verify the approver signatures over the *proposed transaction's*
/// commitment, so approvers sign the actual transaction they intend to run. The auth procedure
/// takes the immediate path whenever the verified signatures reach the transaction's immediate
/// threshold and falls back to the delayed path otherwise, so a proposal only ever opens the
/// cheaper path; it cannot hold back a transaction that has the signatures to execute immediately.
///
/// # Auth args
///
/// The transaction's auth args are the commitment to
/// [`MultisigAuthArgs`](crate::account::auth::MultisigAuthArgs).
///
/// # Security
///
/// A [`ProcedurePolicy`] threshold below the default acts like a lowered per-procedure override of
/// [`AuthMultisig`](crate::account::auth::AuthMultisig), so a procedure with such a policy should
/// seal the notes it creates for the reasons described there.
///
/// Delayed execution verifies proposal signatures over the proposed transaction's commitment, and
/// three properties follow from that which callers and operators must account for:
///
/// - A proposal signature is bound to the proposed transaction's commitment, which is a stable,
///   replayable message, so cancelling is final: the cancelled proposal keeps its record with
///   `unlock_block` set to [`AuthMultisigSmart::CANCELLED_UNLOCK_BLOCK`], and that commitment can
///   neither be re-proposed nor executed through the timelock again. Otherwise one approver could
///   re-propose it right after every cancellation, and its execution signatures would stay usable
///   until the approval expiration its own signers chose. Approvers who do want a cancelled action
///   re-sign it with a new salt. Cancelling cannot stop a semantically-equivalent proposal built
///   with a different salt, which has a different commitment, so off-chain monitoring of the
///   proposals map is still required.
///
/// - Proposing pre-authorizes execution. Because both proposing and executing verify signatures
///   over the same (proposed) commitment, an approver's proposal signature also counts toward the
///   execution threshold and can be reused for it. An approver who signs to propose a transaction
///   has therefore also contributed a signature usable to execute it; consent cannot be withdrawn
///   passively, only by cancelling.
///
/// - Cancelling requires its own signatures. They are verified over
///   [`AuthMultisigSmart::cancel_signing_message`], which is domain-separated from the proposed
///   commitment, so the public proposal signatures cannot be replayed to cancel a proposal; only
///   approvers who sign the cancel message can veto it. How many must sign is the greater of the
///   [`DelayedExecutionPolicy`] `cancel_threshold` in force when the proposal was recorded and the
///   number of approvers that signed the proposal, capped by the current approver count: proposers
///   can only raise the quorum with real approver signatures, never lower it below the floor, and a
///   group smaller than the proposers cannot veto them. Signatures do not distinguish the immediate
///   from the delayed path, so a signing round meant for immediate execution that stalls above the
///   delayed threshold can be proposed by whoever holds the signatures, and once the signers
///   outnumber the rest nobody can veto it; approvers who want a transaction to run immediately or
///   not at all sign it without an approval expiration, which closes the delayed path.
///
/// - A proposal cannot block execution. The path is chosen from the verified signatures, so a
///   transaction carrying enough signatures for immediate execution runs whether or not someone
///   proposed its commitment, and any such proposal is dropped when it executes. A rogue approver
///   or a relayer holding a single signature can therefore only open the delayed path for a
///   commitment, never force a fully signed transaction through the timelock or make an
///   immediate-only procedure unexecutable.
///
/// A policy protects a procedure only while the procedures that can weaken it are protected at
/// least as strongly. `update_delayed_execution_policy` shortens the timelock,
/// `set_procedure_policy` rewrites any policy, and `update_signers_and_threshold` replaces the
/// approvers and the default threshold; without a policy of their own, each costs only the default
/// threshold. Say rotation is guarded by an immediate threshold of 4 or a delayed threshold of 2
/// behind a seven-day timelock, while those three procedures are left unpolicied under a default
/// threshold of 2. An attacker holding two keys lowers `min_delay` to one block immediately, then
/// proposes and executes the rotation two blocks later with the same two keys; the seven days and
/// the four-key threshold never apply. Give these procedures a policy at least as strong as the
/// strongest policy they can weaken, so that lowering a protection with fewer keys has to go
/// through a proposal and wait out the current timelock, during which the other approvers can
/// cancel it.
///
/// The spending limit configured through [`SpendingLimitsPolicy`] is only as strong as the
/// policies on the procedures that can weaken it. `update_spending_limits_policy` shortens the
/// window, `update_spending_oracle` changes what every converted amount means, and
/// `set_spending_limit` lifts the limit; without a policy of their own, each costs only the
/// default threshold. Give them a [`ProcedurePolicy`] at least as strong as the protection the
/// limit is meant to provide.
#[derive(Debug)]
pub struct AuthMultisigSmart {
    config: AuthMultisigSmartConfig,
}

impl AuthMultisigSmart {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::multisig_smart";

    /// The `unlock_block` of a cancelled proposal record in the tx-proposals map.
    ///
    /// Cancelling keeps the record and sets its unlock block to this value, which no reference
    /// block can reach, so the commitment stays closed to proposing and delayed execution.
    pub const CANCELLED_UNLOCK_BLOCK: BlockNumber = BlockNumber::MAX;

    pub const UPDATE_DELAYED_EXECUTION_POLICY_PROC_NAME: &'static str =
        "update_delayed_execution_policy";

    /// The name of the procedure that rotates the approver set and thresholds.
    pub const UPDATE_SIGNERS_AND_THRESHOLD_PROC_NAME: &'static str = "update_signers_and_threshold";

    /// The name of the procedure that edits per-procedure policies.
    pub const SET_PROCEDURE_POLICY_PROC_NAME: &'static str = "set_procedure_policy";

    /// The name of the procedure that records a delayed-execution proposal.
    pub const PROPOSE_TRANSACTION_PROC_NAME: &'static str = "propose_transaction";

    /// The name of the procedure that cancels a delayed-execution proposal.
    pub const CANCEL_TRANSACTION_PROPOSAL_PROC_NAME: &'static str = "cancel_transaction_proposal";

    /// The names of the spending-limit configuration procedures.
    const UPDATE_SPENDING_LIMITS_POLICY_PROC_NAME: &'static str = "update_spending_limits_policy";
    const UPDATE_SPENDING_ORACLE_PROC_NAME: &'static str = "update_spending_oracle";
    const SET_SPENDING_LIMIT_PROC_NAME: &'static str = "set_spending_limit";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &MULTISIG_SMART_PACKAGE.code
    }

    /// Returns the procedure root of the `update_spending_limits_policy` account procedure.
    pub fn update_spending_limits_policy_root() -> AccountProcedureRoot {
        *MULTISIG_SMART_UPDATE_SPENDING_LIMITS_POLICY
    }

    /// Returns the procedure root of the `update_spending_oracle` account procedure.
    pub fn update_spending_oracle_root() -> AccountProcedureRoot {
        *MULTISIG_SMART_UPDATE_SPENDING_ORACLE
    }

    /// Returns the procedure root of the `set_spending_limit` account procedure.
    pub fn set_spending_limit_root() -> AccountProcedureRoot {
        *MULTISIG_SMART_SET_SPENDING_LIMIT
    }

    /// Creates a new [`AuthMultisigSmart`] component from the provided configuration.
    pub fn new(config: AuthMultisigSmartConfig) -> Result<Self, AccountError> {
        let num_approvers = config.approvers().len() as u32;
        validate_proc_policies(num_approvers, config.procedure_policies())?;
        if config.delayed_execution_policy().cancel_threshold() > num_approvers {
            return Err(AccountError::other(
                "delayed execution cancel_threshold cannot exceed number of approvers",
            ));
        }
        Ok(Self { config })
    }

    /// Returns the approver list configured for this component.
    pub fn approvers(&self) -> &[Approver] {
        self.config.approvers()
    }

    /// Returns the default approver threshold.
    pub fn default_threshold(&self) -> u32 {
        self.config.default_threshold()
    }

    /// Returns the per-procedure smart policy map.
    pub fn procedure_policies(&self) -> &[(AccountProcedureRoot, ProcedurePolicy)] {
        self.config.procedure_policies()
    }

    /// Returns the configured delayed-execution policy.
    pub fn delayed_execution_policy(&self) -> DelayedExecutionPolicy {
        self.config.delayed_execution_policy()
    }

    pub fn threshold_config_slot() -> &'static StorageSlotName {
        &THRESHOLD_CONFIG_SLOT_NAME
    }

    pub fn approver_public_keys_slot() -> &'static StorageSlotName {
        &APPROVER_PUBKEYS_SLOT_NAME
    }

    pub fn approver_scheme_ids_slot() -> &'static StorageSlotName {
        &APPROVER_SCHEME_ID_SLOT_NAME
    }

    pub fn executed_transactions_slot() -> &'static StorageSlotName {
        &EXECUTED_TRANSACTIONS_SLOT_NAME
    }

    pub fn procedure_policies_slot() -> &'static StorageSlotName {
        &PROCEDURE_POLICIES_SLOT_NAME
    }

    pub fn delay_config_slot() -> &'static StorageSlotName {
        &DELAY_CONFIG_SLOT_NAME
    }

    pub fn tx_proposals_slot() -> &'static StorageSlotName {
        &TX_PROPOSALS_SLOT_NAME
    }

    /// Returns the [`AccountProcedureRoot`] of the `update_delayed_execution_policy` procedure.
    ///
    /// Use it to key a [`ProcedurePolicy`] that guards timelock changes. Shortening the timelock
    /// weakens every delayed policy, so this policy should be at least as strong as the strongest
    /// of them; see the `Security` section on [`AuthMultisigSmart`].
    pub fn update_delayed_execution_policy_root() -> AccountProcedureRoot {
        *MULTISIG_SMART_UPDATE_DELAYED_EXECUTION_POLICY
    }

    /// Returns the [`AccountProcedureRoot`] of the `update_signers_and_threshold` procedure.
    ///
    /// Use it to key a [`ProcedurePolicy`] that guards approver-set rotation at a higher threshold
    /// than the account default.
    pub fn update_signers_and_threshold_root() -> AccountProcedureRoot {
        *MULTISIG_SMART_UPDATE_SIGNERS_AND_THRESHOLD
    }

    /// Returns the message approvers sign to cancel the proposal for `tx_summary_commitment`.
    ///
    /// Mirrors `cancel_signing_message` in the MASM component: the proposal stays keyed by the raw
    /// commitment, but cancellation signatures are over its hash under
    /// [`MULTISIG_SMART_CANCEL_PROPOSAL_DOMAIN`], so that proposal signatures (which
    /// are over the commitment itself and also authorize execution) cannot be replayed to cancel.
    pub fn cancel_signing_message(tx_summary_commitment: Word) -> Word {
        Hasher::hash_double_word_in_domain(
            &[tx_summary_commitment, Word::empty()],
            MULTISIG_SMART_CANCEL_PROPOSAL_DOMAIN,
        )
    }

    /// Returns the [`AccountProcedureRoot`] of the `set_procedure_policy` procedure.
    ///
    /// It is the only procedure that writes the policy map, so callers guarding policy edits
    /// commonly need its root. Rewriting a policy weakens whatever it protects, so this policy
    /// should be at least as strong as the strongest policy in the map; see the `Security` section
    /// on [`AuthMultisigSmart`].
    pub fn set_procedure_policy_root() -> AccountProcedureRoot {
        *MULTISIG_SMART_SET_PROCEDURE_POLICY
    }

    /// Returns the [`AccountProcedureRoot`] of the `propose_transaction` procedure.
    ///
    /// It cannot carry a [`ProcedurePolicy`]: proposing verifies its own signatures.
    pub fn propose_transaction_root() -> AccountProcedureRoot {
        *MULTISIG_SMART_PROPOSE_TRANSACTION
    }

    /// Returns the [`AccountProcedureRoot`] of the `cancel_transaction_proposal` procedure.
    ///
    /// It cannot carry a [`ProcedurePolicy`]: cancelling verifies its own signatures.
    pub fn cancel_transaction_proposal_root() -> AccountProcedureRoot {
        *MULTISIG_SMART_CANCEL_TRANSACTION_PROPOSAL
    }

    pub fn spending_config_slot() -> &'static StorageSlotName {
        &SPENDING_CONFIG_SLOT_NAME
    }

    pub fn spending_oracle_slot() -> &'static StorageSlotName {
        &SPENDING_ORACLE_SLOT_NAME
    }

    pub fn spending_base_asset_slot() -> &'static StorageSlotName {
        &SPENDING_BASE_ASSET_SLOT_NAME
    }

    pub fn spending_limit_slot() -> &'static StorageSlotName {
        &SPENDING_LIMIT_SLOT_NAME
    }

    pub fn spending_tracker_slot() -> &'static StorageSlotName {
        &SPENDING_TRACKER_SLOT_NAME
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        MULTISIG_SMART_PACKAGE.metadata.clone()
    }
}

impl From<AuthMultisigSmart> for AccountComponent {
    fn from(multisig: AuthMultisigSmart) -> Self {
        let mut storage_slots = Vec::with_capacity(12);

        // Threshold config slot (value: [threshold, num_approvers, 0, 0])
        let num_approvers = multisig.config.approvers().len() as u32;
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::threshold_config_slot().clone(),
            Word::from([multisig.config.default_threshold(), num_approvers, 0, 0]),
        ));

        // Approver public keys slot (map)
        let map_entries = multisig.config.approvers().iter().enumerate().map(|(i, approver)| {
            (StorageMapKey::from_index(i as u32), Word::from(approver.pub_key()))
        });
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::approver_public_keys_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        // Approver scheme IDs slot
        let scheme_id_entries =
            multisig.config.approvers().iter().enumerate().map(|(i, approver)| {
                (
                    StorageMapKey::from_index(i as u32),
                    Word::from([approver.auth_scheme() as u32, 0, 0, 0]),
                )
            });
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::approver_scheme_ids_slot().clone(),
            StorageMap::with_entries(scheme_id_entries).unwrap(),
        ));

        // Executed transactions slot (map)
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::executed_transactions_slot().clone(),
            StorageMap::default(),
        ));

        // Procedure policies slot (map)
        let procedure_policies = StorageMap::with_entries(
            multisig.config.procedure_policies().iter().map(|(proc_root, policy)| {
                (StorageMapKey::from_raw(proc_root.as_word()), policy.to_word())
            }),
        )
        .unwrap();
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::procedure_policies_slot().clone(),
            procedure_policies,
        ));

        // Delay config slot.
        let delayed_execution_policy = multisig.config.delayed_execution_policy();
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::delay_config_slot().clone(),
            Word::from([
                delayed_execution_policy.min_delay(),
                delayed_execution_policy.propose_expiration_delta() as u32,
                delayed_execution_policy.cancel_threshold(),
                0u32,
            ]),
        ));

        // Tx-proposals map slot.
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::tx_proposals_slot().clone(),
            StorageMap::default(),
        ));

        // Spending-limit slots. They always exist so the auth procedure can read the configuration
        // unconditionally; a zero window length disables the policy.
        let spending = multisig.config.spending_limits_policy();
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::spending_config_slot().clone(),
            spending.map_or_else(Word::empty, SpendingLimitsPolicy::config_word),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::spending_oracle_slot().clone(),
            spending.map_or_else(Word::empty, SpendingLimitsPolicy::oracle_word),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::spending_base_asset_slot().clone(),
            spending.map_or_else(Word::empty, SpendingLimitsPolicy::base_asset_word),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::spending_limit_slot().clone(),
            spending.map_or_else(Word::empty, SpendingLimitsPolicy::limit_word),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::spending_tracker_slot().clone(),
            Word::empty(),
        ));

        let metadata = AuthMultisigSmart::component_metadata();

        AccountComponent::new(AuthMultisigSmart::code().clone(), storage_slots, metadata).expect(
            "multisig smart component should satisfy the requirements of a valid account component",
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_protocol::account::AccountBuilder;
    use miden_protocol::account::auth::AuthSecretKey;

    use super::*;
    use crate::account::wallets::BasicWallet;

    fn default_delayed_execution_policy() -> DelayedExecutionPolicy {
        DelayedExecutionPolicy::new(30, 2, 1).expect("default test policy must be valid")
    }

    #[test]
    fn test_multisig_smart_component_setup() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            Approver::new(sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            Approver::new(sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];
        let num_approvers = approvers.len() as u32;
        let default_threshold = 2u32;
        let receive_asset_immediate_threshold = 1u32;

        let approver_set =
            ApproverSet::new(approvers, default_threshold).expect("invalid approver set");
        let config = AuthMultisigSmartConfig::new(approver_set, default_delayed_execution_policy())
            .with_proc_policies(vec![(
                BasicWallet::receive_asset_root(),
                ProcedurePolicy::with_immediate_threshold(receive_asset_immediate_threshold)
                    .expect("procedure policy should be valid"),
            )])
            .expect("procedure policy config should be valid");

        let component =
            AuthMultisigSmart::new(config).expect("multisig smart component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_component(component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        let threshold_config = account
            .storage()
            .get_item(AuthMultisigSmart::threshold_config_slot())
            .expect("threshold config should be present");
        assert_eq!(threshold_config, Word::from([default_threshold, num_approvers, 0, 0]));

        let receive_asset_policy = account
            .storage()
            .get_map_item(
                AuthMultisigSmart::procedure_policies_slot(),
                StorageMapKey::from_raw(BasicWallet::receive_asset_root().as_word()),
            )
            .expect("receive_asset policy should be present");
        assert_eq!(
            receive_asset_policy,
            Word::from([receive_asset_immediate_threshold, 0u32, 0u32, 0u32])
        );
    }

    #[test]
    fn test_multisig_smart_component_rejects_duplicate_procedure_roots() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            Approver::new(sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            Approver::new(sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let receive_asset_root = BasicWallet::receive_asset_root();
        let policy_one =
            ProcedurePolicy::with_immediate_threshold(1).expect("procedure policy should be valid");
        let policy_two =
            ProcedurePolicy::with_immediate_threshold(2).expect("procedure policy should be valid");

        let approver_set = ApproverSet::new(approvers, 2).expect("invalid approver set");
        let result = AuthMultisigSmartConfig::new(approver_set, default_delayed_execution_policy())
            .with_proc_policies(vec![
                (receive_asset_root, policy_one),
                (receive_asset_root, policy_two),
            ]);

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate procedure roots are not allowed in the procedure policy map")
        );
    }

    #[test]
    fn test_multisig_smart_component_rejects_cancel_threshold_above_num_approvers() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            Approver::new(sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            Approver::new(sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];
        let approver_set = ApproverSet::new(approvers, 2).expect("invalid approver set");
        let policy = DelayedExecutionPolicy::new(30, 2, 3).expect("policy fields are non-zero");

        let err = AuthMultisigSmart::new(AuthMultisigSmartConfig::new(approver_set, policy))
            .expect_err("a cancel threshold above the approver count must be rejected");
        assert!(err.to_string().contains("cancel_threshold cannot exceed number of approvers"));
    }

    #[test]
    fn test_multisig_smart_component_rejects_policies_on_delay_actions() {
        for root in [
            AuthMultisigSmart::propose_transaction_root(),
            AuthMultisigSmart::cancel_transaction_proposal_root(),
        ] {
            let sec_key = AuthSecretKey::new_ecdsa_k256_keccak();
            let approver_set = ApproverSet::new(
                vec![Approver::new(sec_key.public_key().to_commitment(), sec_key.auth_scheme())],
                1,
            )
            .expect("invalid approver set");
            let err =
                AuthMultisigSmartConfig::new(approver_set, default_delayed_execution_policy())
                    .with_proc_policies(vec![(
                        root,
                        ProcedurePolicy::with_immediate_threshold(1)
                            .expect("procedure policy should be valid"),
                    )])
                    .expect_err("a policy on a delay action must be rejected");
            assert!(err.to_string().contains("cannot be set on propose_transaction"));
        }
    }
}
