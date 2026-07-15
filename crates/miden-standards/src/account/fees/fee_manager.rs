//! Fee manager.
//!
//! [`FeeManager`] mirrors the token policy managers: it owns an `active_fee_policy_proc_root`
//! slot plus an `allowed_fee_policy_proc_roots` map slot for validating policy-switching at set
//! time, and its `estimate_note_fee` procedure dispatches to the active fee policy via `dynexec`.
//! The actual fee computation logic lives in fee policy components (see
//! [`super::policies`]).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountComponentName,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;

use super::policies::FeePolicy;
use crate::account::account_component_code;
use crate::procedure_root;

account_component_code!(FEE_MANAGER_CODE, "miden-standards-fees-fee-manager.masp");

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`FeeManager::NAME`],
/// which mirrors the standards-side MASM module path.
const FEE_MANAGER_LIBRARY_PATH: &str = "miden::standards::components::fees::fee_manager";

procedure_root!(
    FEE_MANAGER_ESTIMATE_NOTE_FEE,
    FEE_MANAGER_LIBRARY_PATH,
    FeeManager::ESTIMATE_NOTE_FEE_PROC_NAME,
    FeeManager::code()
);

procedure_root!(
    FEE_MANAGER_SET_FEE_POLICY,
    FEE_MANAGER_LIBRARY_PATH,
    FeeManager::SET_FEE_POLICY_PROC_NAME,
    FeeManager::code()
);

procedure_root!(
    FEE_MANAGER_GET_FEE_POLICY,
    FEE_MANAGER_LIBRARY_PATH,
    FeeManager::GET_FEE_POLICY_PROC_NAME,
    FeeManager::code()
);

// STORAGE SLOT NAMES
// ================================================================================================

static ACTIVE_FEE_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::fee_manager::active_fee_policy_proc_root")
        .expect("storage slot name should be valid")
});

static ALLOWED_FEE_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::fee_manager::allowed_fee_policy_proc_roots")
        .expect("storage slot name should be valid")
});

// FEE MANAGER
// ================================================================================================

/// An [`AccountComponent`] that owns the fee-policy storage slots and dispatches note fee
/// estimation to the active fee policy.
///
/// The component exposes:
/// - `estimate_note_fee`: designed to be `call`ed by external callers - typically via FPI from the
///   authentication component of an account that creates a note targeted at this account. It
///   dispatches to the active fee policy via `dynexec`; the policy derives the fee this account
///   charges for a note with the given parameters and returns it as a fee asset (asset ID and value
///   words).
/// - `set_fee_policy` / `get_fee_policy`: switch and read the active fee policy root. Switching is
///   restricted to the roots registered in the allowed-policies map, and authorization is delegated
///   to the account-wide [`Authority`][crate::account::access::Authority] component, which must be
///   installed alongside this manager.
///
/// Construct via [`Self::builder`]. The builder requires the active fee policy
/// ([`FeeManagerBuilder::active_fee_policy`]); additional reserved alternatives for runtime
/// switching may be registered via [`FeeManagerBuilder::allowed_fee_policy`].
///
/// ## Storage layout
///
/// - [`Self::active_fee_policy_slot`]: procedure root of the active fee policy.
/// - [`Self::allowed_fee_policies_slot`]: map of allowed fee policy roots.
#[derive(Debug, Clone)]
pub struct FeeManager {
    active_fee_policy_root: AccountProcedureRoot,
    policies: BTreeMap<AccountProcedureRoot, Vec<AccountComponent>>,
}

#[bon::bon]
impl FeeManager {
    /// Builder constructor for [`FeeManager`].
    ///
    /// The `active_fee_policy` setter is required and registers the policy the manager
    /// dispatches to. Each `allowed_fee_policy` setter registers an additional reserved
    /// alternative for runtime switching via the `set_fee_policy` procedure.
    #[builder]
    pub fn new(
        #[builder(field)] allowed_fee_policies: BTreeMap<AccountProcedureRoot, FeePolicy>,
        active_fee_policy: FeePolicy,
    ) -> Self {
        let active_fee_policy_root = active_fee_policy.root();

        let mut policies: BTreeMap<AccountProcedureRoot, Vec<AccountComponent>> = BTreeMap::new();
        policies.insert(active_fee_policy_root, active_fee_policy.into_iter().collect());
        for (root, policy) in allowed_fee_policies {
            policies.entry(root).or_insert_with(|| policy.into_iter().collect());
        }

        Self { active_fee_policy_root, policies }
    }
}

impl<S: fee_manager_builder::State> FeeManagerBuilder<S> {
    /// Registers a reserved fee policy in the `allowed_fee_policy_proc_roots` map. May be
    /// activated at runtime via `set_fee_policy`. Allowed entries are deduplicated by procedure
    /// root.
    pub fn allowed_fee_policy(mut self, policy: FeePolicy) -> Self {
        self.allowed_fee_policies.insert(policy.root(), policy);
        self
    }
}

impl FeeManager {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component (used in metadata).
    pub const NAME: &'static str = "miden::standards::fees::fee_manager";

    /// Component description used in [`AccountComponentMetadata`].
    pub const DESCRIPTION: &'static str =
        "Fee manager dispatching note fee estimation to a configurable fee policy";

    const ESTIMATE_NOTE_FEE_PROC_NAME: &'static str = "estimate_note_fee";
    const SET_FEE_POLICY_PROC_NAME: &'static str = "set_fee_policy";
    const GET_FEE_POLICY_PROC_NAME: &'static str = "get_fee_policy";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the active fee policy procedure root.
    pub fn active_fee_policy(&self) -> AccountProcedureRoot {
        self.active_fee_policy_root
    }

    /// Returns all allowed fee policy procedure roots (active + reserved).
    pub fn allowed_fee_policies(&self) -> Vec<AccountProcedureRoot> {
        self.policies.keys().copied().collect()
    }

    /// Returns the procedure root of the `estimate_note_fee` account procedure.
    pub fn estimate_note_fee_root() -> AccountProcedureRoot {
        *FEE_MANAGER_ESTIMATE_NOTE_FEE
    }

    /// Returns the procedure root of the `set_fee_policy` account procedure.
    pub fn set_fee_policy_root() -> AccountProcedureRoot {
        *FEE_MANAGER_SET_FEE_POLICY
    }

    /// Returns the procedure root of the `get_fee_policy` account procedure.
    pub fn get_fee_policy_root() -> AccountProcedureRoot {
        *FEE_MANAGER_GET_FEE_POLICY
    }

    /// Returns the [`StorageSlotName`] where the active fee policy procedure root is stored.
    pub fn active_fee_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_FEE_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed fee policy roots are stored.
    pub fn allowed_fee_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_FEE_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &FEE_MANAGER_CODE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            (
                ACTIVE_FEE_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Active fee policy procedure root",
                    SchemaType::native_word(),
                ),
            ),
            (
                ALLOWED_FEE_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Allowed fee policy procedure roots",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(Self::DESCRIPTION)
            .with_storage_schema(storage_schema)
    }

    fn manager_storage_slots(&self) -> Vec<StorageSlot> {
        vec![
            StorageSlot::with_value(
                ACTIVE_FEE_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_fee_policy_root.as_word(),
            ),
            StorageSlot::with_map(
                ALLOWED_FEE_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                self.build_allowed_map(),
            ),
        ]
    }

    /// Builds the `allowed_fee_policy_proc_roots` storage map from the registered policies
    /// (active + reserved). Each entry maps the policy procedure root to a non-zero flag, so
    /// runtime `set_fee_policy` validation can confirm the root is allowed before activating it.
    fn build_allowed_map(&self) -> StorageMap {
        let allowed_flag = Word::from([1u32, 0, 0, 0]);
        let entries: Vec<_> = self
            .policies
            .keys()
            .map(|root| (StorageMapKey::new(root.as_word()), allowed_flag))
            .collect();
        StorageMap::with_entries(entries).expect("allowed policy roots should have unique keys")
    }

    fn to_manager_component(&self) -> AccountComponent {
        AccountComponent::new(
            Self::code().clone(),
            self.manager_storage_slots(),
            Self::component_metadata(),
        )
        .expect(
            "fee manager component should satisfy the requirements of a valid account component",
        )
    }
}

impl IntoIterator for FeeManager {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this fee policy configuration: the manager
    /// itself first, then the companion components contributed by every registered policy.
    /// Deduplication by procedure root is implicit (the manager's internal `policies` map is
    /// keyed by root).
    fn into_iter(self) -> Self::IntoIter {
        let manager_component = self.to_manager_component();
        let mut components = vec![manager_component];
        for (_, policy_components) in self.policies {
            components.extend(policy_components);
        }
        components.into_iter()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountBuilder, AccountId, AccountType, StorageSlotContent};
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    use super::*;
    use crate::account::auth::NoAuth;
    use crate::account::fees::{ConstantFeePolicy, ZeroFeePolicy};

    fn fee_faucet_id() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing account ID should be valid")
    }

    fn fee_manager() -> FeeManager {
        FeeManager::builder()
            .active_fee_policy(FeePolicy::constant(ConstantFeePolicy::new(fee_faucet_id())))
            .allowed_fee_policy(FeePolicy::zero())
            .build()
    }

    /// Check that the manager component's slots hold the active policy root and register both
    /// the active and the reserved policy roots in the allowed-policies map.
    #[test]
    fn manager_slots_hold_active_root_and_allowed_map() {
        let manager_component = fee_manager().to_manager_component();

        let active_slot = manager_component
            .storage_slots()
            .iter()
            .find(|slot| slot.name() == FeeManager::active_fee_policy_slot())
            .expect("active fee policy slot must be registered");
        assert_eq!(active_slot.value(), ConstantFeePolicy::root().as_word());

        let allowed_slot = manager_component
            .storage_slots()
            .iter()
            .find(|slot| slot.name() == FeeManager::allowed_fee_policies_slot())
            .expect("allowed fee policies slot must be registered");
        let StorageSlotContent::Map(map) = allowed_slot.content() else {
            panic!("allowed fee policies slot must be a map");
        };
        let allowed_flag = Word::from([1u32, 0, 0, 0]);
        assert_eq!(
            map.get(&StorageMapKey::new(ConstantFeePolicy::root().as_word())),
            allowed_flag,
            "the active policy root should be registered in the allowed map"
        );
        assert_eq!(
            map.get(&StorageMapKey::new(ZeroFeePolicy::root().as_word())),
            allowed_flag,
            "the reserved policy root should be registered in the allowed map"
        );
    }

    /// Check that the manager and its policies can be added to an account and that the resulting
    /// account exposes the manager procedures and the policies' `compute_note_fee` procedures.
    #[test]
    fn account_exposes_fee_manager_procedures() -> anyhow::Result<()> {
        let account = AccountBuilder::new([1; 32])
            .account_type(AccountType::Public)
            .with_auth_component(NoAuth)
            .with_components(fee_manager())
            .build_existing()?;

        for root in [
            FeeManager::estimate_note_fee_root(),
            FeeManager::set_fee_policy_root(),
            FeeManager::get_fee_policy_root(),
            ConstantFeePolicy::root(),
            ZeroFeePolicy::root(),
        ] {
            assert!(account.code().has_procedure(*root.mast_root()));
        }

        Ok(())
    }
}
