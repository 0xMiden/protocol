//! Fee policy manager.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::component::{SchemaType, StorageSlotSchema};
use miden_protocol::account::{
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::AssetId;
use miden_protocol::utils::sync::LazyLock;

use super::policies::FeePolicy;

// STORAGE SLOT NAMES
// ================================================================================================

static ACTIVE_FEE_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::network_account::active_fee_policy_proc_root")
        .expect("storage slot name should be valid")
});

static ALLOWED_FEE_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::network_account::allowed_fee_policy_proc_roots")
        .expect("storage slot name should be valid")
});

static FEE_ASSET_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::network_account::fee_asset_id")
        .expect("storage slot name should be valid")
});

// FEE POLICY MANAGER
// ================================================================================================

/// The fee policy configuration of a network account: the policy defining the fee estimation for
/// notes, which policies it may be switched to, and the asset that fees are charged in.
///
/// The actual fee computation logic is defined by a fee policy (e.g.
/// [`BasicConstantFeePolicy`](crate::account::fees::BasicConstantFeePolicy)).
///
/// The [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount) component carries the
/// manager and adds the components of every registered policy when installed, so they do not
/// need to be installed separately. The [`FeePolicyManager`] is not an account component itself and
/// only exists to configure the auth component it is contained in.
///
/// Construct via [`Self::builder`]. The builder requires a fee asset selection and the active fee
/// policy. Additional allowed policies for runtime switching may be registered.
#[derive(Debug, Clone)]
pub struct FeePolicyManager {
    fee_asset_id: Option<AssetId>,
    active_fee_policy_root: AccountProcedureRoot,
    policies: BTreeMap<AccountProcedureRoot, Vec<AccountComponent>>,
}

#[bon::bon]
impl FeePolicyManager {
    /// Builder constructor for [`FeePolicyManager`].
    ///
    /// Select the fee asset with either `fee_faucet_id` or
    /// [`FeePolicyManagerBuilder::account_issued_fee_asset`]. The `active_fee_policy` setter is
    /// also required and registers the policy the manager dispatches to. Each
    /// `allowed_fee_policy` setter registers an additional reserved alternative for runtime
    /// switching via the `set_fee_policy` procedure.
    #[builder]
    pub fn new(
        #[builder(field)] allowed_fee_policies: BTreeMap<AccountProcedureRoot, FeePolicy>,
        #[builder(required, setters(vis = ""))] fee_asset_id: Option<AssetId>,
        active_fee_policy: FeePolicy,
    ) -> Self {
        let active_fee_policy_root = active_fee_policy.root();

        let mut policies: BTreeMap<AccountProcedureRoot, Vec<AccountComponent>> = BTreeMap::new();
        policies.insert(active_fee_policy_root, active_fee_policy.into_iter().collect());
        for (root, policy) in allowed_fee_policies {
            policies.entry(root).or_insert_with(|| policy.into_iter().collect());
        }

        Self {
            fee_asset_id,
            active_fee_policy_root,
            policies,
        }
    }
}

impl<S: fee_policy_manager_builder::State> FeePolicyManagerBuilder<S> {
    /// Registers a reserved fee policy in the `allowed_fee_policy_proc_roots` map. May be
    /// activated at runtime via `set_fee_policy`. Allowed entries are deduplicated by procedure
    /// root.
    pub fn allowed_fee_policy(mut self, policy: FeePolicy) -> Self {
        self.allowed_fee_policies.insert(policy.root(), policy);
        self
    }
}

impl<S: fee_policy_manager_builder::State> FeePolicyManagerBuilder<S>
where
    S::FeeAssetId: fee_policy_manager_builder::IsUnset,
{
    /// Configures fees in the fungible asset issued by `fee_faucet_id`.
    pub fn fee_faucet_id(
        self,
        fee_faucet_id: AccountId,
    ) -> FeePolicyManagerBuilder<fee_policy_manager_builder::SetFeeAssetId<S>> {
        self.fee_asset_id(Some(AssetId::new_fungible(fee_faucet_id)))
    }

    /// Configures fees in the fungible asset issued by the account carrying this manager.
    pub fn account_issued_fee_asset(
        self,
    ) -> FeePolicyManagerBuilder<fee_policy_manager_builder::SetFeeAssetId<S>> {
        self.fee_asset_id(None)
    }
}

impl FeePolicyManager {
    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the explicit [`AssetId`] fees are charged in, or `None` when the asset is issued by
    /// the account carrying the manager.
    pub fn fee_asset_id(&self) -> Option<AssetId> {
        self.fee_asset_id
    }

    /// Returns the active fee policy procedure root.
    pub fn active_fee_policy(&self) -> AccountProcedureRoot {
        self.active_fee_policy_root
    }

    /// Returns all allowed fee policy procedure roots (active + reserved).
    pub fn allowed_fee_policies(&self) -> Vec<AccountProcedureRoot> {
        self.policies.keys().copied().collect()
    }

    /// Yields the [`AccountComponent`]s contributed by every registered fee policy.
    pub fn into_fee_policy_components(self) -> impl Iterator<Item = AccountComponent> {
        self.policies.into_values().flat_map(|components| components.into_iter())
    }

    // STORAGE
    // --------------------------------------------------------------------------------------------

    /// Returns the storage slot holding the active fee policy procedure root.
    pub fn active_fee_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_FEE_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the storage slot holding the map of allowed fee policy procedure roots.
    pub fn allowed_fee_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_FEE_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the storage slot holding the explicit fee asset ID or the account issued marker.
    pub fn fee_asset_id_slot() -> &'static StorageSlotName {
        &FEE_ASSET_ID_SLOT_NAME
    }

    /// Returns the schema entries for the three fee-policy storage slots.
    ///
    /// These slots are installed by the owning
    /// [`AuthNetworkAccount`][crate::account::auth::AuthNetworkAccount] component, whose storage
    /// schema includes them.
    pub(crate) fn slot_schemas() -> [(StorageSlotName, StorageSlotSchema); 3] {
        [
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
            (
                FEE_ASSET_ID_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Explicit fee asset ID, or an empty word for the account issued asset",
                    SchemaType::native_word(),
                ),
            ),
        ]
    }

    /// Builds the three fee-policy storage slots from this manager's configuration:
    /// - the active-policy value.
    /// - the allowed-policies map.
    /// - fee-asset value slot.
    ///
    /// Exposed so tests and tooling can reproduce the fee-policy storage without building the full
    /// auth component.
    pub fn to_storage_slots(&self) -> [StorageSlot; 3] {
        let allowed_flag = Word::from([1u32, 0, 0, 0]);
        let allowed_entries: Vec<_> = self
            .allowed_fee_policies()
            .into_iter()
            .map(|root| (StorageMapKey::new(root.as_word()), allowed_flag))
            .collect();
        let allowed_map = StorageMap::with_entries(allowed_entries)
            .expect("allowed policy roots should have unique keys");

        [
            StorageSlot::with_value(
                ACTIVE_FEE_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_fee_policy().as_word(),
            ),
            StorageSlot::with_map(ALLOWED_FEE_POLICY_PROC_ROOTS_SLOT_NAME.clone(), allowed_map),
            StorageSlot::with_value(
                FEE_ASSET_ID_SLOT_NAME.clone(),
                self.fee_asset_id.map_or_else(Word::empty, |asset_id| asset_id.to_word()),
            ),
        ]
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountId;
    use miden_protocol::account::component::AccountComponentMetadata;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    use super::*;
    use crate::account::auth::AuthNetworkAccount;
    use crate::account::fees::BasicConstantFeePolicy;
    use crate::code_builder::CodeBuilder;

    fn fee_faucet_id() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing account ID should be valid")
    }

    /// Builds a minimal user-defined fee policy, mirroring how a contract developer registers a
    /// reserved policy for runtime switching.
    fn custom_fee_policy() -> FeePolicy {
        const NAME: &str = "test::fees::custom_policy";
        let masm_source = "
            @account_procedure
            pub proc compute_note_fee
                dropw dropw dropw dropw
            end
        ";
        let code = CodeBuilder::default()
            .compile_component_code(NAME, masm_source)
            .expect("custom fee policy should compile");
        let root = code
            .get_procedure_root_by_path(format!("{NAME}::compute_note_fee").as_str())
            .expect("custom fee policy should export compute_note_fee");
        let component = AccountComponent::new(code, vec![], AccountComponentMetadata::mock(NAME))
            .expect("custom fee policy component should be valid");
        FeePolicy::custom(root, [component])
            .expect("custom fee policy root should be in the component")
    }

    /// The manager is not a component itself: it expands into the components of the registered
    /// policies only, each of which exports its policy root, and none of which exports a
    /// fee-policy procedure - those belong to `AuthNetworkAccount`.
    #[test]
    fn manager_expands_into_policy_components_only() {
        let fee_policy_manager = FeePolicyManager::builder()
            .fee_faucet_id(fee_faucet_id())
            .active_fee_policy(BasicConstantFeePolicy::new().into())
            .allowed_fee_policy(custom_fee_policy())
            .build();

        let allowed_roots = fee_policy_manager.allowed_fee_policies();
        let components: Vec<AccountComponent> =
            fee_policy_manager.into_fee_policy_components().collect();

        for root in allowed_roots {
            assert!(
                components.iter().any(|component| component.has_procedure(root)),
                "every registered policy root should be exported by a yielded component"
            );
        }
        assert!(
            !components
                .iter()
                .any(|component| component.has_procedure(AuthNetworkAccount::get_fee_policy_root())),
            "the fee-policy procedures are exported by the auth component, not by the manager"
        );
    }

    /// Explicit fee assets retain their asset ID encoding, while the account issued mode stores an
    /// empty marker so account construction does not depend on the ID being derived.
    #[test]
    fn fee_asset_storage_encoding_distinguishes_both_modes() {
        let explicit_manager = FeePolicyManager::builder()
            .fee_faucet_id(fee_faucet_id())
            .active_fee_policy(BasicConstantFeePolicy::new().into())
            .build();
        let account_issued_manager = FeePolicyManager::builder()
            .account_issued_fee_asset()
            .active_fee_policy(BasicConstantFeePolicy::new().into())
            .build();

        let expected_asset_id = AssetId::new_fungible(fee_faucet_id());
        assert_eq!(explicit_manager.fee_asset_id(), Some(expected_asset_id));
        assert_eq!(explicit_manager.to_storage_slots()[2].value(), expected_asset_id.to_word());

        assert_eq!(account_issued_manager.fee_asset_id(), None);
        assert_eq!(account_issued_manager.to_storage_slots()[2].value(), Word::empty());
    }
}
