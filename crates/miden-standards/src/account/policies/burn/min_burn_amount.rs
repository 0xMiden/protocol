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
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::account_component_code;
use crate::procedure_root;

// MIN-BURN-AMOUNT BURN POLICY
// ================================================================================================

account_component_code!(
    MIN_BURN_AMOUNT_BURN_POLICY_CODE,
    "faucets/policies/burn/min_burn_amount.masl"
);

procedure_root!(
    MIN_BURN_AMOUNT_POLICY_ROOT,
    MinBurnAmount::NAME,
    MinBurnAmount::PROC_NAME,
    MinBurnAmount::code()
);

procedure_root!(
    MIN_BURN_AMOUNT_SET_ROOT,
    MinBurnAmount::NAME,
    MinBurnAmount::SET_PROC_NAME,
    MinBurnAmount::code()
);

procedure_root!(
    MIN_BURN_AMOUNT_GET_ROOT,
    MinBurnAmount::NAME,
    MinBurnAmount::GET_PROC_NAME,
    MinBurnAmount::code()
);

static MIN_BURN_AMOUNT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::burn::min_burn_amount::min_burn_amount",
    )
    .expect("storage slot name should be valid")
});

/// The `min_burn_amount` burn policy account component.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed burn-policies map
/// includes [`MinBurnAmount::root`]. When active, a burn is rejected unless its amount meets or
/// exceeds the configured minimum burn amount, which is stored in this component's value slot
/// ([`MinBurnAmount::slot_name`]) and can be updated through the authority-gated
/// `set_min_burn_amount` procedure (authorized via the account-wide
/// [`Authority`][crate::account::access::Authority] component).
#[derive(Debug, Clone, Copy)]
pub struct MinBurnAmount {
    min_burn_amount: AssetAmount,
}

impl MinBurnAmount {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::burn::min_burn_amount";

    pub(crate) const PROC_NAME: &str = "check_policy";
    const SET_PROC_NAME: &str = "set_min_burn_amount";
    const GET_PROC_NAME: &str = "get_min_burn_amount";

    /// Creates a new `min_burn_amount` burn policy with the given initial minimum burn amount.
    pub fn new(min_burn_amount: AssetAmount) -> Self {
        Self { min_burn_amount }
    }

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &MIN_BURN_AMOUNT_BURN_POLICY_CODE
    }

    /// Returns the procedure root of the `check_policy` burn policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *MIN_BURN_AMOUNT_POLICY_ROOT
    }

    /// Returns the procedure root of the `set_min_burn_amount` account procedure.
    pub fn set_min_burn_amount_root() -> AccountProcedureRoot {
        *MIN_BURN_AMOUNT_SET_ROOT
    }

    /// Returns the procedure root of the `get_min_burn_amount` account procedure.
    pub fn get_min_burn_amount_root() -> AccountProcedureRoot {
        *MIN_BURN_AMOUNT_GET_ROOT
    }

    /// Returns the [`StorageSlotName`] where the minimum burn amount is stored.
    pub fn slot_name() -> &'static StorageSlotName {
        &MIN_BURN_AMOUNT_SLOT_NAME
    }

    /// Returns the configured minimum burn amount.
    pub fn min_burn_amount(&self) -> AssetAmount {
        self.min_burn_amount
    }

    /// Returns the storage slot schema for the minimum burn amount slot.
    pub fn slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::slot_name().clone(),
            StorageSlotSchema::value("Minimum burn amount", SchemaType::native_word()),
        )
    }

    /// Converts the configured minimum burn amount into its storage value word
    /// `[min_burn_amount, 0, 0, 0]`.
    fn to_word(self) -> Word {
        Word::from([Felt::from(self.min_burn_amount), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    /// Converts the configured minimum burn amount into a [`StorageSlot`].
    fn to_storage_slot(self) -> StorageSlot {
        StorageSlot::with_value(Self::slot_name().clone(), self.to_word())
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema =
            StorageSchema::new([Self::slot_schema()]).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("`min_burn_amount` burn policy for fungible faucets")
            .with_storage_schema(storage_schema)
    }
}

impl From<MinBurnAmount> for AccountComponent {
    fn from(policy: MinBurnAmount) -> Self {
        let storage_slot = policy.to_storage_slot();

        AccountComponent::new(
            MinBurnAmount::code().clone(),
            vec![storage_slot],
            MinBurnAmount::component_metadata(),
        )
        .expect(
            "`min_burn_amount` burn policy component should satisfy the requirements of a valid account component",
        )
    }
}
