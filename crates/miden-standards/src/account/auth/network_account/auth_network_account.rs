use alloc::collections::BTreeSet;
use alloc::vec;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountComponentName,
    AccountProcedureRoot,
    StorageSlotName,
};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::TransactionScriptRoot;

use super::{
    NetworkAccountNoteAllowlist,
    NetworkAccountNoteAllowlistError,
    NetworkAccountTxScriptAllowlist,
    SponsorshipPolicy,
};
use crate::account::account_component_code;
use crate::account::fees::FeePolicyManager;
use crate::note::FeeSponsorshipNote;
use crate::note::config::NetworkAccountConfigNote;
use crate::procedure_root;
use crate::tx_script::ExpirationTransactionScript;

account_component_code!(NETWORK_ACCOUNT_AUTH_CODE, "miden-standards-auth-network-account.masp");

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`AuthNetworkAccount::NAME`], which mirrors the standards-side MASM module path.
const NETWORK_ACCOUNT_AUTH_LIBRARY_PATH: &str =
    "miden::standards::components::auth::network_account";

procedure_root!(
    NETWORK_ACCOUNT_ADD_ALLOWED_NOTE_SCRIPT,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::ADD_ALLOWED_NOTE_SCRIPT_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_REMOVE_ALLOWED_NOTE_SCRIPT,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::REMOVE_ALLOWED_NOTE_SCRIPT_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_ADD_ALLOWED_TX_SCRIPT,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::ADD_ALLOWED_TX_SCRIPT_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_REMOVE_ALLOWED_TX_SCRIPT,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::REMOVE_ALLOWED_TX_SCRIPT_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_ESTIMATE_NOTE_FEE,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::ESTIMATE_NOTE_FEE_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_SET_FEE_POLICY,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::SET_FEE_POLICY_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_GET_FEE_POLICY,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::GET_FEE_POLICY_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_GET_FEE_ASSET_ID,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::GET_FEE_ASSET_ID_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    FEE_MANAGER_ADD_ALLOWED_FEE_POLICY,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::ADD_ALLOWED_FEE_POLICY_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    FEE_MANAGER_REMOVE_ALLOWED_FEE_POLICY,
    NETWORK_ACCOUNT_AUTH_LIBRARY_PATH,
    AuthNetworkAccount::REMOVE_ALLOWED_FEE_POLICY_PROC_NAME,
    AuthNetworkAccount::code()
);

// AUTH NETWORK ACCOUNT
// ================================================================================================

/// An [`AccountComponent`] implementing an authentication scheme that restricts what notes an
/// account can consume to a fixed allowlist of note script roots, and what transaction scripts may
/// run against the account to a fixed allowlist of tx script roots.
///
/// This is intended for network-owned accounts (e.g. the AggLayer bridge or a network faucet)
/// whose only legitimate inputs are a known, finite set of system-issued notes and scripts.
///
/// The component exports a single auth procedure, `auth_network_transaction`, that rejects the
/// transaction unless all three of the following are true:
/// - the transaction script root, if any, is present in the component's tx-script allowlist
/// - every consumed input note has a script root present in the component's note-script allowlist
/// - before fee collection and payment, it has consumed at least one input note, created at least
///   one output note, or changed the account state.
///
/// If these checks pass, the procedure pays the transaction fee by creating a public TX_FEE
/// note funded from the account's vault in the native fee asset at rate 1/1 (see
/// `miden::standards::fee::pay_fee` and `miden::standards::fee::native_conversion_info`). On
/// chains with a zero verification base fee no note is created.
///
/// Because a network account has no signature gate by default, a transaction script is an
/// unconstrained code path that could call the account's procedures directly. The tx-script
/// allowlist constrains this to a fixed set of owner-approved scripts; an empty tx-script allowlist
/// permits no transaction scripts at all.
///
/// IMPORTANT: an allowlisted root pins a script's *code* (its MAST root), not the inputs it runs
/// on. A tx script still receives caller-controlled `TX_SCRIPT_ARGS` and advice-provider inputs,
/// and a note script receives caller-controlled `NOTE_ARGS`; on an open network account anyone can
/// supply those. A root should therefore only be allowlisted when the script's effect is safe for
/// *every* possible input. The canonical example is a tx script that sets the transaction
/// expiration delta to a hardcoded constant: its effect is fixed regardless of caller or inputs,
/// and the kernel only ever lets a script tighten the current transaction's expiration window
/// (never extend it), so the worst a caller can do is make their own transaction expire sooner.
/// Allowlisting a script whose effect depends on its inputs re-opens the very code path the
/// allowlist exists to constrain.
///
/// The note allowlist is stored in the standardized [`NetworkAccountNoteAllowlist`] slot so
/// off-chain services can identify a network account by checking for this slot.
///
/// Both allowlists can be updated after deployment via the `add_allowed_note_script` /
/// `remove_allowed_note_script` and `add_allowed_tx_script` / `remove_allowed_tx_script` account
/// procedures. These are gated by the account-wide
/// [`Authority`](crate::account::access::Authority) component, which must be composed onto the
/// account in [`OwnerControlled`](crate::account::access::Authority::OwnerControlled) or
/// [`RbacControlled`](crate::account::access::Authority::RbacControlled) mode.
/// [`AuthControlled`](crate::account::access::Authority::AuthControlled) mode is unsafe here
/// because this component's auth scheme is intentionally permissionless, so authorization to mutate
/// the allowlists must come from an owner or a role rather than from the auth scheme itself.
///
/// An update is driven by a note the authorized party sends to the account. That admin note's own
/// script root must already be in the note-script allowlist so the transaction passes auth. The
/// auth procedure reads the allowlists from the transaction's initial state, so an update only
/// takes effect from the next transaction.
///
/// # Fee policy
///
/// This component owns the fee-policy related storage slots and procedures. It carries the
/// [`FeePolicyManager`] it was constructed with, which configures those slots, and, when expanded
/// into [`AccountComponent`]s, yields the components of the manager's registered fee policies right
/// after itself. The auth procedure also collects fees from `FEE_SPONSORSHIP` input notes,
/// denominated in the configured fee asset.
///
/// Because every network transaction pays a fee, the fee policy is not optional: the component is
/// constructed from a [`FeePolicyManager`], which initializes the slots from the manager's active
/// policy, allowed policies and fee asset.
///
/// # Sponsorship policy
///
/// Paying the fee also sponsors every network output note the transaction creates, out of this
/// account's vault. The component's [`SponsorshipPolicy`] decides whether that spending is bounded
/// by what the account collected in the same transaction. It defaults to
/// [`SponsorshipPolicy::AtMostCollectedFees`], so an account only forwards value it collected.
/// Accounts that are meant to subsidise their own outgoing notes opt into
/// [`SponsorshipPolicy::Unlimited`].
pub struct AuthNetworkAccount {
    allowed_notes: NetworkAccountNoteAllowlist,
    allowed_tx_scripts: NetworkAccountTxScriptAllowlist,
    sponsorship_policy: SponsorshipPolicy,
    policy_manager: FeePolicyManager,
}

impl AuthNetworkAccount {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::network_account";

    const ADD_ALLOWED_NOTE_SCRIPT_PROC_NAME: &'static str = "add_allowed_note_script";
    const REMOVE_ALLOWED_NOTE_SCRIPT_PROC_NAME: &'static str = "remove_allowed_note_script";
    const ADD_ALLOWED_TX_SCRIPT_PROC_NAME: &'static str = "add_allowed_tx_script";
    const REMOVE_ALLOWED_TX_SCRIPT_PROC_NAME: &'static str = "remove_allowed_tx_script";
    const ESTIMATE_NOTE_FEE_PROC_NAME: &'static str = "estimate_note_fee";
    const SET_FEE_POLICY_PROC_NAME: &'static str = "set_fee_policy";
    const GET_FEE_POLICY_PROC_NAME: &'static str = "get_fee_policy";
    const GET_FEE_ASSET_ID_PROC_NAME: &'static str = "get_fee_asset_id";
    const ADD_ALLOWED_FEE_POLICY_PROC_NAME: &'static str = "add_allowed_fee_policy";
    const REMOVE_ALLOWED_FEE_POLICY_PROC_NAME: &'static str = "remove_allowed_fee_policy";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AuthNetworkAccount`] component configured with the standard network-account
    /// defaults on top of the provided input-note script roots, paying fees per the given
    /// [`FeePolicyManager`].
    ///
    /// On top of `allowed_notes`, the following default configuration is always applied (use
    /// [`custom`](Self::custom) for a variant that applies none of it):
    /// - The standardized [`NetworkAccountConfigNote`] script root is added to the note allowlist,
    ///   so the account's allowlists can be updated after deployment by sending that note.
    /// - The [`FeeSponsorshipNote`] script root is added to the note allowlist. A network account
    ///   collects prepaid fees by consuming these notes, so without it, fees could not be
    ///   collected. Allowlisting it is safe: the note's own script refuses consumption without the
    ///   note it sponsors, and fee collection asserts every consumed note's fee is covered by the
    ///   sponsorships bound to it.
    /// - The tx-script allowlist contains the [`ExpirationTransactionScript`] root, which the
    ///   network transaction builder attaches to every network transaction, so the account is
    ///   serviceable by the network.
    ///
    /// The active policy, allowed policies and fee asset of `fee_policy_manager` initialize the
    /// three fee-policy storage slots this component owns. The manager is carried by the component
    /// and the components of its registered policies are emitted alongside it when the component is
    /// expanded (see the [`IntoIterator`] impl), so the caller does not install them separately.
    pub fn new(
        mut allowed_notes: BTreeSet<NoteScriptRoot>,
        fee_policy_manager: FeePolicyManager,
    ) -> Result<Self, NetworkAccountNoteAllowlistError> {
        allowed_notes.extend(Self::default_allowed_note_scripts());
        Ok(Self::custom(allowed_notes, fee_policy_manager)?
            .with_allowed_tx_scripts([ExpirationTransactionScript::script_root()]))
    }

    /// Returns the note script roots added to every standard network account's allowlist.
    pub fn default_allowed_note_scripts() -> [NoteScriptRoot; 2] {
        [NetworkAccountConfigNote::script_root(), FeeSponsorshipNote::script_root()]
    }

    /// Creates a raw [`AuthNetworkAccount`] component from the given note-script allowlist, with an
    /// empty tx-script allowlist and without any default configuration.
    ///
    /// Most callers should use [`Self::new`] to include the defaults.
    pub fn custom(
        allowed_notes: BTreeSet<NoteScriptRoot>,
        fee_policy_manager: FeePolicyManager,
    ) -> Result<Self, NetworkAccountNoteAllowlistError> {
        Ok(Self {
            allowed_notes: NetworkAccountNoteAllowlist::new(allowed_notes)?,
            allowed_tx_scripts: NetworkAccountTxScriptAllowlist::default(),
            sponsorship_policy: SponsorshipPolicy::default(),
            policy_manager: fee_policy_manager,
        })
    }

    /// Sets the [`SponsorshipPolicy`] bounding how much the account spends sponsoring the network
    /// notes it creates.
    pub fn with_sponsorship_policy(mut self, sponsorship_policy: SponsorshipPolicy) -> Self {
        self.sponsorship_policy = sponsorship_policy;
        self
    }

    /// Extends the tx-script allowlist with the given transaction script roots, keeping any that
    /// are already allowlisted.
    ///
    /// Only tx scripts whose effect is safe for every possible input should be allowlisted: a root
    /// pins the script's code but not its `TX_SCRIPT_ARGS` or advice inputs, which the (arbitrary)
    /// transaction submitter controls. See the [`AuthNetworkAccount`] type docs for the full
    /// rationale.
    pub fn with_allowed_tx_scripts(
        mut self,
        allowed_tx_script_roots: impl IntoIterator<Item = TransactionScriptRoot>,
    ) -> Self {
        self.allowed_tx_scripts.extend_script_roots(allowed_tx_script_roots);
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &NETWORK_ACCOUNT_AUTH_CODE
    }

    /// Returns the [`NetworkAccountNoteAllowlist`] of this component.
    pub fn allowed_notes(&self) -> &NetworkAccountNoteAllowlist {
        &self.allowed_notes
    }

    /// Returns the [`NetworkAccountTxScriptAllowlist`] of this component.
    pub fn allowed_tx_scripts(&self) -> &NetworkAccountTxScriptAllowlist {
        &self.allowed_tx_scripts
    }

    /// Returns the [`SponsorshipPolicy`] of this component.
    pub fn sponsorship_policy(&self) -> SponsorshipPolicy {
        self.sponsorship_policy
    }

    /// Returns the procedure root of the `add_allowed_note_script` procedure exposed by this
    /// component.
    pub fn add_allowed_note_script_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_ADD_ALLOWED_NOTE_SCRIPT
    }

    /// Returns the procedure root of the `remove_allowed_note_script` procedure exposed by this
    /// component.
    pub fn remove_allowed_note_script_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_REMOVE_ALLOWED_NOTE_SCRIPT
    }

    /// Returns the procedure root of the `add_allowed_tx_script` procedure exposed by this
    /// component.
    pub fn add_allowed_tx_script_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_ADD_ALLOWED_TX_SCRIPT
    }

    /// Returns the procedure root of the `remove_allowed_tx_script` procedure exposed by this
    /// component.
    pub fn remove_allowed_tx_script_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_REMOVE_ALLOWED_TX_SCRIPT
    }

    /// Returns the procedure root of the `estimate_note_fee` procedure exposed by this component.
    pub fn estimate_note_fee_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_ESTIMATE_NOTE_FEE
    }

    /// Returns the procedure root of the `set_fee_policy` procedure exposed by this component.
    pub fn set_fee_policy_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_SET_FEE_POLICY
    }

    /// Returns the procedure root of the `get_fee_policy` procedure exposed by this component.
    pub fn get_fee_policy_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_GET_FEE_POLICY
    }

    /// Returns the procedure root of the `get_fee_asset_id` procedure exposed by this component.
    pub fn get_fee_asset_id_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_GET_FEE_ASSET_ID
    }

    /// Returns the procedure root of the `add_allowed_fee_policy` account procedure.
    pub fn add_allowed_fee_policy_root() -> AccountProcedureRoot {
        *FEE_MANAGER_ADD_ALLOWED_FEE_POLICY
    }

    /// Returns the procedure root of the `remove_allowed_fee_policy` account procedure.
    pub fn remove_allowed_fee_policy_root() -> AccountProcedureRoot {
        *FEE_MANAGER_REMOVE_ALLOWED_FEE_POLICY
    }

    /// Returns the storage slot holding the allowlist of allowed input-note script roots.
    pub fn allowed_note_scripts_slot() -> &'static StorageSlotName {
        NetworkAccountNoteAllowlist::slot_name()
    }

    /// Returns the storage slot schema for the note-script allowlist slot.
    pub fn allowed_note_scripts_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        NetworkAccountNoteAllowlist::slot_schema()
    }

    /// Returns the storage slot holding the allowlist of allowed transaction script roots.
    pub fn allowed_tx_scripts_slot() -> &'static StorageSlotName {
        NetworkAccountTxScriptAllowlist::slot_name()
    }

    /// Returns the storage slot schema for the tx-script allowlist slot.
    pub fn allowed_tx_scripts_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        NetworkAccountTxScriptAllowlist::slot_schema()
    }

    /// Returns the storage slot holding the sponsorship policy.
    pub fn sponsorship_policy_slot() -> &'static StorageSlotName {
        SponsorshipPolicy::slot_name()
    }

    /// Returns the storage slot schema for the sponsorship policy slot.
    pub fn sponsorship_policy_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        SponsorshipPolicy::slot_schema()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let mut slot_schemas = vec![
            NetworkAccountNoteAllowlist::slot_schema(),
            NetworkAccountTxScriptAllowlist::slot_schema(),
            SponsorshipPolicy::slot_schema(),
        ];
        slot_schemas.extend(FeePolicyManager::slot_schemas());
        let storage_schema =
            StorageSchema::new(slot_schemas).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Authentication component that restricts input notes and transaction scripts to \
                 fixed allowlists of script roots",
            )
            .with_storage_schema(storage_schema)
    }
}

impl IntoIterator for AuthNetworkAccount {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Expands the configuration into its [`AccountComponent`]s: the auth component itself and all
    /// fee policy components registered with the [`FeePolicyManager`].
    fn into_iter(self) -> Self::IntoIter {
        let Self {
            allowed_notes,
            allowed_tx_scripts,
            sponsorship_policy,
            policy_manager,
        } = self;

        let fee_policy_slots = policy_manager.to_storage_slots();
        let mut storage_slots = vec![
            allowed_notes.into_storage_slot(),
            allowed_tx_scripts.into_storage_slot(),
            sponsorship_policy.into_storage_slot(),
        ];
        storage_slots.extend(fee_policy_slots);

        let auth_component =
            AccountComponent::new(Self::code().clone(), storage_slots, Self::component_metadata())
                .expect(
                    "AuthNetworkAccount component should satisfy the requirements of a valid \
                     account component",
                );

        let mut components = vec![auth_component];
        components.extend(policy_manager.into_fee_policy_components());
        components.into_iter()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountBuilder, StorageSlotContent};
    use miden_protocol::asset::FungibleAsset;

    use super::*;
    use crate::account::wallets::BasicWallet;
    use crate::note::config::NetworkAccountConfigNote;

    #[test]
    fn auth_network_account_component_builds() {
        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let root_b = NoteScriptRoot::from_array([5, 6, 7, 8]);

        let _account = AccountBuilder::new([0; 32])
            .with_components(
                AuthNetworkAccount::new(
                    BTreeSet::from_iter([root_a, root_b]),
                    FeePolicyManager::mock(FungibleAsset::mock_issuer()),
                )
                .expect("non-empty allowlist should construct"),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building with AuthNetworkAccount failed");
    }

    #[test]
    fn auth_network_account_with_empty_input_allowlists_default_notes() {
        let account = AccountBuilder::new([0; 32])
            .with_components(
                AuthNetworkAccount::new(
                    BTreeSet::new(),
                    FeePolicyManager::mock(FungibleAsset::mock_issuer()),
                )
                .expect("the default note roots make the allowlist non-empty"),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building with AuthNetworkAccount failed");

        let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
            .expect("allowlist should be reconstructable from account storage");

        assert_eq!(
            allowlist.allowed_script_roots(),
            &BTreeSet::from_iter([
                NetworkAccountConfigNote::script_root(),
                FeeSponsorshipNote::script_root(),
            ]),
            "an empty input should yield an allowlist containing only the default note roots",
        );
    }

    #[test]
    fn auth_network_account_uses_standardized_allowlist_slot() {
        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let component: AccountComponent = AuthNetworkAccount::new(
            BTreeSet::from_iter([root_a]),
            FeePolicyManager::mock(FungibleAsset::mock_issuer()),
        )
        .expect("non-empty allowlist should construct")
        .into_iter()
        .next()
        .expect("auth component is yielded first");

        let storage_slots = component.storage_slots();
        assert_eq!(storage_slots[0].name(), NetworkAccountNoteAllowlist::slot_name());
        assert_eq!(storage_slots[1].name(), NetworkAccountTxScriptAllowlist::slot_name());

        for name in [
            NetworkAccountNoteAllowlist::slot_name(),
            NetworkAccountTxScriptAllowlist::slot_name(),
        ] {
            let slot = storage_slots
                .iter()
                .find(|slot| slot.name() == name)
                .expect("allowlist slot must be present");
            let StorageSlotContent::Map(_) = slot.content() else {
                panic!("allowlist slots must be maps");
            };
        }
    }

    #[test]
    fn auth_network_account_always_allowlists_config_note() {
        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let account = AccountBuilder::new([0; 32])
            .with_components(
                AuthNetworkAccount::new(
                    BTreeSet::from_iter([root_a]),
                    FeePolicyManager::mock(FungibleAsset::mock_issuer()),
                )
                .expect("config note root makes the allowlist non-empty"),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building with AuthNetworkAccount failed");

        let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
            .expect("allowlist should be reconstructable from account storage");

        assert!(
            allowlist
                .allowed_script_roots()
                .contains(&NetworkAccountConfigNote::script_root()),
            "new should always allowlist the config note root",
        );
        assert!(
            allowlist.allowed_script_roots().contains(&root_a),
            "new should preserve the provided allowlist entries",
        );
    }
}
