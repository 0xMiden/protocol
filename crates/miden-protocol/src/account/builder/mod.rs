use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::account::component::StorageSchema;
use crate::account::{
    Account,
    AccountCode,
    AccountComponent,
    AccountId,
    AccountIdV1,
    AccountIdVersion,
    AccountStorage,
    AccountType,
    AssetCallbackFlag,
};
use crate::asset::{AssetCallbacks, AssetVault};
use crate::errors::AccountError;
use crate::{Felt, Word};

/// A convenient builder for an [`Account`] allowing for safe construction of an account by
/// combining multiple [`AccountComponent`]s.
///
/// This will build a valid new account with these properties:
/// - An empty [`AssetVault`].
/// - The nonce set to [`Felt::ZERO`].
/// - A seed which results in an [`AccountId`] valid for the configured account type.
///
/// By default, the builder is initialized with:
/// - The `account_type` set to [`AccountType::Private`].
/// - The `version` set to [`AccountIdVersion::Version1`].
///
/// [`AccountBuilder::with_component`] (or [`AccountBuilder::with_components`]) must be called at
/// least once, and exactly one of the added components must be an authentication component (i.e. a
/// component exporting a procedure marked with the `@auth_script` attribute). The auth component is
/// identified and extracted automatically when [`AccountBuilder::build`] is called.
///
/// # Security
///
/// The builder only enforces the structural requirement of exactly one auth component; it does not
/// check that the auth component is a sensible choice for the other components on the account. In
/// particular, an auth component that performs no authentication makes the account permissionless:
/// every state-changing procedure it exposes can be called by anyone. This is especially dangerous
/// when combined with components that rely on the auth component as their sole access gate (such as
/// authority-controlled setters), which then become permissionless as well. Higher-level factory
/// functions vet these combinations; when building an account directly, the caller is responsible
/// for pairing a suitable auth component with the account's other components.
///
/// Under the `testing` feature, it is possible to:
/// - Build an existing account using `AccountBuilder::build_existing`, which will set the account's
///   nonce to `1` by default, or to the configured value.
/// - Add assets to the account's vault; this only succeeds when using
///   `AccountBuilder::build_existing`.
///
/// **Account Procedure Order**
///
/// Note that the auth procedure is always moved to the first position, since the tx kernel assumes
/// procedure index 0 is the auth procedure within an [`AccountCode`]. The procedures of all other
/// components are merged and sorted, so the order in which `with_component` is called does not
/// affect the resulting account code commitment.
#[derive(Debug, Clone)]
pub struct AccountBuilder {
    #[cfg(any(feature = "testing", test))]
    assets: Vec<crate::asset::Asset>,
    #[cfg(any(feature = "testing", test))]
    nonce: Option<Felt>,
    components: Vec<AccountComponent>,
    account_type: AccountType,
    asset_callbacks: AssetCallbackFlag,
    init_seed: [u8; 32],
    id_version: AccountIdVersion,
}

impl AccountBuilder {
    /// Creates a new builder for an account and sets the initial seed from which the grinding
    /// process for that account's [`AccountId`] will start.
    ///
    /// This initial seed should come from a cryptographic random number generator.
    pub fn new(init_seed: [u8; 32]) -> Self {
        Self {
            #[cfg(any(feature = "testing", test))]
            assets: vec![],
            #[cfg(any(feature = "testing", test))]
            nonce: None,
            components: vec![],
            init_seed,
            account_type: AccountType::Private,
            asset_callbacks: AssetCallbackFlag::Disabled,
            id_version: AccountIdVersion::Version1,
        }
    }

    /// Sets the [`AccountIdVersion`] of the account ID.
    pub fn version(mut self, version: AccountIdVersion) -> Self {
        self.id_version = version;
        self
    }

    /// Sets the account type of the account.
    pub fn account_type(mut self, account_type: AccountType) -> Self {
        self.account_type = account_type;
        self
    }

    /// Sets the immutable [`AssetCallbackFlag`] of the account.
    ///
    /// This determines whether assets issued by the account (if any) trigger callbacks. It must be
    /// set to [`AssetCallbackFlag::Enabled`] for faucets that configure a transfer policy, and
    /// is encoded into the resulting [`AccountId`] at creation. Defaults to
    /// [`AssetCallbackFlag::Disabled`].
    pub fn with_asset_callbacks(mut self, asset_callbacks: AssetCallbackFlag) -> Self {
        self.asset_callbacks = asset_callbacks;
        self
    }

    /// Adds an [`AccountComponent`] to the builder. This method can be called multiple times and
    /// **must be called at least once** since an account must export at least one procedure.
    ///
    /// All components will be merged to form the final code and storage of the built account.
    /// Exactly one of the added components must be an authentication component (see
    /// [`AccountComponent::is_auth_component`]); it is identified and moved to the front of the
    /// procedure list automatically when [`Self::build`] is called, while all other procedures are
    /// sorted.
    ///
    /// For composite configurations that expand into multiple components (such as
    /// `AccessControl` or `TokenPolicyManager`), use [`Self::with_components`].
    pub fn with_component(mut self, account_component: impl Into<AccountComponent>) -> Self {
        self.components.push(account_component.into());
        self
    }

    /// Adds the components yielded by `components` to the builder.
    ///
    /// This is a convenience wrapper around repeated [`Self::with_component`] calls. It is
    /// most useful for installing the variable number of components produced by composite
    /// configurations whose component count is not known at the call site (for example, a
    /// configuration value that expands into one or several components depending on its
    /// variant).
    pub fn with_components(
        mut self,
        components: impl IntoIterator<Item = impl Into<AccountComponent>>,
    ) -> Self {
        for component in components {
            self = self.with_component(component);
        }
        self
    }

    /// Returns an iterator of storage schemas attached to the builder's components.
    pub fn storage_schemas(&self) -> impl Iterator<Item = &StorageSchema> + '_ {
        self.components.iter().map(|component| component.storage_schema())
    }

    /// Builds the common parts of testing and non-testing code.
    fn build_inner(&mut self) -> Result<(AssetVault, AccountCode, AccountStorage), AccountError> {
        #[cfg(any(feature = "testing", test))]
        let vault = AssetVault::new(&self.assets).map_err(|err| {
            AccountError::BuildError(format!("asset vault failed to build: {err}"), None)
        })?;

        #[cfg(all(not(feature = "testing"), not(test)))]
        let vault = AssetVault::default();

        // The build method does not access components, so it is safe to `take` them out.
        let components = core::mem::take(&mut self.components);
        let (code, storage) = Account::initialize_from_components(components).map_err(|err| {
            AccountError::BuildError(
                "account components failed to build".into(),
                Some(Box::new(err)),
            )
        })?;

        self.validate_asset_callbacks(&storage)?;

        Ok((vault, code, storage))
    }

    /// Validates that the configured [`AssetCallbackFlag`] is consistent with the asset callback
    /// slots installed by the builder's components.
    ///
    /// The kernel decides whether to invoke a faucet's asset callbacks solely from the
    /// [`AssetCallbackFlag`] encoded in its [`AccountId`], and that flag is immutable once the ID
    /// is ground. A component that installs a callback slot while the flag is
    /// [`AssetCallbackFlag::Disabled`] therefore looks correctly configured but can never have its
    /// callbacks invoked, silently and permanently disabling whatever the callbacks enforce. This
    /// is rejected at build time so the misconfiguration cannot reach a deployed account.
    ///
    /// The converse (the flag enabled without callback slots) is valid: the kernel skips the
    /// callback when the slot is absent or holds the empty word.
    fn validate_asset_callbacks(&self, storage: &AccountStorage) -> Result<(), AccountError> {
        if self.asset_callbacks == AssetCallbackFlag::Enabled {
            return Ok(());
        }

        for slot_name in [
            AssetCallbacks::on_before_asset_added_to_account_slot(),
            AssetCallbacks::on_before_asset_added_to_note_slot(),
        ] {
            if storage.get(slot_name).is_some_and(|slot| !slot.value().is_empty()) {
                return Err(AccountError::BuildError(
                    format!(
                        "component installs the asset callback slot `{slot_name}` but the account's asset callback flag is disabled, so the callback would never be invoked"
                    ),
                    None,
                ));
            }
        }

        Ok(())
    }

    /// Grinds a new [`AccountId`] using the `init_seed` as a starting point.
    fn grind_account_id(
        &self,
        init_seed: [u8; 32],
        version: AccountIdVersion,
        code_commitment: Word,
        storage_commitment: Word,
    ) -> Result<Word, AccountError> {
        let seed = AccountIdV1::compute_account_seed(
            init_seed,
            self.account_type,
            self.asset_callbacks,
            version,
            code_commitment,
            storage_commitment,
        )
        .map_err(|err| {
            AccountError::BuildError("account seed generation failed".into(), Some(Box::new(err)))
        })?;

        Ok(seed)
    }

    /// Builds an [`Account`] out of the configured builder.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The init seed is not set.
    /// - The number of procedures in all merged components is 0 or exceeds
    ///   [`AccountCode::MAX_NUM_PROCEDURES`](crate::account::AccountCode::MAX_NUM_PROCEDURES).
    /// - Two or more packages export a procedure with the same MAST root.
    /// - Authentication component is missing.
    /// - Multiple authentication procedures are found.
    /// - The number of [`StorageSlot`](crate::account::StorageSlot)s of all components exceeds 255.
    /// - [`MastForest::merge`](miden_processor::mast::MastForest::merge) fails on the given
    ///   components.
    /// - A component declares a [`ComponentDependency`](crate::account::ComponentDependency) that
    ///   no component on the account satisfies.
    /// - A component installs an asset callback slot while the configured [`AssetCallbackFlag`] is
    ///   [`AssetCallbackFlag::Disabled`], since the kernel would never invoke that callback.
    /// - If duplicate assets were added to the builder (only under the `testing` feature).
    /// - If the vault is not empty on new accounts (only under the `testing` feature).
    pub fn build(mut self) -> Result<Account, AccountError> {
        let (vault, code, storage) = self.build_inner()?;

        #[cfg(any(feature = "testing", test))]
        if !vault.is_empty() {
            return Err(AccountError::BuildError(
                "account asset vault must be empty on new accounts".into(),
                None,
            ));
        }

        let seed = self.grind_account_id(
            self.init_seed,
            self.id_version,
            code.commitment(),
            storage.to_commitment(),
        )?;

        let account_id = AccountId::new(
            seed,
            AccountIdVersion::Version1,
            code.commitment(),
            storage.to_commitment(),
        )
        .expect("get_account_seed should provide a suitable seed");

        debug_assert_eq!(account_id.account_type(), self.account_type);
        debug_assert_eq!(account_id.asset_callback_flag(), self.asset_callbacks);

        // SAFETY: The account ID was derived from the seed and the seed is provided, so it is safe
        // to bypass the checks of `Account::new`.
        let account =
            Account::new_unchecked(account_id, vault, storage, code, Felt::ZERO, Some(seed));

        Ok(account)
    }
}

#[cfg(any(feature = "testing", test))]
impl AccountBuilder {
    /// Adds all the assets to the account's [`AssetVault`]. This method is optional.
    ///
    /// Must only be used when using [`Self::build_existing`] instead of [`Self::build`] since new
    /// accounts must have an empty vault.
    pub fn with_assets<I: IntoIterator<Item = crate::asset::Asset>>(mut self, assets: I) -> Self {
        self.assets.extend(assets);
        self
    }

    /// Sets the nonce of an existing account.
    ///
    /// This method is optional. It must only be used when using [`Self::build_existing`]
    /// instead of [`Self::build`] since new accounts must have a nonce of `0`.
    pub fn nonce(mut self, nonce: Felt) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Builds the account as an existing account, that is, with the nonce set to [`Felt::ONE`].
    ///
    /// The [`AccountId`] is constructed by slightly modifying `init_seed[0..8]` to be a valid ID.
    ///
    /// For possible errors, see the documentation of [`Self::build`].
    pub fn build_existing(mut self) -> Result<Account, AccountError> {
        let (vault, code, storage) = self.build_inner()?;

        let account_id = {
            let bytes = <[u8; 15]>::try_from(&self.init_seed[0..15])
                .expect("we should have sliced exactly 15 bytes off");
            AccountId::dummy(
                bytes,
                AccountIdVersion::Version1,
                self.account_type,
                self.asset_callbacks,
            )
        };

        // Use the nonce value set by the Self::nonce method or Felt::ONE as a default.
        let nonce = self.nonce.unwrap_or(Felt::ONE);

        Ok(Account::new_existing(account_id, vault, storage, code, nonce))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use assert_matches::assert_matches;
    use miden_core::mast::MastNodeExt;
    use miden_mast_package::Package;

    use super::*;
    use crate::account::component::{AccountComponentMetadata, ComponentDependency};
    use crate::account::{AccountProcedureRoot, StorageSlot, StorageSlotName};
    use crate::testing::assembler::assemble_test_package;
    use crate::testing::noop_auth_component::NoopAuthComponent;

    const CUSTOM_CODE1: &str = "
          @account_procedure
          pub proc foo
            push.2.2 add eq.4
          end
        ";
    const CUSTOM_CODE2: &str = "
            @account_procedure
            pub proc bar
              push.4.4 add eq.8
            end
          ";

    static CUSTOM_PACKAGE1: LazyLock<Package> = LazyLock::new(|| {
        assemble_test_package("custom-package-1", "custom::component1", CUSTOM_CODE1)
    });
    static CUSTOM_PACKAGE2: LazyLock<Package> = LazyLock::new(|| {
        assemble_test_package("custom-package-2", "custom::component2", CUSTOM_CODE2)
    });

    static CUSTOM_COMPONENT1_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
        StorageSlotName::new("custom::component1::slot0")
            .expect("storage slot name should be valid")
    });
    static CUSTOM_COMPONENT2_SLOT_NAME0: LazyLock<StorageSlotName> = LazyLock::new(|| {
        StorageSlotName::new("custom::component2::slot0")
            .expect("storage slot name should be valid")
    });
    static CUSTOM_COMPONENT2_SLOT_NAME1: LazyLock<StorageSlotName> = LazyLock::new(|| {
        StorageSlotName::new("custom::component2::slot1")
            .expect("storage slot name should be valid")
    });

    struct CustomComponent1 {
        slot0: u32,
    }
    impl From<CustomComponent1> for AccountComponent {
        fn from(custom: CustomComponent1) -> Self {
            let mut value = Word::empty();
            value[0] = Felt::from(custom.slot0);

            let metadata = AccountComponentMetadata::new("test::custom_component1");
            AccountComponent::new(
                CUSTOM_PACKAGE1.clone(),
                vec![StorageSlot::with_value(CUSTOM_COMPONENT1_SLOT_NAME.clone(), value)],
                metadata,
            )
            .expect("component should be valid")
        }
    }

    struct CustomComponent2 {
        slot0: u32,
        slot1: u32,
    }
    impl From<CustomComponent2> for AccountComponent {
        fn from(custom: CustomComponent2) -> Self {
            let mut value0 = Word::empty();
            value0[3] = Felt::from(custom.slot0);
            let mut value1 = Word::empty();
            value1[3] = Felt::from(custom.slot1);

            let metadata = AccountComponentMetadata::new("test::custom_component2");
            AccountComponent::new(
                CUSTOM_PACKAGE2.clone(),
                vec![
                    StorageSlot::with_value(CUSTOM_COMPONENT2_SLOT_NAME0.clone(), value0),
                    StorageSlot::with_value(CUSTOM_COMPONENT2_SLOT_NAME1.clone(), value1),
                ],
                metadata,
            )
            .expect("component should be valid")
        }
    }

    /// A component that accesses a storage slot installed by [`CustomComponent2`] without
    /// installing it itself, declared as a [`ComponentDependency`].
    struct DependentComponent;
    impl From<DependentComponent> for AccountComponent {
        fn from(_: DependentComponent) -> Self {
            let metadata = AccountComponentMetadata::new("test::dependent_component")
                .with_dependency(ComponentDependency::StorageSlot(
                    CUSTOM_COMPONENT2_SLOT_NAME0.clone(),
                ));

            AccountComponent::new(CUSTOM_PACKAGE1.clone(), vec![], metadata)
                .expect("component should be valid")
        }
    }

    /// A component whose declared dependency is not installed would abort at runtime on every
    /// procedure that accesses the missing slot, so the account must not build at all.
    #[test]
    fn account_builder_rejects_unsatisfied_dependency() {
        let err = Account::builder([5; 32])
            .with_component(NoopAuthComponent)
            .with_component(DependentComponent)
            .build()
            .expect_err("component dependency is not satisfied");

        assert_matches!(err, AccountError::BuildError(_, Some(source)) => {
            assert_matches!(*source, AccountError::UnsatisfiedComponentDependency { component_name, slot_name } => {
                assert_eq!(component_name, "test::dependent_component");
                assert_eq!(slot_name, *CUSTOM_COMPONENT2_SLOT_NAME0);
            });
        });
    }

    /// Any component may satisfy a dependency: the account builds once some other component
    /// installs the required slot.
    #[test]
    fn account_builder_accepts_satisfied_dependency() {
        let account = Account::builder([5; 32])
            .with_component(NoopAuthComponent)
            .with_component(DependentComponent)
            .with_component(CustomComponent2 { slot0: 1, slot1: 2 })
            .build()
            .expect("component dependency is satisfied by CustomComponent2");

        assert!(account.storage().get(&CUSTOM_COMPONENT2_SLOT_NAME0).is_some());
    }

    #[test]
    fn account_builder() {
        let storage_slot0 = 25;
        let storage_slot1 = 12;
        let storage_slot2 = 42;

        let account = Account::builder([5; 32])
            .with_component(NoopAuthComponent)
            .with_component(CustomComponent1 { slot0: storage_slot0 })
            .with_component(CustomComponent2 {
                slot0: storage_slot1,
                slot1: storage_slot2,
            })
            .build()
            .unwrap();

        // Account should be new, i.e. nonce = zero.
        assert_eq!(account.nonce(), Felt::ZERO);

        let computed_id = AccountId::new(
            account.seed().unwrap(),
            AccountIdVersion::Version1,
            account.code.commitment(),
            account.storage.to_commitment(),
        )
        .unwrap();
        assert_eq!(account.id(), computed_id);

        // The merged code should have one procedure from each package.
        assert_eq!(account.code.procedure_roots().count(), 3);

        let foo_root = CUSTOM_PACKAGE1.mast_forest()[CUSTOM_PACKAGE1
            .get_export_node_id(CUSTOM_PACKAGE1.manifest.exports().next().unwrap().path())]
        .digest();
        let bar_root = CUSTOM_PACKAGE2.mast_forest()[CUSTOM_PACKAGE2
            .get_export_node_id(CUSTOM_PACKAGE2.manifest.exports().next().unwrap().path())]
        .digest();

        assert!(account.code().procedures().contains(&AccountProcedureRoot::from_raw(foo_root)));
        assert!(account.code().procedures().contains(&AccountProcedureRoot::from_raw(bar_root)));

        assert_eq!(
            account.storage().get_item(&CUSTOM_COMPONENT1_SLOT_NAME).unwrap(),
            Word::from([Felt::from(storage_slot0), Felt::ZERO, Felt::ZERO, Felt::ZERO])
        );
        assert_eq!(
            account.storage().get_item(&CUSTOM_COMPONENT2_SLOT_NAME0).unwrap(),
            Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(storage_slot1)])
        );
        assert_eq!(
            account.storage().get_item(&CUSTOM_COMPONENT2_SLOT_NAME1).unwrap(),
            Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(storage_slot2)])
        );
    }

    #[test]
    fn account_builder_with_components() {
        let storage_slot0 = 25;
        let storage_slot1 = 12;
        let storage_slot2 = 42;

        let components: Vec<AccountComponent> = vec![
            CustomComponent1 { slot0: storage_slot0 }.into(),
            CustomComponent2 {
                slot0: storage_slot1,
                slot1: storage_slot2,
            }
            .into(),
        ];

        let account = Account::builder([5; 32])
            .with_component(NoopAuthComponent)
            .with_components(components)
            .build()
            .unwrap();

        // The account built via `with_components` should be identical to one built via
        // chained `with_component` calls in the same order.
        let expected = Account::builder([5; 32])
            .with_component(NoopAuthComponent)
            .with_component(CustomComponent1 { slot0: storage_slot0 })
            .with_component(CustomComponent2 {
                slot0: storage_slot1,
                slot1: storage_slot2,
            })
            .build()
            .unwrap();

        assert_eq!(account.id(), expected.id());
        assert_eq!(account.code().commitment(), expected.code().commitment());
        assert_eq!(account.storage().to_commitment(), expected.storage().to_commitment());

        // Empty iterators are accepted and behave as a no-op.
        let account_no_extra = Account::builder([6; 32])
            .with_component(NoopAuthComponent)
            .with_component(CustomComponent1 { slot0: storage_slot0 })
            .with_components(core::iter::empty::<CustomComponent2>())
            .build()
            .unwrap();

        let expected_no_extra = Account::builder([6; 32])
            .with_component(NoopAuthComponent)
            .with_component(CustomComponent1 { slot0: storage_slot0 })
            .build()
            .unwrap();

        assert_eq!(account_no_extra.id(), expected_no_extra.id());
    }

    #[test]
    fn account_builder_auth_component_position_is_irrelevant() {
        let component1 = CustomComponent1 { slot0: 25 };
        let component2 = CustomComponent2 { slot0: 12, slot1: 42 };
        let common_components =
            vec![AccountComponent::from(component1), AccountComponent::from(component2)];

        let mut components_auth_1st = common_components.clone();
        components_auth_1st.insert(0, AccountComponent::from(NoopAuthComponent));

        let mut components_auth_2nd = common_components.clone();
        components_auth_2nd.insert(1, AccountComponent::from(NoopAuthComponent));

        let seed = [5; 32];
        let auth_1st = Account::builder(seed).with_components(components_auth_1st).build().unwrap();
        let auth_2nd = Account::builder(seed).with_components(components_auth_2nd).build().unwrap();

        assert_eq!(auth_1st.id(), auth_2nd.id());
        assert_eq!(auth_1st.code().commitment(), auth_2nd.code().commitment());
        assert_eq!(auth_1st.storage().to_commitment(), auth_2nd.storage().to_commitment());
    }

    #[test]
    fn account_builder_without_auth_component_fails() {
        let build_error = Account::builder([5; 32])
            .with_component(CustomComponent1 { slot0: 25 })
            .build()
            .unwrap_err();

        assert_matches!(build_error, AccountError::BuildError(_, Some(source)) => {
            assert_matches!(*source, AccountError::AccountCodeNoAuthComponent);
        });
    }

    #[test]
    fn account_builder_with_multiple_auth_components_fails() {
        let build_error = Account::builder([5; 32])
            .with_component(NoopAuthComponent)
            .with_component(NoopAuthComponent)
            .with_component(CustomComponent1 { slot0: 25 })
            .build()
            .unwrap_err();

        assert_matches!(build_error, AccountError::BuildError(_, Some(source)) => {
            assert_matches!(*source, AccountError::AccountCodeMultipleAuthComponents);
        });
    }

    #[test]
    fn account_builder_non_empty_vault_on_new_account() {
        let storage_slot0 = 25;

        let build_error = Account::builder([0xff; 32])
            .with_component(NoopAuthComponent)
            .with_component(CustomComponent1 { slot0: storage_slot0 })
            .with_assets(AssetVault::mock().assets())
            .build()
            .unwrap_err();

        assert_matches!(build_error, AccountError::BuildError(msg, _) if msg == "account asset vault must be empty on new accounts")
    }

    /// A component that installs an asset callback slot must not be built into an account whose
    /// [`AssetCallbackFlag`] is disabled: the kernel gates callback invocation on that flag alone
    /// and the flag is immutable once the ID is ground, so whatever the callback enforces would
    /// be silently and permanently bypassed.
    #[test]
    fn account_builder_rejects_callback_slot_with_disabled_flag() {
        let callback_component = |slots| {
            AccountComponent::new(
                CUSTOM_PACKAGE1.clone(),
                slots,
                AccountComponentMetadata::new("test::callback_component"),
            )
            .expect("component should be valid")
        };

        for slots in [
            AssetCallbacks::new()
                .on_before_asset_added_to_note(Word::from([1u32, 2, 3, 4]))
                .into_storage_slots(),
            AssetCallbacks::new()
                .on_before_asset_added_to_account(Word::from([1u32, 2, 3, 4]))
                .into_storage_slots(),
        ] {
            let build_error = Account::builder([7; 32])
                .with_component(NoopAuthComponent)
                .with_component(callback_component(slots.clone()))
                .build()
                .unwrap_err();

            assert_matches!(build_error, AccountError::BuildError(msg, _) if msg.contains("asset callback flag is disabled"));

            // The same component is accepted once the flag is enabled.
            Account::builder([7; 32])
                .with_asset_callbacks(AssetCallbackFlag::Enabled)
                .with_component(NoopAuthComponent)
                .with_component(callback_component(slots))
                .build()
                .unwrap();
        }
    }

    // TODO: Test that a BlockHeader with a number which is not a multiple of 2^16 returns an error.
}
