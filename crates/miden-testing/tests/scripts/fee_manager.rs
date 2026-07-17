use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountType,
    StorageMap,
    StorageMapKey,
    StorageSlot,
};
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::errors::MasmError;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::fees::{ConstantFeePolicy, FeeManager, FeePolicy};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_LOOKUP_KEY_PROC_ROOT_NOT_IN_ACCOUNT,
    ERR_LOOKUP_KEY_PROC_ROOT_NOT_SET,
    ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE,
};
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use rstest::rstest;

// HELPERS
// ================================================================================================

/// The fee amount scheduled in these tests.
pub(super) const FEE_AMOUNT: u64 = 500;

pub(super) fn fee_faucet_id() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?)
}

/// The note script root priced in the fee schedule of the constant fee policy.
pub(super) fn priced_root() -> NoteScriptRoot {
    NoteScriptRoot::from_array([1, 2, 3, 4])
}

/// The note script root scheduled with an explicit 0 fee in the constant fee policy.
fn free_root() -> NoteScriptRoot {
    NoteScriptRoot::from_array([5, 6, 7, 8])
}

/// Builds a `FeeManager` whose active policy is a `ConstantFeePolicy` charging [`FEE_AMOUNT`]
/// (in the test faucet's asset) for notes with the [`priced_root`] script root and an explicit
/// 0 fee for the [`free_root`] script root, and whose allowed-policies map additionally
/// registers the user-defined [`custom_fee_policy`] for runtime switching.
fn fee_manager() -> anyhow::Result<FeeManager> {
    let constant_fee_policy = ConstantFeePolicy::new(fee_faucet_id()?)
        .with_fee(priced_root(), AssetAmount::new(FEE_AMOUNT)?)
        .with_fee(free_root(), AssetAmount::ZERO);
    Ok(FeeManager::builder()
        .active_fee_policy(constant_fee_policy.into())
        .allowed_fee_policy(custom_fee_policy()?)
        .build())
}

/// The fee charged by the user-defined test policy in [`custom_fee_policy`].
pub(super) const CUSTOM_FEE_AMOUNT: u64 = 777;

/// The namespace under which the user-defined test policy is compiled.
const CUSTOM_FEE_POLICY_NAME: &str = "test::fees::storage_commitment_fee";

/// Builds a user-defined fee policy component, mirroring how a contract developer would plug
/// their own fee computation logic into the `FeeManager` via [`FeePolicy::custom`].
///
/// The policy charges [`CUSTOM_FEE_AMOUNT`] in an "asset" identified by the note's
/// STORAGE_COMMITMENT. Pricing on a parameter other than NOTE_SCRIPT_ROOT proves that the
/// manager forwards the full note parameter set to the policy implementation.
pub(super) fn custom_fee_policy() -> anyhow::Result<FeePolicy> {
    let masm_source = format!(
        r#"
        use {{Asset, NoteScriptRoot}} from miden::protocol::types

        #! Fee policy charging a fixed amount in an asset identified by the note's storage
        #! commitment.
        #!
        #! Inputs:  [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT]
        #! Outputs: [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]
        #!
        #! Invocation: call
        @account_procedure
        pub proc compute_note_fee(
            note_script_root: NoteScriptRoot,
            storage_commitment: word,
            assets_commitment: word,
            attachments_commitment: word
        ) -> Asset
            # keep STORAGE_COMMITMENT as the fee asset ID, dropping the other note parameters
            dropw swapw dropw swapw dropw
            # => [STORAGE_COMMITMENT, pad(12)]

            push.0.0.0.{CUSTOM_FEE_AMOUNT}
            # => [FEE_ASSET_VALUE, STORAGE_COMMITMENT, pad(12)]

            swapw
            # => [STORAGE_COMMITMENT, FEE_ASSET_VALUE, pad(12)]

            # drop the excess padding to restore the stack depth for the call boundary
            movupw.3 dropw
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]
        end
        "#
    );

    let code =
        CodeBuilder::default().compile_component_code(CUSTOM_FEE_POLICY_NAME, &masm_source)?;
    let root = code
        .get_procedure_root_by_path(format!("{CUSTOM_FEE_POLICY_NAME}::compute_note_fee").as_str())
        .expect("custom fee policy should export compute_note_fee");
    let component = AccountComponent::new(
        code,
        vec![],
        AccountComponentMetadata::mock(CUSTOM_FEE_POLICY_NAME),
    )?;

    Ok(FeePolicy::custom(root, [component])?)
}

/// The namespace under which the user-defined lookup-key procedure is compiled.
const CUSTOM_LOOKUP_KEY_NAME: &str = "test::fees::storage_commitment_lookup";

/// Builds the `constant_fee` policy component by hand with the given fee schedule and lookup-key
/// procedure root - `From<ConstantFeePolicy>` always writes the built-in root to the slot.
fn constant_fee_component(
    fee_schedule: StorageMap,
    lookup_key_proc_root: Word,
) -> anyhow::Result<AccountComponent> {
    let fee_asset_id_slot = StorageSlot::with_value(
        ConstantFeePolicy::fee_asset_id_slot_name().clone(),
        AssetId::new_fungible(fee_faucet_id()?).to_word(),
    );
    let fee_schedule_slot =
        StorageSlot::with_map(ConstantFeePolicy::fee_schedule_slot_name().clone(), fee_schedule);
    let lookup_key_proc_root_slot = StorageSlot::with_value(
        ConstantFeePolicy::lookup_key_proc_root_slot_name().clone(),
        lookup_key_proc_root,
    );
    Ok(AccountComponent::new(
        ConstantFeePolicy::code().clone(),
        vec![fee_asset_id_slot, fee_schedule_slot, lookup_key_proc_root_slot],
        ConstantFeePolicy::component_metadata(),
    )?)
}

/// Builds an account exposing the fee manager procedures, owned by `owner` via `Ownable2Step`
/// with an owner-controlled `Authority` so the owner-gated `set_fee_policy` can be exercised.
pub(super) fn build_fee_account_with_switching(owner: AccountId) -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
        .with_components(fee_manager()?)
        .build_existing()?)
}

/// Builds a transaction script that calls `estimate_note_fee` and asserts the returned fee
/// asset. The tx script argument supplies NOTE_SCRIPT_ROOT on top of the initial operand stack;
/// the given STORAGE_COMMITMENT is pushed below it, and the remaining zeros serve as the other
/// note parameters, forming the full 16-felt `estimate_note_fee` inputs. A wrong result aborts
/// the transaction, so successful execution proves the returned fee asset.
pub(super) fn estimate_note_fee_tx_script_code(
    storage_commitment: Word,
    expected_fee_asset_id: Word,
    expected_fee_value: Word,
) -> String {
    format!(
        r#"
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            # => [NOTE_SCRIPT_ROOT, pad(12)]

            # place STORAGE_COMMITMENT below NOTE_SCRIPT_ROOT
            push.{storage_commitment} swapw
            # => [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, pad(12)]

            call.fee_manager::estimate_note_fee
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]

            push.{expected_fee_asset_id}
            assert_eqw.err="estimate_note_fee should return the expected fee asset ID"
            # => [FEE_ASSET_VALUE, pad(12)]

            push.{expected_fee_value}
            assert_eqw.err="estimate_note_fee should return the expected fee amount"
            # => [pad(16)]
        end
        "#
    )
}

/// Builds a note script that calls the owner-gated `set_fee_policy` with the given policy root.
pub(super) fn create_set_fee_policy_note_script(policy_root: Word) -> String {
    format!(
        r#"
        use miden::standards::fees::fee_manager

        @note_script
        pub proc main
            padw padw padw
            push.{policy_root}
            call.fee_manager::set_fee_policy
            dropw dropw dropw dropw
        end
        "#
    )
}

// TESTS
// ================================================================================================

/// `FeeManager::estimate_note_fee`, invoked via `call` from a transaction script, dispatches to
/// the active `ConstantFeePolicy` and returns the policy's fee asset ID and the fee amount
/// scheduled for the queried note script root. Roots scheduled with an explicit 0 fee estimate
/// to an amount of 0.
#[rstest]
#[case::priced_root(priced_root(), FEE_AMOUNT)]
#[case::zero_fee_root(free_root(), 0)]
#[tokio::test]
async fn estimate_note_fee_returns_scheduled_fee(
    #[case] queried_root: NoteScriptRoot,
    #[case] expected_amount: u64,
) -> anyhow::Result<()> {
    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_manager()?)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // The constant fee policy ignores the storage commitment, so an all-zero one is passed.
    let tx_script_code = estimate_note_fee_tx_script_code(
        Word::empty(),
        AssetId::new_fungible(fee_faucet_id()?).to_word(),
        AssetAmount::new(expected_amount)?.to_word(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(queried_root.as_word())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// `compute_note_fee` refuses to dispatch to an invalid lookup-key procedure root: a hand-built
/// `constant_fee` component deployment whose `lookup_key_proc_root` slot holds a zero word or a
/// root that is not a procedure of the account aborts with the matching error instead of invoking
/// an arbitrary MAST root.
#[rstest]
#[case::unset_root(Word::empty(), ERR_LOOKUP_KEY_PROC_ROOT_NOT_SET)]
#[case::foreign_root(Word::from([4u32, 3, 2, 1]), ERR_LOOKUP_KEY_PROC_ROOT_NOT_IN_ACCOUNT)]
#[tokio::test]
async fn estimate_note_fee_rejects_invalid_lookup_key_proc_root(
    #[case] lookup_key_proc_root: Word,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let component = constant_fee_component(StorageMap::new(), lookup_key_proc_root)?;
    let policy = FeePolicy::custom(ConstantFeePolicy::root(), [component])?;

    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(FeeManager::builder().active_fee_policy(policy).build())
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // The expected fee values are irrelevant: the transaction must abort before returning.
    let tx_script_code = estimate_note_fee_tx_script_code(
        Word::empty(),
        AssetId::new_fungible(fee_faucet_id()?).to_word(),
        AssetAmount::new(0)?.to_word(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let result = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(priced_root().as_word())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// `estimate_note_fee` aborts when the queried note script root has no entry in the active
/// `ConstantFeePolicy`'s fee schedule, rather than estimating unpriced note scripts to a fee
/// of 0.
#[tokio::test]
async fn estimate_note_fee_aborts_for_unscheduled_root() -> anyhow::Result<()> {
    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_manager()?)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // The expected fee asset words are irrelevant: execution aborts in `compute_note_fee`
    // before the tx script's assertions are reached.
    let tx_script_code =
        estimate_note_fee_tx_script_code(Word::empty(), Word::empty(), Word::empty());
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let result = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(NoteScriptRoot::from_array([9, 10, 11, 12]).as_word())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE);

    Ok(())
}

/// A `constant_fee` deployment with a custom root in the `lookup_key_proc_root` slot dispatches
/// to that procedure: it keys on STORAGE_COMMITMENT, so an unpriced note script root estimates
/// to the fee stored under the note's storage commitment.
#[tokio::test]
async fn estimate_note_fee_dispatches_to_custom_lookup_key_procedure() -> anyhow::Result<()> {
    let masm_source = r#"
        use {NoteScriptRoot, StorageMapKey} from miden::protocol::types

        #! Lookup-key procedure keying the fee schedule on the note's storage commitment.
        #!
        #! Inputs:  [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT]
        #! Outputs: [LOOKUP_KEY, pad(12)]
        #!
        #! Invocation: call
        @account_procedure
        pub proc build_note_fee_lookup_key(
            note_script_root: NoteScriptRoot,
            storage_commitment: word,
            assets_commitment: word,
            attachments_commitment: word
        ) -> StorageMapKey
            # keep STORAGE_COMMITMENT as the lookup key, dropping the other note parameters
            dropw swapw dropw swapw dropw
            # => [LOOKUP_KEY, pad(12)]
        end
        "#;

    let lookup_code =
        CodeBuilder::default().compile_component_code(CUSTOM_LOOKUP_KEY_NAME, masm_source)?;
    let lookup_root = lookup_code
        .get_procedure_root_by_path(
            format!("{CUSTOM_LOOKUP_KEY_NAME}::build_note_fee_lookup_key").as_str(),
        )
        .expect("custom lookup-key component should export build_note_fee_lookup_key");
    let lookup_component = AccountComponent::new(
        lookup_code,
        vec![],
        AccountComponentMetadata::mock(CUSTOM_LOOKUP_KEY_NAME),
    )?;

    // The custom lookup-key procedure keys on the storage commitment, so the fee is scheduled
    // under it (as [fee_amount, 0, 0, 1] with the set-marker in the last element).
    let storage_commitment = Word::from([5u32, 6, 7, 8]);
    let fee_schedule = StorageMap::with_entries([(
        StorageMapKey::new(storage_commitment),
        Word::new([Felt::new(FEE_AMOUNT)?, Felt::ZERO, Felt::ZERO, Felt::ONE]),
    )])?;

    let policy_component = constant_fee_component(fee_schedule, lookup_root.as_word())?;
    let policy =
        FeePolicy::custom(ConstantFeePolicy::root(), [policy_component, lookup_component])?;

    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(FeeManager::builder().active_fee_policy(policy).build())
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let tx_script_code = estimate_note_fee_tx_script_code(
        storage_commitment,
        AssetId::new_fungible(fee_faucet_id()?).to_word(),
        AssetAmount::new(FEE_AMOUNT)?.to_word(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    // The queried note script root has no schedule entry; the fee can only come from the
    // storage-commitment key produced by the custom lookup-key procedure.
    mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(NoteScriptRoot::from_array([9, 9, 9, 9]).as_word())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// End-to-end dispatch through a user-defined fee policy: a custom policy component (registered
/// via [`FeePolicy::custom`]) is set as the manager's active policy, and `estimate_note_fee` is
/// invoked via FPI. The manager forwards the note parameters to the user-defined
/// `compute_note_fee`, whose result flows back through `estimate_note_fee` to the FPI caller.
///
/// The custom policy prices on STORAGE_COMMITMENT (ignoring NOTE_SCRIPT_ROOT), so the assertion
/// on the returned fee asset proves the full parameter set reached the user-defined procedure.
#[tokio::test]
async fn estimate_note_fee_dispatches_to_custom_policy_via_fpi() -> anyhow::Result<()> {
    let fee_manager = FeeManager::builder().active_fee_policy(custom_fee_policy()?).build();

    let foreign_account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_manager)
        .build_existing()?;

    let native_account = AccountBuilder::new([2; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    // The custom policy identifies the fee asset by the note's storage commitment.
    let storage_commitment = Word::from([5u32, 6, 7, 8]);

    // The note parameters are pushed inline: STORAGE_COMMITMENT first, then an arbitrary
    // NOTE_SCRIPT_ROOT (the custom policy ignores it) on top; the zeros below serve as the
    // other note parameters.
    let tx_script_code = format!(
        r#"
        use miden::protocol::tx

        @transaction_script
        pub proc main
            # => [pad(16)]

            push.{storage_commitment} push.{note_script_root}
            # => [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, pad(16)]

            # push the estimate_note_fee procedure root and the foreign account ID
            push.{estimate_note_fee_root}
            push.{foreign_prefix} push.{foreign_suffix}
            # => [foreign_account_id_suffix, foreign_account_id_prefix, FOREIGN_PROC_ROOT,
            #     NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, pad(16)]

            exec.tx::execute_foreign_procedure
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]

            push.{expected_fee_asset_id}
            assert_eqw.err="custom fee policy should price in the asset identified by the storage commitment"
            # => [FEE_ASSET_VALUE, pad(12)]

            push.{expected_fee_value}
            assert_eqw.err="custom fee policy should charge the fixed custom amount"
            # => [pad(16)]
        end
        "#,
        note_script_root = NoteScriptRoot::from_array([9, 9, 9, 9]).as_word(),
        estimate_note_fee_root = FeeManager::estimate_note_fee_root().mast_root(),
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        expected_fee_asset_id = storage_commitment,
        expected_fee_value = AssetAmount::new(CUSTOM_FEE_AMOUNT)?.to_word(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(foreign_account.id())?;

    mock_chain
        .build_tx_context(native_account.id(), &[], &[])?
        .foreign_accounts([foreign_account_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}
