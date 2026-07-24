use alloc::sync::Arc;
use std::collections::BTreeSet;

use miden_processor::ExecutionError;
use miden_processor::crypto::random::RandomCoin;
use miden_processor::operation::OperationError;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{AccessControl, Authority, Ownable2Step};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{ConstantFeePolicy, FeePolicy, FeePolicyManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_POLICY_ROOT_IS_ACTIVE,
    ERR_FEE_POLICY_ROOT_NOT_ALLOWED,
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
    ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE,
    ERR_SENDER_NOT_OWNER,
    ERR_TIMEFRAME_OR_PRIORITY_NOT_U32,
};
use miden_standards::note::{FeePolicyManagerConfig, FeePolicyManagerConfigNote};
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use rstest::rstest;

// HELPERS
// ================================================================================================

/// The fee scheduled for [`priced_root`] in these tests.
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

/// Builds a `FeePolicyManager` whose active policy is a `ConstantFeePolicy` charging [`FEE_AMOUNT`]
/// (in the test faucet's asset) for notes with the [`priced_root`] script root and an explicit
/// 0 fee for the [`free_root`] script root, and whose allowed-policies map additionally
/// registers the user-defined [`custom_fee_policy`] for runtime switching.
fn fee_policy_manager() -> anyhow::Result<FeePolicyManager> {
    let constant_fee_policy = ConstantFeePolicy::new()
        .with_fee(priced_root(), AssetAmount::new(FEE_AMOUNT)?)
        .with_fee(free_root(), AssetAmount::ZERO);

    Ok(FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(constant_fee_policy.into())
        .allowed_fee_policy(custom_fee_policy()?)
        .build())
}

/// Installs a `FeePolicyManager`'s policy components together with the fee-policy storage and
/// procedures that, in a real deployment, the `AuthNetworkAccount` component owns.
pub(super) fn fee_policy_manager_with_storage(
    manager: FeePolicyManager,
) -> anyhow::Result<Vec<AccountComponent>> {
    let storage: AccountComponent =
        MockAccountComponent::with_slots(manager.to_storage_slots().to_vec()).into();
    Ok([storage, fee_procedures_component()?]
        .into_iter()
        .chain(manager.into_fee_policy_components())
        .collect())
}

/// Compiles a minimal account component re-exporting the fee-policy procedures, standing in for
/// the `AuthNetworkAccount` component that exposes them in a real deployment.
fn fee_procedures_component() -> anyhow::Result<AccountComponent> {
    const NAME: &str = "test::fees::fee_procedure_exposer";
    let code = CodeBuilder::default().compile_component_code(
        NAME,
        "pub use {estimate_note_fee} from miden::standards::fees::fee_manager
         pub use {get_fee_asset_id} from miden::standards::fees::fee_manager
         pub use {get_fee_policy} from miden::standards::fees::fee_manager
         pub use {set_fee_policy} from miden::standards::fees::fee_manager
         pub use {add_allowed_fee_policy} from miden::standards::fees::fee_manager
         pub use {remove_allowed_fee_policy} from miden::standards::fees::fee_manager\n",
    )?;
    Ok(AccountComponent::new(code, vec![], AccountComponentMetadata::mock(NAME))?)
}

/// The base fee charged by the user-defined test policy in [`custom_fee_policy`].
pub(super) const CUSTOM_FEE_AMOUNT: u64 = 777;

/// The fee the user-defined test policy in [`custom_fee_policy`] charges for the given storage
/// commitment, timeframe, and priority. The distinct timeframe and priority weights make a
/// transposition of the two parameters detectable; the storage-commitment term proves the
/// policy recovered the commitment from the recipient.
pub(super) fn custom_fee_amount_for(
    storage_commitment: Word,
    timeframe: u64,
    priority: u64,
) -> u64 {
    let commitment_sum = (0..4).map(|idx| storage_commitment[idx].as_canonical_u64()).sum::<u64>();
    CUSTOM_FEE_AMOUNT + 2 * timeframe + priority + commitment_sum
}

/// The namespace under which the user-defined test policy is compiled.
const CUSTOM_FEE_POLICY_NAME: &str = "test::fees::storage_commitment_fee";

/// Builds a user-defined fee policy component, mirroring how a contract developer would plug
/// their own fee computation logic into the `FeePolicyManager` via [`FeePolicy::custom`].
///
/// The policy charges [`custom_fee_amount_for`] the note's storage commitment (recovered from
/// RECIPIENT via the advice provider), timeframe, and priority. Pricing on parameters other than
/// the note's script root - with distinct weights on timeframe and priority - proves that the
/// manager forwards the full note parameter set, slot by slot, to the policy implementation. The
/// policy stores no fee asset ID of its own and instead reads the one of the manager it assumes
/// to be installed alongside, so the manager's fee asset consistency check always passes.
pub(super) fn custom_fee_policy() -> anyhow::Result<FeePolicy> {
    let masm_source = format!(
        r#"
        use miden::standards::fees::fee_manager
        use miden::standards::note

        use {{Asset, NoteRecipient}} from miden::protocol::types

        #! Fee policy charging a fixed amount plus twice the timeframe plus the priority plus the
        #! sum of the storage commitment elements (recovered from the recipient via the advice
        #! provider), in the fee asset the manager is configured with.
        #!
        #! Inputs:  [RECIPIENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, priority, pad(2)]
        #! Outputs: [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]
        #!
        #! Invocation: call
        @account_procedure
        pub proc compute_note_fee(
            recipient: NoteRecipient,
            assets_commitment: word,
            attachments_commitment: word,
            timeframe: u32,
            priority: u32
        ) -> Asset
            exec.note::get_recipient_preimage
            # => [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT,
            #     timeframe, priority, pad(2)]

            # drop the script root and reduce the storage commitment to the sum of its elements
            dropw add add add
            # => [storage_commitment_sum, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe,
            #     priority, pad(2)]

            # keep the sum and the timeframe and priority as pricing inputs, dropping the
            # remaining note parameters
            movdn.8 dropw dropw
            # => [storage_commitment_sum, timeframe, priority, pad(10)]

            # charge the base amount plus twice the timeframe plus the priority plus the storage
            # commitment sum
            swap mul.2 add add push.{CUSTOM_FEE_AMOUNT} add
            # => [fee_amount, pad(12)]

            push.0.0.0 movup.3
            # => [FEE_ASSET_VALUE, pad(15)]

            # drop the excess padding before reading the fee asset ID
            movupw.3 dropw
            # => [FEE_ASSET_VALUE, pad(12)]

            # charge the fee in the asset the manager is configured with
            exec.fee_manager::read_fee_asset_id
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(12)]

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

/// Builds an account exposing the fee policy manager procedures, owned by `owner` via
/// `Ownable2Step` with an owner-controlled `Authority` so the owner-gated `set_fee_policy` can be
/// exercised.
pub(super) fn build_fee_account_with_switching(owner: AccountId) -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
        .with_components(fee_policy_manager_with_storage(fee_policy_manager()?)?)
        .build_existing()?)
}

/// Builds a transaction script that calls `estimate_note_fee` and asserts the returned fee
/// asset. The tx script argument supplies the queried NOTE_SCRIPT_ROOT on top of the initial
/// operand stack. The script derives the RECIPIENT of a note with that script root, the given
/// STORAGE_COMMITMENT, and an all-zero serial number, seeding the advice map with the recipient
/// preimages the fee policy recovers, and places the given timeframe and priority in their
/// parameter slots; the remaining zeros serve as the other note parameters (assets and
/// attachments commitments), forming the full 16-felt `estimate_note_fee` inputs. A wrong result
/// aborts the transaction, so successful execution proves the returned fee asset.
pub(super) fn estimate_note_fee_tx_script_code(
    storage_commitment: Word,
    timeframe: u64,
    priority: u64,
    expected_fee_asset_id: Word,
    expected_fee_value: Word,
) -> String {
    format!(
        r#"
        use miden::core::crypto::hashes::poseidon2
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            # => [NOTE_SCRIPT_ROOT, pad(12)]

            # place STORAGE_COMMITMENT below NOTE_SCRIPT_ROOT and the all-zero serial number plus
            # the empty word above it
            push.{storage_commitment} swapw padw padw
            # => [SERIAL_NUM = 0, EMPTY_WORD, NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, pad(12)]

            # compute the note's recipient, inserting the recipient preimages into the advice map
            # so the fee policy can recover the script root and storage commitment
            adv.insert_hdword exec.poseidon2::merge
            adv.insert_hdword exec.poseidon2::merge
            adv.insert_hdword exec.poseidon2::merge
            # => [RECIPIENT, pad(12)]

            # place the timeframe and priority in their parameter slots; the zeros in between
            # serve as the assets and attachments commitments
            push.{priority} push.{timeframe} movdn.13 movdn.13
            # => [RECIPIENT, ASSETS_COMMITMENT = 0, ATTACHMENTS_COMMITMENT = 0, timeframe,
            #     priority, pad(4)]

            call.fee_manager::estimate_note_fee
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(10)]

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

/// Builds a note script that calls the owner-gated `fee_manager` procedure `proc_name` with the
/// given policy root. Covers the procedures taking a single policy-root word: `set_fee_policy`,
/// `add_allowed_fee_policy`, and `remove_allowed_fee_policy`.
pub(super) fn create_fee_manager_note_script(proc_name: &str, policy_root: Word) -> String {
    format!(
        r#"
        use miden::standards::fees::fee_manager

        @note_script
        pub proc main
            push.{policy_root}
            call.fee_manager::{proc_name}

            dropw
        end
        "#
    )
}

/// Builds a note script that calls `get_fee_policy` and asserts the returned active fee policy root
/// matches `expected_policy_root`.
pub(super) fn create_get_fee_policy_note_script(expected_policy_root: Word) -> String {
    format!(
        r#"
        use miden::standards::fees::fee_manager

        @note_script
        pub proc main
            padw padw padw padw
            call.fee_manager::get_fee_policy
            # => [FEE_POLICY_ROOT, pad(12)]

            push.{expected_policy_root}
            assert_eqw.err="get_fee_policy should return the active fee policy root"
            # => [pad(12)]
            dropw dropw dropw
        end
        "#
    )
}

/// Builds a private note carrying `note_script`, sent by `sender` and seeded from `seed`.
fn build_sender_note(sender: AccountId, seed: u32, note_script: &str) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new([Felt::from(seed); 4].into());
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .code(note_script)
        .build()?)
}

/// Consumes `note` with `account_id`, commits the resulting transaction, and advances the chain so
/// the account's storage mutation takes effect for subsequent transactions. Panics if the
/// transaction fails.
async fn consume_note(
    mock_chain: &mut MockChain,
    account_id: AccountId,
    note: &Note,
) -> anyhow::Result<()> {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let executed_transaction = mock_chain
        .build_transaction(account_id)
        .authenticated_input_note(note.id())
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

// TESTS
// ================================================================================================

/// `FeePolicyManager::estimate_note_fee`, invoked via `call` from a transaction script, dispatches
/// to the active `ConstantFeePolicy` and returns the policy's fee asset ID and the fee amount
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
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_policy_manager_with_storage(fee_policy_manager()?)?)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // The constant fee policy ignores the storage commitment, timeframe, and priority, so an
    // all-zero commitment and arbitrary non-zero timeframe and priority are passed.
    let tx_script_code = estimate_note_fee_tx_script_code(
        Word::empty(),
        11,
        7,
        AssetId::new_fungible(fee_faucet_id()?).to_word(),
        AssetAmount::new(expected_amount)?.to_word(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .tx_script_args(queried_root.as_word())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// `estimate_note_fee` rejects a timeframe or priority that is not a valid u32 value.
#[rstest]
#[case::timeframe(u64::from(u32::MAX) + 1, 0)]
#[case::priority(0, u64::from(u32::MAX) + 1)]
#[tokio::test]
async fn estimate_note_fee_rejects_non_u32_timeframe_or_priority(
    #[case] timeframe: u64,
    #[case] priority: u64,
) -> anyhow::Result<()> {
    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_policy_manager_with_storage(fee_policy_manager()?)?)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // The expected fee asset is irrelevant since the call aborts before the assertions.
    let tx_script_code = estimate_note_fee_tx_script_code(
        Word::empty(),
        timeframe,
        priority,
        Word::empty(),
        Word::empty(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let result = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .tx_script_args(priced_root().as_word())
        .build()?
        .execute()
        .await;

    // `u32assert2` raises a `U32AssertionFailed` (not a plain `FailedAssertion`), so match the
    // variant explicitly and assert on its error code.
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { err_code, .. },
            ..
        } if err_code == ERR_TIMEFRAME_OR_PRIORITY_NOT_U32.code()
    );

    Ok(())
}

/// `estimate_note_fee` aborts when the queried note script root has no entry in the active
/// `ConstantFeePolicy`'s fee schedule, rather than estimating unpriced note scripts to a fee
/// of 0.
#[tokio::test]
async fn estimate_note_fee_aborts_for_unscheduled_root() -> anyhow::Result<()> {
    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_policy_manager_with_storage(fee_policy_manager()?)?)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // The expected fee asset words are irrelevant: execution aborts in `compute_note_fee`
    // before the tx script's assertions are reached.
    let tx_script_code =
        estimate_note_fee_tx_script_code(Word::empty(), 0, 0, Word::empty(), Word::empty());
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let result = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .tx_script_args(NoteScriptRoot::from_array([9, 10, 11, 12]).as_word())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE);

    Ok(())
}

/// End-to-end dispatch through a user-defined fee policy: a custom policy component (registered
/// via [`FeePolicy::custom`]) is set as the manager's active policy, and `estimate_note_fee` is
/// invoked via FPI. The manager forwards the note parameters to the user-defined
/// `compute_note_fee`, whose result (including the fee asset ID the policy reads from the
/// manager's storage) flows back through `estimate_note_fee` to the FPI caller.
///
/// The custom policy prices on STORAGE_COMMITMENT, timeframe, and priority (ignoring
/// NOTE_SCRIPT_ROOT), so the assertions on the returned fee asset prove the full parameter set
/// reached the user-defined procedure slot by slot.
#[tokio::test]
async fn estimate_note_fee_dispatches_to_custom_policy_via_fpi() -> anyhow::Result<()> {
    let fee_policy_manager = FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(custom_fee_policy()?)
        .build();

    let foreign_account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_policy_manager_with_storage(fee_policy_manager)?)
        .build_existing()?;

    let native_account = AccountBuilder::new([2; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    // The custom policy folds the sum of the storage commitment elements into the fee amount.
    let storage_commitment = Word::from([5u32, 6, 7, 8]);

    // Distinct non-zero timeframe and priority prove the parameters reach the policy slot by
    // slot.
    let timeframe = 40u64;
    let priority = 9u64;

    // The note parameters are pushed inline: the RECIPIENT is derived from the storage
    // commitment, an arbitrary NOTE_SCRIPT_ROOT (the custom policy ignores it), and an all-zero
    // serial number, seeding the advice map with the recipient preimages the custom policy
    // recovers; the zeros below serve as the other note parameters.
    let tx_script_code = format!(
        r#"
        use miden::core::crypto::hashes::poseidon2
        use miden::protocol::tx

        @transaction_script
        pub proc main
            # => [pad(16)]

            push.{storage_commitment} push.{note_script_root} padw padw
            # => [SERIAL_NUM = 0, EMPTY_WORD, NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, pad(16)]

            # compute the note's recipient, inserting the recipient preimages into the advice map
            # so the custom policy can recover the script root and storage commitment
            adv.insert_hdword exec.poseidon2::merge
            adv.insert_hdword exec.poseidon2::merge
            adv.insert_hdword exec.poseidon2::merge
            # => [RECIPIENT, pad(16)]

            # place the timeframe and priority in their parameter slots; the zeros in between
            # serve as the assets and attachments commitments
            push.{priority} push.{timeframe} movdn.13 movdn.13
            # => [RECIPIENT, ASSETS_COMMITMENT = 0, ATTACHMENTS_COMMITMENT = 0, timeframe,
            #     priority, pad(8)]

            # push the estimate_note_fee procedure root and the foreign account ID
            push.{estimate_note_fee_root}
            push.{foreign_prefix} push.{foreign_suffix}
            # => [foreign_account_id_suffix, foreign_account_id_prefix, FOREIGN_PROC_ROOT,
            #     RECIPIENT, ASSETS_COMMITMENT = 0, ATTACHMENTS_COMMITMENT = 0, timeframe,
            #     priority, pad(8)]

            exec.tx::execute_foreign_procedure
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(14)]

            push.{expected_fee_asset_id}
            assert_eqw.err="estimate_note_fee should return the manager's fee asset ID"
            # => [FEE_ASSET_VALUE, pad(12)]

            push.{expected_fee_value}
            assert_eqw.err="custom fee policy should charge the amount derived from the storage commitment, timeframe, and priority"
            # => [pad(16)]
        end
        "#,
        note_script_root = NoteScriptRoot::from_array([9, 9, 9, 9]).as_word(),
        estimate_note_fee_root = AuthNetworkAccount::estimate_note_fee_root().mast_root(),
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        expected_fee_asset_id = AssetId::new_fungible(fee_faucet_id()?).to_word(),
        expected_fee_value =
            AssetAmount::new(custom_fee_amount_for(storage_commitment, timeframe, priority))?
                .to_word(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(foreign_account.id())?;

    mock_chain
        .build_transaction(native_account.id())
        .foreign_accounts([foreign_account_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Tests that `get_fee_policy` returns the active fee policy root the manager was configured with.
#[tokio::test]
async fn get_fee_policy_returns_active_policy_root_via_note() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    // The active policy is the constant fee policy the manager is built with.
    let get_policy_note_script =
        create_get_fee_policy_note_script(ConstantFeePolicy::root().as_word());
    let mut rng = RandomCoin::new([Felt::from(602u32); 4].into());
    let get_policy_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(get_policy_note_script)
        .build()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(get_policy_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(get_policy_note.id())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// `FeePolicyManager::get_fee_asset_id`, invoked via FPI, returns the fee asset ID the manager was
/// configured with. A wrong result aborts the transaction, so successful execution proves the
/// returned fee asset ID.
#[tokio::test]
async fn get_fee_asset_id_returns_configured_fee_asset_via_fpi() -> anyhow::Result<()> {
    let foreign_account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_policy_manager_with_storage(fee_policy_manager()?)?)
        .build_existing()?;

    let native_account = AccountBuilder::new([2; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    let tx_script_code = format!(
        r#"
        use miden::protocol::tx
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            # push the get_fee_asset_id procedure root and the foreign account ID
            procref.fee_manager::get_fee_asset_id
            push.{foreign_prefix} push.{foreign_suffix}
            # => [foreign_account_id_suffix, foreign_account_id_prefix, FOREIGN_PROC_ROOT, pad(16)]

            exec.tx::execute_foreign_procedure
            # => [FEE_ASSET_ID, pad(12)]

            push.{expected_fee_asset_id}
            assert_eqw.err="get_fee_asset_id should return the configured fee asset ID"
            # => [pad(16)]
        end
        "#,
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        expected_fee_asset_id = AssetId::new_fungible(fee_faucet_id()?).to_word(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(foreign_account.id())?;

    mock_chain
        .build_transaction(native_account.id())
        .foreign_accounts([foreign_account_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// The owner mutates the allowed-policies map after deployment, and a follow-up `set_fee_policy` to
/// the mutated root reflects the change: an added root becomes switchable, while a removed root can
/// no longer be switched to (`ERR_FEE_POLICY_ROOT_NOT_ALLOWED`). This proves the allowlist can be
/// both extended and narrowed post-deployment.
///
/// - `add`: `FeeManager::get_fee_policy_root` is a procedure of the account but not in the initial
///   allowlist, so `set_fee_policy` rejects it before the add and accepts it after.
/// - `remove`: the reserved `custom_fee_policy` root is allowlisted at deployment, so
///   `set_fee_policy` accepts it before the remove and rejects it after.
#[rstest]
#[case::add("add_allowed_fee_policy", AuthNetworkAccount::get_fee_policy_root().as_word(), None)]
#[case::remove(
    "remove_allowed_fee_policy",
    custom_fee_policy().unwrap().root().as_word(),
    Some(ERR_FEE_POLICY_ROOT_NOT_ALLOWED)
)]
#[tokio::test]
async fn owner_can_mutate_allowed_fee_policy_roots(
    #[case] mutator_proc: &str,
    #[case] target_root: Word,
    #[case] set_fee_policy_error: Option<MasmError>,
) -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    let mutation_note = build_sender_note(
        owner_account_id,
        700,
        &create_fee_manager_note_script(mutator_proc, target_root),
    )?;
    let set_note = build_sender_note(
        owner_account_id,
        701,
        &create_fee_manager_note_script("set_fee_policy", target_root),
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(mutation_note.clone()));
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Apply the allowlist mutation; it takes effect from the next block.
    consume_note(&mut mock_chain, account.id(), &mutation_note).await?;

    // Switching to the mutated root now behaves per the mutation: an added root is accepted, a
    // removed root aborts with `ERR_FEE_POLICY_ROOT_NOT_ALLOWED`.
    let source_manager = Arc::new(DefaultSourceManager::default());
    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(set_note.id())
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    match set_fee_policy_error {
        None => {
            result?;
        },
        Some(expected) => assert_transaction_executor_error!(result, expected),
    }

    Ok(())
}

/// A non-owner cannot mutate the allowed-policies map: `add_allowed_fee_policy` is gated by the
/// account-wide `Authority`, which rejects a note sent by anyone other than the owner.
#[tokio::test]
async fn non_owner_cannot_add_allowed_fee_policy_root() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);
    let non_owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([5; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    let new_root = AuthNetworkAccount::get_fee_policy_root().as_word();
    let add_note = build_sender_note(
        non_owner_account_id,
        702,
        &create_fee_manager_note_script("add_allowed_fee_policy", new_root),
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(add_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(add_note.id())
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

/// The active fee policy's root cannot be removed from the allowed-policies map:
/// `remove_allowed_fee_policy` aborts with `ERR_FEE_POLICY_ROOT_IS_ACTIVE`, so the active policy's
/// root always stays allowlisted.
#[tokio::test]
async fn removing_active_policy_root_is_rejected() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    // The active policy is the `ConstantFeePolicy`; its root is registered in the allowlist at
    // deployment.
    let active_root = ConstantFeePolicy::root().as_word();

    let remove_note = build_sender_note(
        owner_account_id,
        720,
        &create_fee_manager_note_script("remove_allowed_fee_policy", active_root),
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(remove_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Consuming the note that tries to remove the active policy's root aborts.
    let source_manager = Arc::new(DefaultSourceManager::default());
    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(remove_note.id())
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_POLICY_ROOT_IS_ACTIVE);

    Ok(())
}

// FEE POLICY MANAGER CONFIG NOTE
// ================================================================================================

/// Builds a standardized `FeePolicyManagerConfigNote` triggering `action` on `account`, sent by
/// `sender` and seeded from `serial_seed`.
fn build_config_note(
    sender: AccountId,
    account: AccountId,
    action: FeePolicyManagerConfig,
    serial_seed: u32,
) -> anyhow::Result<Note> {
    let note = FeePolicyManagerConfigNote::builder()
        .sender(sender)
        .account(account)
        .action(action)
        .serial_number(Word::from([serial_seed, 0, 0, 0]))
        .build()?;
    Ok(Note::from(note))
}

/// The standardized `FeePolicyManagerConfigNote` drives `add_allowed_fee_policy`: after the owner
/// consumes an `AddAllowedFeePolicy` note, `set_fee_policy` accepts the newly allowed root.
#[tokio::test]
async fn config_note_adds_allowed_fee_policy_root() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    // A procedure of the account that is not in the initial fee policy allowlist.
    let new_root = AuthNetworkAccount::get_fee_policy_root();

    let add_note = build_config_note(
        owner_account_id,
        account.id(),
        FeePolicyManagerConfig::AddAllowedFeePolicy { policy_root: new_root },
        800,
    )?;
    let set_note = build_sender_note(
        owner_account_id,
        801,
        &create_fee_manager_note_script("set_fee_policy", new_root.as_word()),
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(add_note.clone()));
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Register the new root via the config note; the mutation takes effect from the next block.
    consume_note(&mut mock_chain, account.id(), &add_note).await?;

    // With the root now allowed, `set_fee_policy` accepts it.
    consume_note(&mut mock_chain, account.id(), &set_note).await?;

    Ok(())
}

/// The standardized `FeePolicyManagerConfigNote` drives `remove_allowed_fee_policy`: after the
/// owner consumes a `RemoveAllowedFeePolicy` note, `set_fee_policy` rejects the removed root.
#[tokio::test]
async fn config_note_removes_allowed_fee_policy_root() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    // The custom policy root is registered in the allowlist at deployment by `fee_policy_manager`.
    let allowed_root = custom_fee_policy()?.root();

    let remove_note = build_config_note(
        owner_account_id,
        account.id(),
        FeePolicyManagerConfig::RemoveAllowedFeePolicy { policy_root: allowed_root },
        810,
    )?;
    let set_note = build_sender_note(
        owner_account_id,
        811,
        &create_fee_manager_note_script("set_fee_policy", allowed_root.as_word()),
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(remove_note.clone()));
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Remove the root via the config note; the mutation takes effect from the next block.
    consume_note(&mut mock_chain, account.id(), &remove_note).await?;

    // With the root no longer allowed, `set_fee_policy` rejects switching back to it.
    let source_manager = Arc::new(DefaultSourceManager::default());
    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(set_note.id())
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_POLICY_ROOT_NOT_ALLOWED);

    Ok(())
}

// FEE POLICY MANAGER CONFIG NOTE — AUTH NETWORK ACCOUNT
// ================================================================================================

/// A zero-fee `FeePolicyManager` scheduling every root in `scheduled_roots` at a 0 fee. A network
/// account prices each note it consumes through its active fee policy, and a constant policy aborts
/// fee estimation for note scripts without a schedule entry, so every consumable note root must be
/// scheduled.
fn zero_fee_policy_manager(
    scheduled_roots: impl IntoIterator<Item = NoteScriptRoot>,
) -> anyhow::Result<FeePolicyManager> {
    let mut policy = ConstantFeePolicy::new();
    for root in scheduled_roots {
        policy = policy.with_fee(root, AssetAmount::ZERO);
    }
    Ok(FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(policy.into())
        .build())
}

/// Builds an `AuthNetworkAccount` carrying the fee policy manager, gated by `owner` via
/// `AccessControl::Ownable2Step`. `allowed_note_roots` are added to the note-script allowlist (the
/// component also auto-allowlists its own config-note root); every allowlisted root plus
/// `fee_scheduled_roots` is scheduled at a 0 fee so those notes can be consumed.
fn build_network_fee_account(
    owner: AccountId,
    allowed_note_roots: Vec<NoteScriptRoot>,
    fee_scheduled_roots: Vec<NoteScriptRoot>,
) -> anyhow::Result<Account> {
    let note_roots: BTreeSet<NoteScriptRoot> = allowed_note_roots.into_iter().collect();
    let scheduled: Vec<NoteScriptRoot> =
        note_roots.iter().copied().chain(fee_scheduled_roots).collect();
    let manager = zero_fee_policy_manager(scheduled)?;
    let auth_component = AuthNetworkAccount::new(note_roots, manager)?;

    Ok(AccountBuilder::new([7; 32])
        .with_components(auth_component)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(BasicWallet)
        .account_type(AccountType::Public)
        .build_existing()?)
}

/// An `AuthNetworkAccount` whose note-script allowlist includes the `FeePolicyManagerConfig` note
/// root consumes an `AddAllowedFeePolicy` config note end-to-end: allowlist check, fee pricing, and
/// the owner-authorized `add_allowed_fee_policy` call all pass.
#[tokio::test]
async fn network_account_consumes_add_fee_policy_config_note() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let new_root = AuthNetworkAccount::get_fee_policy_root();

    let account = build_network_fee_account(
        owner_account_id,
        vec![FeePolicyManagerConfigNote::script_root()],
        vec![],
    )?;

    let add_note = build_config_note(
        owner_account_id,
        account.id(),
        FeePolicyManagerConfig::AddAllowedFeePolicy { policy_root: new_root },
        830,
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(add_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_note(&mut mock_chain, account.id(), &add_note).await?;

    Ok(())
}

/// An `AuthNetworkAccount` whose note-script allowlist does NOT include the
/// `FeePolicyManagerConfig` note root rejects the config note at the allowlist check, even when its
/// sender is the owner. The config note root is fee-scheduled here so the allowlist check - not fee
/// estimation - is what rejects it.
#[tokio::test]
async fn network_account_rejects_config_note_when_not_allowlisted() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let new_root = AuthNetworkAccount::get_fee_policy_root();

    // Allowlist an unrelated placeholder root, not the config note root.
    let placeholder = NoteScriptRoot::from_array([1, 0, 0, 0]);
    let account = build_network_fee_account(
        owner_account_id,
        vec![placeholder],
        vec![FeePolicyManagerConfigNote::script_root()],
    )?;

    let add_note = build_config_note(
        owner_account_id,
        account.id(),
        FeePolicyManagerConfig::AddAllowedFeePolicy { policy_root: new_root },
        840,
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(add_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(add_note.id())
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);

    Ok(())
}
