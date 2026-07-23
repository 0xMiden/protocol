use alloc::sync::Arc;

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
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::fees::{ConstantFeePolicy, FeeManager, FeePolicy};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_POLICY_ROOT_NOT_ALLOWED,
    ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE,
    ERR_SENDER_NOT_OWNER,
    ERR_TIMEFRAME_OR_PRIORITY_NOT_U32,
};
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

/// Builds a `FeeManager` whose active policy is a `ConstantFeePolicy` charging [`FEE_AMOUNT`]
/// (in the test faucet's asset) for notes with the [`priced_root`] script root and an explicit
/// 0 fee for the [`free_root`] script root, and whose allowed-policies map additionally
/// registers the user-defined [`custom_fee_policy`] for runtime switching.
fn fee_manager() -> anyhow::Result<FeeManager> {
    let constant_fee_policy = ConstantFeePolicy::new()
        .with_fee(priced_root(), AssetAmount::new(FEE_AMOUNT)?)
        .with_fee(free_root(), AssetAmount::ZERO);
    Ok(FeeManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(constant_fee_policy.into())
        .allowed_fee_policy(custom_fee_policy()?)
        .build())
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
/// their own fee computation logic into the `FeeManager` via [`FeePolicy::custom`].
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
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_manager()?)
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
    let fee_manager = FeeManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(custom_fee_policy()?)
        .build();

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
        estimate_note_fee_root = FeeManager::estimate_note_fee_root().mast_root(),
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

/// `FeeManager::get_fee_asset_id`, invoked via FPI, returns the fee asset ID the manager was
/// configured with. A wrong result aborts the transaction, so successful execution proves the
/// returned fee asset ID.
#[tokio::test]
async fn get_fee_asset_id_returns_configured_fee_asset_via_fpi() -> anyhow::Result<()> {
    let foreign_account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_manager()?)
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

    let tx_script_code = format!(
        r#"
        use miden::protocol::tx

        @transaction_script
        pub proc main
            # => [pad(16)]

            # push the get_fee_asset_id procedure root and the foreign account ID
            push.{get_fee_asset_id_root}
            push.{foreign_prefix} push.{foreign_suffix}
            # => [foreign_account_id_suffix, foreign_account_id_prefix, FOREIGN_PROC_ROOT, pad(16)]

            exec.tx::execute_foreign_procedure
            # => [FEE_ASSET_ID, pad(12)]

            push.{expected_fee_asset_id}
            assert_eqw.err="get_fee_asset_id should return the configured fee asset ID"
            # => [pad(16)]
        end
        "#,
        get_fee_asset_id_root = FeeManager::get_fee_asset_id_root().mast_root(),
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
#[case::add("add_allowed_fee_policy", FeeManager::get_fee_policy_root().as_word(), None)]
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

    let new_root = FeeManager::get_fee_policy_root().as_word();
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

/// Removing the active fee policy's root from the allowed-policies map does not disable it for fee
/// estimation: `estimate_note_fee` reads the active policy root directly from its slot, not the
/// allowlist, so estimation still returns the scheduled fee after the active root is removed.
/// (Removal only prevents switching *back* to the root via `set_fee_policy`.)
#[tokio::test]
async fn removing_active_policy_root_does_not_disable_estimation() -> anyhow::Result<()> {
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

    // Remove the active policy's root from the allowlist; the mutation takes effect from the next
    // block.
    consume_note(&mut mock_chain, account.id(), &remove_note).await?;

    // Estimation still returns the scheduled fee for `priced_root`: the active policy remains in
    // use for fee estimation even though its root is no longer allowlisted.
    let tx_script_code = estimate_note_fee_tx_script_code(
        Word::empty(),
        11,
        7,
        AssetId::new_fungible(fee_faucet_id()?).to_word(),
        AssetAmount::new(FEE_AMOUNT)?.to_word(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .tx_script_args(priced_root().as_word())
        .build()?
        .execute()
        .await?;

    Ok(())
}
