extern crate alloc;

use alloc::sync::Arc;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::note::{NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::fees::{ConstantFeePolicy, FeeManager, FeePolicy};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{ERR_FEE_POLICY_ROOT_NOT_ALLOWED, ERR_SENDER_NOT_OWNER};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use rstest::rstest;

// HELPERS
// ================================================================================================

/// The fee scheduled for [`priced_root`] in these tests.
const FEE_AMOUNT: u64 = 500;

fn fee_faucet_id() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?)
}

/// The note script root priced in the fee schedule of the constant fee policy.
fn priced_root() -> NoteScriptRoot {
    NoteScriptRoot::from_array([1, 2, 3, 4])
}

/// Builds a `FeeManager` whose active policy is a `ConstantFeePolicy` charging [`FEE_AMOUNT`]
/// (in the test faucet's asset) for notes with the [`priced_root`] script root, and whose
/// allowed-policies map additionally registers the user-defined [`custom_fee_policy`] for
/// runtime switching.
fn fee_manager() -> anyhow::Result<FeeManager> {
    let constant_fee_policy = ConstantFeePolicy::new(fee_faucet_id()?)
        .with_fee(priced_root(), AssetAmount::new(FEE_AMOUNT)?);
    Ok(FeeManager::builder()
        .active_fee_policy(FeePolicy::constant(constant_fee_policy))
        .allowed_fee_policy(custom_fee_policy()?)
        .build())
}

/// The fee charged by the user-defined test policy in [`custom_fee_policy`].
const CUSTOM_FEE_AMOUNT: u64 = 777;

/// The namespace under which the user-defined test policy is compiled.
const CUSTOM_FEE_POLICY_NAME: &str = "test::fees::storage_commitment_fee";

/// Builds a user-defined fee policy component, mirroring how a contract developer would plug
/// their own fee computation logic into the `FeeManager` via [`FeePolicy::custom`].
///
/// The policy charges [`CUSTOM_FEE_AMOUNT`] in an "asset" identified by the note's
/// STORAGE_COMMITMENT. Pricing on a parameter other than NOTE_SCRIPT_ROOT proves that the
/// manager forwards the full note parameter set to the policy implementation.
fn custom_fee_policy() -> anyhow::Result<FeePolicy> {
    let masm_source = format!(
        r#"
        #! Fee policy charging a fixed amount in an asset identified by the note's storage
        #! commitment.
        #!
        #! Inputs:  [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT]
        #! Outputs: [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]
        #!
        #! Invocation: call
        @account_procedure
        pub proc compute_note_fee
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

/// Returns the asset value word `[fee_amount, 0, 0, 0]` for the given amount.
fn fee_value_word(amount: u64) -> anyhow::Result<Word> {
    Ok(Word::new([
        AssetAmount::new(amount)?.into(),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ]))
}

/// Builds an account exposing the fee manager procedures, owned by `owner` via `Ownable2Step`
/// with an owner-controlled `Authority` so the owner-gated `set_fee_policy` can be exercised.
fn build_fee_account_with_switching(owner: AccountId) -> anyhow::Result<Account> {
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
/// the zeros below it serve as the remaining note parameters, forming the full 16-felt
/// `estimate_note_fee` inputs. A wrong result aborts the transaction, so successful execution
/// proves the returned fee asset.
fn estimate_note_fee_tx_script_code(
    expected_fee_asset_id: Word,
    expected_fee_value: Word,
) -> String {
    format!(
        r#"
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            # => [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT]
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
fn create_set_fee_policy_note_script(policy_root: Word) -> String {
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
/// scheduled for the queried note script root. Roots without a schedule entry estimate to an
/// amount of 0.
#[rstest]
#[case::priced_root(priced_root(), FEE_AMOUNT)]
#[case::unknown_root(NoteScriptRoot::from_array([5, 6, 7, 8]), 0)]
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

    let tx_script_code = estimate_note_fee_tx_script_code(
        AssetId::new_fungible(fee_faucet_id()?).to_word(),
        fee_value_word(expected_amount)?,
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

    // The tx script argument supplies NOTE_SCRIPT_ROOT (arbitrary here - the custom policy
    // ignores it) on top of the initial operand stack; STORAGE_COMMITMENT is placed below it,
    // and the remaining zeros serve as the other note parameters.
    let tx_script_code = format!(
        r#"
        use miden::protocol::tx

        @transaction_script
        pub proc main
            # => [NOTE_SCRIPT_ROOT, pad(12)]

            # place STORAGE_COMMITMENT below NOTE_SCRIPT_ROOT
            push.{storage_commitment} swapw
            # => [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, pad(12)]

            # push the estimate_note_fee procedure root and the foreign account ID
            push.{estimate_note_fee_root}
            push.{foreign_prefix} push.{foreign_suffix}
            # => [foreign_account_id_suffix, foreign_account_id_prefix, FOREIGN_PROC_ROOT,
            #     NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, pad(12)]

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
        estimate_note_fee_root = FeeManager::estimate_note_fee_root().mast_root(),
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        expected_fee_asset_id = storage_commitment,
        expected_fee_value = fee_value_word(CUSTOM_FEE_AMOUNT)?,
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(foreign_account.id())?;

    mock_chain
        .build_tx_context(native_account.id(), &[], &[])?
        .foreign_accounts([foreign_account_inputs])
        .tx_script(tx_script)
        .tx_script_args(NoteScriptRoot::from_array([9, 9, 9, 9]).as_word())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// The owner switches the active fee policy from the constant fee policy to the user-defined
/// custom policy via `set_fee_policy`, after which `estimate_note_fee` prices the previously
/// priced root with the custom policy's logic instead of the schedule.
#[tokio::test]
async fn set_fee_policy_switches_to_custom_policy() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    let set_policy_note_script =
        create_set_fee_policy_note_script(custom_fee_policy()?.root().as_word());
    let mut rng = RandomCoin::new([Felt::from(600u32); 4].into());
    let set_policy_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(set_policy_note_script.as_str())
        .build()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_policy_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_context = mock_chain
        .build_tx_context(account.id(), &[set_policy_note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let executed_transaction = tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // With the custom policy active, the previously priced root is priced by the custom logic:
    // the fee asset ID echoes STORAGE_COMMITMENT (all zeros in this script) and the amount is
    // the fixed custom fee.
    let tx_script_code =
        estimate_note_fee_tx_script_code(Word::empty(), fee_value_word(CUSTOM_FEE_AMOUNT)?);
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(priced_root().as_word())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// `set_fee_policy` rejects policy roots outside the allowed policy roots map, even if the root
/// is a procedure of the account.
#[tokio::test]
async fn set_fee_policy_rejects_non_allowed_root() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    // This root exists in the account code, but is not in the fee policy allowlist.
    let invalid_policy_root = FeeManager::get_fee_policy_root().as_word();
    let set_policy_note_script = create_set_fee_policy_note_script(invalid_policy_root);
    let mut rng = RandomCoin::new([Felt::from(601u32); 4].into());
    let set_policy_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(set_policy_note_script.as_str())
        .build()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_policy_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let result = mock_chain
        .build_tx_context(account.id(), &[set_policy_note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_POLICY_ROOT_NOT_ALLOWED);

    Ok(())
}

/// A non-owner cannot switch the active fee policy via `set_fee_policy`.
#[tokio::test]
async fn non_owner_cannot_set_fee_policy() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);
    let non_owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([5; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    let set_policy_note_script =
        create_set_fee_policy_note_script(custom_fee_policy()?.root().as_word());
    let mut rng = RandomCoin::new([Felt::from(602u32); 4].into());
    let set_policy_note = NoteBuilder::new(non_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(set_policy_note_script.as_str())
        .build()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_policy_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let result = mock_chain
        .build_tx_context(account.id(), &[set_policy_note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}
