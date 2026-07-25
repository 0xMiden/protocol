use alloc::sync::Arc;
use std::collections::BTreeSet;

use miden_processor::ExecutionError;
use miden_processor::crypto::random::RandomCoin;
use miden_processor::operation::OperationError;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{AssetAmount, AssetId, FungibleAsset};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::transaction::{RawOutputNote, TransactionScriptRoot};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicy, FeePolicyManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_POLICY_ROOT_IS_ACTIVE,
    ERR_FEE_POLICY_ROOT_NOT_ALLOWED,
    ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE,
    ERR_SENDER_NOT_OWNER,
    ERR_TIMEFRAME_OR_PRIORITY_NOT_U32,
};
use miden_standards::note::FeeSponsorshipNote;
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

/// The note script root priced in the fee schedule of the basic constant fee policy.
pub(super) fn priced_root() -> NoteScriptRoot {
    NoteScriptRoot::from_array([1, 2, 3, 4])
}

/// The note script root scheduled with an explicit 0 fee in the basic constant fee policy.
fn free_root() -> NoteScriptRoot {
    NoteScriptRoot::from_array([5, 6, 7, 8])
}

/// Builds a `FeePolicyManager` whose active policy is a `BasicConstantFeePolicy` charging
/// [`FEE_AMOUNT`] (in the test faucet's asset) for notes with the [`priced_root`] script root and
/// an explicit 0 fee for the [`free_root`] script root, and whose allowed-policies map additionally
/// registers the user-defined [`custom_fee_policy`] for runtime switching.
///
/// Each root in `zero_fee_note_roots` is additionally scheduled at a 0 fee.
fn fee_policy_manager(
    zero_fee_note_roots: &BTreeSet<NoteScriptRoot>,
) -> anyhow::Result<FeePolicyManager> {
    let mut basic_constant_fee_policy = BasicConstantFeePolicy::new()
        .with_fee(priced_root(), AssetAmount::new(FEE_AMOUNT)?)
        .with_fee(free_root(), AssetAmount::ZERO);
    for note_root in zero_fee_note_roots {
        basic_constant_fee_policy =
            basic_constant_fee_policy.with_fee(*note_root, AssetAmount::ZERO);
    }

    Ok(FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(basic_constant_fee_policy.into())
        .allowed_fee_policy(custom_fee_policy()?)
        .build())
}

/// The base fee charged by the user-defined test policy in [`custom_fee_policy`].
pub(super) const CUSTOM_FEE_AMOUNT: u64 = 777;

/// The fee the user-defined test policy in [`custom_fee_policy`] charges for the given storage
/// commitment, timeframe, and priority. The distinct timeframe and priority weights make a
/// transposition of the two parameters detectable; the storage-commitment term proves the
/// policy recovered the commitment from the recipient.
///
/// The commitment elements are field-summed and reduced to their low 32 bits, keeping the fee
/// within a valid asset amount for any (hash-derived) commitment.
pub(super) fn custom_fee_amount_for(
    storage_commitment: Word,
    timeframe: u64,
    priority: u64,
) -> AssetAmount {
    let elements = storage_commitment.as_elements();
    let commitment_sum = elements[0] + elements[1] + elements[2] + elements[3];
    let commitment_term = commitment_sum.as_canonical_u64() & u64::from(u32::MAX);
    let amount = CUSTOM_FEE_AMOUNT + 2 * timeframe + priority + commitment_term;
    AssetAmount::new(amount).expect("custom fee amount should not exceed the maximum asset amount")
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
        #! low 32 bits of the sum of the storage commitment elements, in the fee asset the manager
        #! is configured with. The commitment term is bounded so the fee is always a valid asset
        #! amount.
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

            # drop the script root and reduce the storage commitment to the low 32 bits of the sum
            # of its elements. The commitment's raw sum could exceed a valid asset amount so we
            # take the the low 32 bits.
            dropw add add add u32split swap drop
            # => [storage_commitment_term, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe,
            #     priority, pad(2)]

            # drop the remaining note parameters
            movdn.8 dropw dropw
            # => [storage_commitment_term, timeframe, priority, pad(10)]

            # charge the base amount plus twice the timeframe plus the priority plus the bounded
            # storage commitment term
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

/// Builds an `AuthNetworkAccount`-authenticated account exposing the fee policy manager procedures,
/// owned by `owner` via `Ownable2Step` with an owner-controlled `Authority` so the owner-gated
/// `set_fee_policy` can be exercised.
///
/// `allowed_note_roots` and `allowed_tx_script_roots` seed the network-auth allowlists, so callers
/// must register the roots of any note they consume or transaction script they run against the
/// account (the auth procedure rejects a transaction touching a non-allowlisted root).
pub(super) fn build_fee_account_with_switching(
    owner: AccountId,
    allowed_note_roots: BTreeSet<NoteScriptRoot>,
    allowed_tx_script_roots: BTreeSet<TransactionScriptRoot>,
) -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            fee_policy_manager: fee_policy_manager(&allowed_note_roots)?,
            allowed_script_roots: allowed_note_roots,
            allowed_tx_script_roots,
        })
        .with_component(BasicWallet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
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

// TESTS
// ================================================================================================

/// `FeePolicyManager::estimate_note_fee`, invoked via `call` from a transaction script, dispatches
/// to the active `BasicConstantFeePolicy` and returns the policy's fee asset ID and the fee amount
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
    // The basic constant fee policy ignores the storage commitment, timeframe, and priority, so an
    // all-zero commitment and arbitrary non-zero timeframe and priority are passed.
    let tx_script_code = estimate_note_fee_tx_script_code(
        Word::empty(),
        11,
        7,
        AssetId::new_fungible(fee_faucet_id()?).to_word(),
        AssetAmount::new(expected_amount)?.to_word(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let mut builder = MockChain::builder();
    let sender = builder.add_existing_wallet(Auth::IncrNonce)?;

    // A note-less query transaction would be rejected as an empty no-op, so the account consumes a
    // note. Its root is allowlisted and scheduled at a 0 fee so the auth procedure's fee collection
    // stays a no-op.
    let consumed_note = builder.add_p2any_note(sender.id(), NoteType::Public, [])?;
    let consumed_root = consumed_note.script().root();

    // The network auth procedure runs after the tx script and rejects any non-allowlisted tx script
    // or input note, so allowlist both the estimate script and the consumed note.
    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::from([consumed_root]),
            allowed_tx_script_roots: BTreeSet::from([tx_script.root()]),
            fee_policy_manager: fee_policy_manager(&BTreeSet::from([consumed_root]))?,
        })
        .with_component(BasicWallet)
        .build_existing()?;

    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(consumed_note.id())
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
    // The expected fee asset is irrelevant since the call aborts before the assertions.
    let tx_script_code = estimate_note_fee_tx_script_code(
        Word::empty(),
        timeframe,
        priority,
        Word::empty(),
        Word::empty(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::new(),
            allowed_tx_script_roots: BTreeSet::from([tx_script.root()]),
            fee_policy_manager: fee_policy_manager(&BTreeSet::new())?,
        })
        .with_component(BasicWallet)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

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
/// `BasicConstantFeePolicy`'s fee schedule, rather than estimating unpriced note scripts to a fee
/// of 0.
#[tokio::test]
async fn estimate_note_fee_aborts_for_unscheduled_root() -> anyhow::Result<()> {
    // The expected fee asset words are irrelevant: execution aborts in `compute_note_fee`
    // before the tx script's assertions are reached.
    let tx_script_code =
        estimate_note_fee_tx_script_code(Word::empty(), 0, 0, Word::empty(), Word::empty());
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::new(),
            allowed_tx_script_roots: BTreeSet::from([tx_script.root()]),
            fee_policy_manager: fee_policy_manager(&BTreeSet::new())?,
        })
        .with_component(BasicWallet)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

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

    // The foreign account's auth never runs under FPI, so its allowlists can stay empty.
    let foreign_account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::new(),
            allowed_tx_script_roots: BTreeSet::new(),
            fee_policy_manager,
        })
        .with_component(BasicWallet)
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
            custom_fee_amount_for(storage_commitment, timeframe, priority).to_word(),
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

    // The active policy is the basic constant fee policy the manager is built with.
    let get_policy_note_script =
        create_get_fee_policy_note_script(BasicConstantFeePolicy::root().as_word());
    let mut rng = RandomCoin::new([Felt::from(602u32); 4].into());
    let get_policy_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(get_policy_note_script)
        .build()?;

    // The account only consumes the get-policy note, so allowlist just its script root (the auth
    // procedure also prices it, which the helper schedules at a 0 fee).
    let account = build_fee_account_with_switching(
        owner_account_id,
        BTreeSet::from([get_policy_note.script().root()]),
        BTreeSet::new(),
    )?;

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
    // The foreign account's auth never runs under FPI, so its allowlists can stay empty.
    let foreign_account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::new(),
            allowed_tx_script_roots: BTreeSet::new(),
            fee_policy_manager: fee_policy_manager(&BTreeSet::new())?,
        })
        .with_component(BasicWallet)
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

/// Builds the owner-gated network account for [`owner_can_mutate_allowed_fee_policy_roots`],
/// scheduling each root in `allowed_note_roots` at a 0 fee.
///
/// When `custom_policy_allowed` is set, [`custom_fee_policy`] starts in the allowed-policies map.
/// Otherwise it is left off the initial allowlist but its component is still installed, so it only
/// becomes switchable once the owner adds its root at runtime. That test needs both starting states
/// so it can exercise a meaningful add (root starts disallowed) and remove (root starts allowed);
/// it therefore builds its account here rather than through [`build_fee_account_with_switching`],
/// which always registers the custom policy.
fn build_mutation_test_account(
    owner: AccountId,
    allowed_note_roots: BTreeSet<NoteScriptRoot>,
    custom_policy_allowed: bool,
) -> anyhow::Result<Account> {
    let mut basic_constant_fee_policy = BasicConstantFeePolicy::new()
        .with_fee(priced_root(), AssetAmount::new(FEE_AMOUNT)?)
        .with_fee(free_root(), AssetAmount::ZERO);
    for note_root in &allowed_note_roots {
        basic_constant_fee_policy =
            basic_constant_fee_policy.with_fee(*note_root, AssetAmount::ZERO);
    }

    let mut manager_builder = FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(basic_constant_fee_policy.into());
    if custom_policy_allowed {
        manager_builder = manager_builder.allowed_fee_policy(custom_fee_policy()?);
    }

    let mut account_builder = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            fee_policy_manager: manager_builder.build(),
            allowed_script_roots: allowed_note_roots,
            allowed_tx_script_roots: BTreeSet::new(),
        })
        .with_component(BasicWallet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled);

    // The manager only installs components for the policies it registers, so when the custom policy
    // is left off the initial allowlist its component must be installed separately to keep it
    // dispatchable once the owner adds its root at runtime.
    if !custom_policy_allowed {
        for component in custom_fee_policy()? {
            account_builder = account_builder.with_component(component);
        }
    }

    Ok(account_builder.build_existing()?)
}

/// The owner mutates the allowed-policies map after deployment, then a follow-up transaction whose
/// note switches the active policy to the `custom_fee_policy` root observes the mutation. Each case
/// starts from the initial allowlist state that makes its mutation meaningful.
///
/// - `add`: the custom policy starts off the allowlist, so `add_allowed_fee_policy` is what makes
///   it switchable. Switching then succeeds; the network auth procedure prices the switch note
///   through the now-active custom policy, so the note is paired with a FEE_SPONSORSHIP note
///   covering that fee and the transaction succeeds.
/// - `remove`: the custom policy starts on the allowlist, so `remove_allowed_fee_policy` is what
///   makes it non-switchable. Switching then is rejected with `ERR_FEE_POLICY_ROOT_NOT_ALLOWED`
///   before fee collection, leaving the sponsorship note unused.
#[rstest]
#[case::add(
    "add_allowed_fee_policy",
    custom_fee_policy().unwrap().root().as_word(),
    false,
    None
)]
#[case::remove(
    "remove_allowed_fee_policy",
    custom_fee_policy().unwrap().root().as_word(),
    true,
    Some(ERR_FEE_POLICY_ROOT_NOT_ALLOWED)
)]
#[tokio::test]
async fn owner_can_mutate_allowed_fee_policy_roots(
    #[case] mutator_proc: &str,
    #[case] target_root: Word,
    #[case] custom_policy_initially_allowed: bool,
    #[case] set_fee_policy_error: Option<MasmError>,
) -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

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

    // The account consumes the mutation note, the switch note, and the switch note's sponsorship
    // note, so allowlist all three roots. The helper schedules the mutation and switch note roots
    // at a 0 fee, so the still-active constant policy prices them for free.
    let account = build_mutation_test_account(
        owner_account_id,
        BTreeSet::from([
            mutation_note.script().root(),
            set_note.script().root(),
            FeeSponsorshipNote::script_root(),
        ]),
        custom_policy_initially_allowed,
    )?;

    // In the `add` case the switch note activates the custom policy, which fee collection then
    // prices the switch note through (on its storage commitment, with a timeframe and priority
    // of 0), so pair it with a sponsorship note covering exactly that fee. The `remove` case
    // aborts in the switch note's script before fee collection, leaving the sponsorship note
    // unused.
    let custom_fee = custom_fee_amount_for(set_note.recipient().storage().commitment(), 0, 0);
    let sponsorship_note = Note::from(
        FeeSponsorshipNote::builder()
            .sender(owner_account_id)
            .target_account(account.id())
            .feature_note_id(set_note.id())
            .asset(FungibleAsset::new(fee_faucet_id()?, custom_fee.as_u64())?)
            .serial_number(Word::from([1, 2, 3, 4u32]))
            .build()?,
    );

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(mutation_note.clone()));
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Apply the allowlist mutation; it takes effect from the next block. The mutation note is
    // priced by the still-active constant policy at 0, so it needs no sponsorship.
    let executed_transaction = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(mutation_note.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // Switch to the mutated root, consuming the switch note followed immediately by its sponsorship
    // note. In the `add` case the switch succeeds and fee collection prices the switch note through
    // the now-active custom policy, covered by the sponsorship; in the `remove` case the switch
    // note aborts with `ERR_FEE_POLICY_ROOT_NOT_ALLOWED`.
    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(set_note.id())
        .authenticated_input_note(sponsorship_note.id())
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

    let new_root = AuthNetworkAccount::get_fee_policy_root().as_word();
    let add_note = build_sender_note(
        non_owner_account_id,
        702,
        &create_fee_manager_note_script("add_allowed_fee_policy", new_root),
    )?;

    // Allowlist the consumed note's root so execution reaches the gated `add_allowed_fee_policy`
    // (which aborts because the sender is not the owner) instead of being rejected by the auth
    // procedure's allowlist check.
    let account = build_fee_account_with_switching(
        owner_account_id,
        BTreeSet::from([add_note.script().root()]),
        BTreeSet::new(),
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

    // The active policy is the `BasicConstantFeePolicy`; its root is registered in the allowlist at
    // deployment.
    let active_root = BasicConstantFeePolicy::root().as_word();

    let remove_note = build_sender_note(
        owner_account_id,
        720,
        &create_fee_manager_note_script("remove_allowed_fee_policy", active_root),
    )?;

    // Allowlist the consumed note's root so execution reaches the gated `remove_allowed_fee_policy`
    // (which aborts because the target is the active policy's root).
    let account = build_fee_account_with_switching(
        owner_account_id,
        BTreeSet::from([remove_note.script().root()]),
        BTreeSet::new(),
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
