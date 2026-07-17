use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::fees::{ConstantFeePolicy, FeeManager, FeePolicy};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain, MockChainBuilder};
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

/// Builds a `FeeManager` whose active policy is a `ConstantFeePolicy` charging [`FEE_AMOUNT`]
/// (in the test faucet's asset) for notes with the [`priced_root`] script root, and whose
/// allowed-policies map additionally registers the user-defined [`custom_fee_policy`] for
/// runtime switching.
fn fee_manager() -> anyhow::Result<FeeManager> {
    let constant_fee_policy = ConstantFeePolicy::new(fee_faucet_id()?)
        .with_fee(priced_root(), AssetAmount::new(FEE_AMOUNT)?);
    Ok(FeeManager::builder()
        .active_fee_policy(constant_fee_policy.into())
        .allowed_fee_policy(custom_fee_policy()?)
        .build())
}

/// The base fee charged by the user-defined test policy in [`custom_fee_policy`].
pub(super) const CUSTOM_FEE_AMOUNT: u64 = 777;

/// The fee the user-defined test policy in [`custom_fee_policy`] charges for the given timeframe
/// and priority. The distinct weights make a transposition of the two parameters detectable.
pub(super) fn custom_fee_amount_for(timeframe: u32, priority: u32) -> u64 {
    CUSTOM_FEE_AMOUNT + 2 * u64::from(timeframe) + u64::from(priority)
}

/// The namespace under which the user-defined test policy is compiled.
const CUSTOM_FEE_POLICY_NAME: &str = "test::fees::storage_commitment_fee";

/// Builds a user-defined fee policy component, mirroring how a contract developer would plug
/// their own fee computation logic into the `FeeManager` via [`FeePolicy::custom`].
///
/// The policy charges [`custom_fee_amount_for`] the note's timeframe and priority in an "asset"
/// identified by the note's STORAGE_COMMITMENT, recovered from RECIPIENT via the advice provider.
/// Pricing on parameters other than the note's script root - with distinct weights on timeframe
/// and priority - proves that the manager forwards the full note parameter set, slot by slot, to
/// the policy implementation.
pub(super) fn custom_fee_policy() -> anyhow::Result<FeePolicy> {
    let masm_source = format!(
        r#"
        use miden::standards::note

        use {{Asset, NoteRecipient}} from miden::protocol::types

        #! Fee policy charging a fixed amount plus twice the timeframe plus the priority, in an
        #! asset identified by the note's storage commitment, recovered from the recipient via the
        #! advice provider.
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

            # keep STORAGE_COMMITMENT as the fee asset ID and the timeframe and priority as
            # pricing inputs, dropping the other note parameters
            dropw swapw dropw swapw dropw
            # => [STORAGE_COMMITMENT, timeframe, priority, pad(10)]

            # charge the base amount plus twice the timeframe plus the priority
            movup.4 mul.2 movup.5 add push.{CUSTOM_FEE_AMOUNT} add
            # => [fee_amount, STORAGE_COMMITMENT, pad(11)]

            push.0.0.0 movup.3
            # => [FEE_ASSET_VALUE, STORAGE_COMMITMENT, pad(11)]

            swapw
            # => [STORAGE_COMMITMENT, FEE_ASSET_VALUE, pad(11)]

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
    timeframe: u32,
    priority: u32,
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
            #     priority, pad(2)]

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

    // Distinct non-zero timeframe and priority prove the parameters reach the policy slot by
    // slot.
    let timeframe = 40u32;
    let priority = 9u32;

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
            #     priority, pad(2), pad(4)]

            # push the estimate_note_fee procedure root and the foreign account ID
            push.{estimate_note_fee_root}
            push.{foreign_prefix} push.{foreign_suffix}
            # => [foreign_account_id_suffix, foreign_account_id_prefix, FOREIGN_PROC_ROOT,
            #     RECIPIENT, ASSETS_COMMITMENT = 0, ATTACHMENTS_COMMITMENT = 0, timeframe,
            #     priority, pad(2), pad(4)]

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
        expected_fee_value =
            AssetAmount::new(custom_fee_amount_for(timeframe, priority))?.to_word(),
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
