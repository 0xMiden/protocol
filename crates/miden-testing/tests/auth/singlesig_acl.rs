use core::slice;
use std::collections::BTreeSet;

use assert_matches::assert_matches;
use miden_processor::ExecutionError;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    AccountStorage,
    AccountType,
    StorageMap,
    StorageMapKey,
    StorageSlot,
};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset, TokenSymbol};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::testing::storage::MOCK_VALUE_SLOT0;
use miden_protocol::transaction::{RawOutputNote, TransactionScript};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Pausable, PausableManager};
use miden_standards::account::auth::{
    AuthSingleSigAcl,
    FeeConversionInfo,
    commit_fee_conversion_info,
};
use miden_standards::account::faucets::{Description, FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{BatchFeeNote, BurnNote};
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::faucet::user_faucet_single_sig_acl;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::BasicAuthenticator;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use crate::prove_and_verify_transaction;

// TESTS
// ================================================================================================

/// The ACL exempt (no-signature) branch pays the transaction fee in the native fee asset,
/// ignoring any conversion info committed via the auth args.
///
/// With no signature over the transaction summary there is no signer to authorize a
/// caller-supplied conversion rate, so the exempt branch pays plainly in the kernel-attested
/// native fee asset at rate 1/1 (mirroring the network account component); paying (rather than
/// skipping the fee) also means exempt transactions cannot evade fees. This test runs a
/// state-changing exempt procedure (`set_item`) on a fee-charging chain with no registered
/// authenticator, supplies an inflated conversion-rate commitment via the auth args, and asserts
/// a native fee note covering the computed fee is created at rate 1/1 (the inflated rate is
/// ignored).
#[tokio::test]
async fn acl_exempt_branch_pays_native_fee_note() -> anyhow::Result<()> {
    const VERIFICATION_BASE_FEE: u32 = 500;

    let (_get_item, set_item, _account_procedure_1) = mock_component_proc_roots();

    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?;

    // `set_item` is exempt, so calling it takes the no-signature branch while still changing state
    // (making the transaction valid without requiring a signature).
    let component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();
    let (auth_component, _authenticator) = Auth::Acl {
        exempt_procedures: BTreeSet::from([set_item]),
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    }
    .build_component();

    let account = AccountBuilder::new([0; 32])
        .with_auth_component(auth_component)
        .with_component(component)
        .account_type(AccountType::Public)
        .with_assets([fee_asset.into()])
        .build_existing()?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // an inflated conversion rate that would double the paid amount if the exempt branch honored
    // the committed conversion info
    let conversion_info = FeeConversionInfo::new(fee_faucet_id, 2, 1)?;
    let (args, advice_value) =
        commit_fee_conversion_info(conversion_info, Word::from([9u32, 10, 11, 12]));

    // no authenticator is registered, so a successful execution proves the exempt (no-signature)
    // branch ran
    let executed = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(compile_call_set_item_script()?)
        .auth_args(args)
        .extend_advice_map([(args, advice_value)])
        .build()?
        .execute()
        .await?;

    // exactly one output note is created: a public BATCH_FEE note carrying the native fee asset
    assert_eq!(executed.output_notes().num_notes(), 1);
    let output_note = executed.output_notes().get_note(0);
    assert_eq!(output_note.metadata().tag(), BatchFeeNote::TAG);
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    let assets = output_note.assets();
    assert_eq!(assets.num_assets(), 1);
    let asset = assets.iter().next().expect("fee note should carry an asset");
    let Asset::Fungible(paid_asset) = asset else {
        panic!("fee note asset should be fungible");
    };
    assert_eq!(paid_asset.faucet_id(), fee_faucet_id);

    // the paid amount covers the computed fee at rate 1/1 with a bounded overshoot; the inflated
    // 2/1 rate committed via the auth args was ignored (honoring it would have doubled the
    // amount, far exceeding the bound)
    let required_fee = executed.compute_fee();
    assert!(
        paid_asset.amount() >= required_fee,
        "paid fee {} should cover the required fee {required_fee}",
        paid_asset.amount()
    );
    let max_overpayment = u64::from(3 * VERIFICATION_BASE_FEE);
    assert!(
        paid_asset.amount().as_u64() <= required_fee.as_u64() + max_overpayment,
        "paid fee {} should not exceed the required fee {required_fee} by more than \
         {max_overpayment}",
        paid_asset.amount()
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_non_exempt_procedures_require_auth(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_, _, account_procedure_1) = mock_component_proc_roots();
    let TestSetup {
        account,
        mock_chain,
        input_note,
        authenticator,
    } = setup_acl_test(BTreeSet::from([account_procedure_1]), auth_scheme);

    let tx_script_get_item = compile_call_get_item_script()?;
    let tx_script_set_item = compile_call_set_item_script()?;

    // Test 1: non-exempt `get_item` WITH authenticator (should succeed).
    let executed_tx_get_item_with_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(authenticator.clone())
        .tx_script(tx_script_get_item.clone())
        .build()?
        .execute()
        .await?;
    prove_and_verify_transaction(executed_tx_get_item_with_auth).await?;

    // Test 2: non-exempt `set_item` WITH authenticator (should succeed).
    mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(authenticator)
        .tx_script(tx_script_set_item)
        .build()?
        .execute()
        .await?;

    // Test 3: non-exempt `get_item` WITHOUT authenticator (should fail).
    let result_no_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(None)
        .tx_script(tx_script_get_item)
        .build()?
        .execute()
        .await;
    assert_matches!(result_no_auth, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// Positive exempt-path: a kernel-detected procedure that *is* on the exempt list can be
/// called without a signature. This is the main path the exempt map lookup is supposed to
/// enable.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_exempt_detected_procedure_succeeds_without_auth(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (get_item, ..) = mock_component_proc_roots();
    let TestSetup { account, mock_chain, input_note, .. } =
        setup_acl_test(BTreeSet::from([get_item]), auth_scheme);

    mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(None)
        .tx_script(compile_call_get_item_script()?)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Empty exempt list is the safe default: any kernel-detected procedure call without a
/// signature must be rejected. Uses `get_item` because it interacts with a kernel-restricted
/// account API (so `was_procedure_called` fires for it).
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_empty_exempt_list_default_denies_unsigned(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let TestSetup { account, mock_chain, input_note, .. } =
        setup_acl_test(BTreeSet::new(), auth_scheme);

    let result = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(None)
        .tx_script(compile_call_get_item_script()?)
        .build()?
        .execute()
        .await;
    assert_matches!(result, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// A transaction that calls a mix of detected exempt and detected non-exempt procedures must
/// still require a signature: a detected exempt call must not suppress the signature
/// requirement for a co-occurring non-exempt call.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_mixed_exempt_and_protected_requires_auth(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (get_item, ..) = mock_component_proc_roots();
    let TestSetup {
        account,
        mock_chain,
        input_note,
        authenticator,
        ..
    } = setup_acl_test(BTreeSet::from([get_item]), auth_scheme);

    // Call `get_item` (detected & exempt) and `set_item` (detected & non-exempt) in the same
    // transaction so both branches of the per-procedure check are exercised.
    let tx_script_mixed = format!(
        r#"
        use mock::account

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        @transaction_script
        pub proc main
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::get_item
            dropw
            push.1.2.3.4
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
    );

    let tx_script_mixed_compiled =
        CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_mixed)?;

    // Without auth: must fail because `set_item` is not exempt.
    let result_no_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(None)
        .tx_script(tx_script_mixed_compiled.clone())
        .build()?
        .execute()
        .await;
    assert_matches!(result_no_auth, Err(TransactionExecutorError::MissingAuthenticator));

    // With auth: must succeed.
    mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(authenticator)
        .tx_script(tx_script_mixed_compiled)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Tests that the singlesig ACL auth procedure reads the initial (pre-rotation) public key
/// when verifying signatures. The transaction script overwrites the public key slot with
/// a bogus value via `set_item` (which is not exempt, so it forces authentication); the
/// test verifies that authentication still succeeds because the auth procedure uses
/// `get_initial_item` to retrieve the original key, rather than `get_item` which would
/// return the overwritten (bogus) value.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_auth_uses_initial_public_key(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_, _, account_procedure_1) = mock_component_proc_roots();
    let TestSetup {
        account,
        mock_chain,
        input_note,
        authenticator,
        ..
    } = setup_acl_test(BTreeSet::from([account_procedure_1]), auth_scheme);

    let pub_key_slot = AuthSingleSigAcl::public_key_slot();
    let tx_script_src = format!(
        r#"
        use mock::account

        const PUB_KEY_SLOT = word("{pub_key_slot}")

        @transaction_script
        pub proc main
            push.99.98.97.96
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
    );

    let executed_tx = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(authenticator)
        .tx_script(CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?)
        .build()?
        .execute()
        .await?;

    prove_and_verify_transaction(executed_tx).await?;

    Ok(())
}

/// Rotated-key negative (ACL): mirrors the singlesig version. `set_item` is not exempt so
/// auth runs; the authenticator signs with sec_b under key A's commitment, and MASM verify
/// must reject the mismatched signature.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_auth_rejects_rotated_key_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_, _, account_procedure_1) = mock_component_proc_roots();
    let TestSetup { account, mock_chain, input_note, .. } =
        setup_acl_test(BTreeSet::from([account_procedure_1]), auth_scheme);

    let mut rng_a = ChaCha20Rng::from_seed(Default::default());
    let pub_key_a = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng_a)?.public_key();

    let mut rng_b = ChaCha20Rng::from_seed([1u8; 32]);
    let sec_key_b = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng_b)?;
    let pub_key_b_commitment: Word = sec_key_b.public_key().to_commitment().into();

    let authenticator = BasicAuthenticator::from_key_pairs(&[(sec_key_b, pub_key_a)]);

    let pub_key_slot = AuthSingleSigAcl::public_key_slot();
    let tx_script_src = format!(
        r#"
        use mock::account

        const PUB_KEY_SLOT = word("{pub_key_slot}")
        const NEW_PUB_KEY = word("{new_pub_key}")

        @transaction_script
        pub proc main
            push.NEW_PUB_KEY
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
        new_pub_key = pub_key_b_commitment,
    );

    let result = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(Some(authenticator))
        .tx_script(CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?)
        .build()?
        .execute()
        .await;

    match auth_scheme {
        AuthScheme::EcdsaK256Keccak => {
            assert_transaction_executor_error!(
                result,
                MasmError::from_static_str("invalid public key commitment")
            );
        },
        AuthScheme::Falcon512Poseidon2 => {
            assert_matches!(
                result,
                Err(TransactionExecutorError::TransactionProgramExecutionFailed(
                    ExecutionError::OperationError {
                        err: miden_processor::operation::OperationError::FailedAssertion { .. },
                        ..
                    }
                ))
            );
        },
        _ => unreachable!("only the two rstest cases are parameterized"),
    }

    Ok(())
}

/// A BURN note targeted at a `user_faucet_single_sig_acl`-configured fungible faucet must
/// execute without an authenticator: the canonical user-faucet auth component carries
/// `receive_and_burn` in its exempt set, so the note's call into the faucet does not require
/// a signature even though no authority-gated setter was invoked.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_burn_note_against_user_faucet_runs_without_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let pub_key_word = Word::new([Felt::ONE; 4]);
    let auth_component = user_faucet_single_sig_acl(pub_key_word.into(), auth_scheme);

    let policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build();

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("polygon")?)
        .symbol(TokenSymbol::try_from("POL")?)
        .decimals(2)
        .max_supply(AssetAmount::new(1000)?)
        .token_supply(AssetAmount::new(100)?)
        .description(Description::new("A polygon token")?)
        .build()?;

    let faucet_account = AccountBuilder::new([42u8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(auth_component)
        .with_component(faucet)
        .with_component(Authority::AuthControlled)
        .with_components(policy_manager)
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
        .build_existing()?;

    let sender = AccountId::builder().account_type(AccountType::Private).build_with_seed([3; 32]);
    let asset = FungibleAsset::new(faucet_account.id(), 10)?;
    let mut rng = RandomCoin::new([Felt::from(7u32); 4].into());
    let burn_note: Note = BurnNote::builder()
        .sender(sender)
        .asset(asset)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    let mut builder = MockChain::builder();
    builder.add_account(faucet_account.clone())?;
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));
    let mock_chain = builder.build()?;

    mock_chain
        .build_tx_context(faucet_account.id(), &[burn_note.id()], &[])?
        .authenticator(None)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// A non-binary exempt-map marker is only constructible by building the component's storage
/// outside the typed `AuthSingleSigAcl` API (which always writes the canonical `[1, 0, 0, 0]`
/// presence marker). Such a marker must degrade safely: the called procedure is treated as
/// non-exempt and authentication is required, rather than the marker check aborting mid-execution
/// and permanently bricking the account.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_non_binary_exempt_marker_requires_auth_instead_of_bricking(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (get_item, ..) = mock_component_proc_roots();

    // Derive a valid public key / scheme id so the auth path is well-formed up to the point where
    // the missing authenticator is detected.
    let mut rng = ChaCha20Rng::from_seed(Default::default());
    let pub_key = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng)?
        .public_key()
        .to_commitment();

    // Build the ACL auth component by hand, planting a NON-BINARY marker (`[5, 0, 0, 0]`) for the
    // `get_item` root instead of the canonical `[1, 0, 0, 0]`. `AccountComponent::new` does not
    // validate storage values against the schema, so this mirrors storage authored outside the
    // typed `AuthSingleSigAcl` API.
    let storage_slots = vec![
        StorageSlot::with_value(AuthSingleSigAcl::public_key_slot().clone(), pub_key.into()),
        StorageSlot::with_value(
            AuthSingleSigAcl::scheme_id_slot().clone(),
            Word::from([auth_scheme.as_u8(), 0, 0, 0]),
        ),
        StorageSlot::with_map(
            AuthSingleSigAcl::exempt_procedure_roots_slot().clone(),
            StorageMap::with_entries([(
                StorageMapKey::from_raw(get_item.as_word()),
                Word::from([5u32, 0, 0, 0]),
            )])?,
        ),
    ];
    let auth_component = AccountComponent::new(
        AuthSingleSigAcl::code().clone(),
        storage_slots,
        AuthSingleSigAcl::component_metadata(),
    )?;

    let mock_component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let account = AccountBuilder::new([0; 32])
        .with_auth_component(auth_component)
        .with_component(mock_component)
        .account_type(AccountType::Public)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let input_note = NoteBuilder::new(account.id(), &mut rand::rng()).build()?;
    builder.add_output_note(RawOutputNote::Full(input_note.clone()));
    let mock_chain = builder.build()?;

    // `get_item` is kernel-detected as called; the non-binary marker must be treated as "not
    // exempt", so authentication is required. Without an authenticator this surfaces as
    // MissingAuthenticator - not a mid-execution assertion abort from the marker check.
    let result = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&input_note))?
        .authenticator(None)
        .tx_script(compile_call_get_item_script()?)
        .build()?
        .execute()
        .await;
    assert_matches!(result, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

// HELPER STRUCTURES
// ================================================================================================

struct TestSetup {
    pub account: Account,
    pub mock_chain: MockChain,
    pub input_note: Note,
    pub authenticator: Option<BasicAuthenticator>,
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the procedure roots used by the ACL tests, in this order:
///   (`get_item`, `set_item`, `account_procedure_1`).
fn mock_component_proc_roots() -> (AccountProcedureRoot, AccountProcedureRoot, AccountProcedureRoot)
{
    let component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let get_item = component
        .get_procedure_root_by_path("mock::account::get_item")
        .expect("get_item procedure should exist");
    let set_item = component
        .get_procedure_root_by_path("mock::account::set_item")
        .expect("set_item procedure should exist");
    let account_procedure_1 = component
        .get_procedure_root_by_path("mock::account::account_procedure_1")
        .expect("account_procedure_1 procedure should exist");

    (get_item, set_item, account_procedure_1)
}

/// Sets up an account using `AuthSingleSigAcl` with the supplied exempt list, registers it
/// on a fresh mock chain, and returns a note ready to be consumed by the account.
fn setup_acl_test(
    exempt_procedures: BTreeSet<AccountProcedureRoot>,
    auth_scheme: AuthScheme,
) -> TestSetup {
    let component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let (auth_component, authenticator) =
        Auth::Acl { exempt_procedures, auth_scheme }.build_component();

    let account = AccountBuilder::new([0; 32])
        .with_auth_component(auth_component)
        .with_component(component)
        .account_type(AccountType::Public)
        .build_existing()
        .expect("failed to create an account");

    let mut builder = MockChain::builder();
    builder
        .add_account(account.clone())
        .expect("failed to add account to the mock chain builder");

    // Create a mock note to consume (needed to make the transaction non-empty)
    let input_note = NoteBuilder::new(account.id(), &mut rand::rng())
        .build()
        .expect("failed to create mock note");
    builder.add_output_note(RawOutputNote::Full(input_note.clone()));
    let mock_chain = builder.build().expect("failed to build a mock chain");

    TestSetup {
        account,
        mock_chain,
        input_note,
        authenticator,
    }
}

/// Compiles the canonical "call `mock::account::get_item` against `MOCK_VALUE_SLOT0`" tx
/// script. Used by several tests that need a non-exempt detected call (`get_item` invokes a
/// kernel-restricted storage-read API).
fn compile_call_get_item_script() -> anyhow::Result<TransactionScript> {
    let src = format!(
        r#"
        use mock::account

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        @transaction_script
        pub proc main
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::get_item
            dropw
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
    );
    Ok(CodeBuilder::with_mock_libraries().compile_tx_script(src)?)
}

/// Compiles the canonical "call `mock::account::set_item` on `MOCK_VALUE_SLOT0` with a fixed
/// dummy word" tx script.
fn compile_call_set_item_script() -> anyhow::Result<TransactionScript> {
    let src = format!(
        r#"
        use mock::account

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        @transaction_script
        pub proc main
            push.1.2.3.4
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
    );
    Ok(CodeBuilder::with_mock_libraries().compile_tx_script(src)?)
}
