use miden_processor::advice::AdviceInputs;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountProcedureRoot,
    AccountType,
    StorageMapKey,
};
use miden_protocol::asset::{AssetId, FungibleAsset};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::{RawOutputNote, TransactionScript};
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::auth::{Approver, ApproverSet, AuthMultisig};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_DUPLICATE_APPROVER_PUBLIC_KEY,
    ERR_PROC_THRESHOLD_EXCEEDS_NUM_APPROVERS,
    ERR_TX_ALREADY_EXECUTED,
};
use miden_standards::note::P2idNote;
use miden_standards::testing::account_interface::get_public_keys_from_account;
use miden_standards::tx_script::{ExpirationTransactionScript, SendNotesTransactionScript};
use miden_testing::utils::create_spawn_note;
use miden_testing::{Auth, MockChainBuilder, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

pub(super) type MultisigTestSetup =
    (Vec<AuthSecretKey>, Vec<AuthScheme>, Vec<PublicKey>, Vec<BasicAuthenticator>);

/// Sets up secret keys, public keys, and authenticators for multisig testing for the given scheme.
pub(super) fn setup_keys_and_authenticators_with_scheme(
    num_approvers: usize,
    threshold: usize,
    auth_scheme: AuthScheme,
) -> anyhow::Result<MultisigTestSetup> {
    let seed: [u8; 32] = rand::random();
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut secret_keys = Vec::new();
    let mut auth_schemes = Vec::new();
    let mut public_keys = Vec::new();
    let mut authenticators = Vec::new();

    for _ in 0..num_approvers {
        let sec_key = match auth_scheme {
            AuthScheme::EcdsaK256Keccak => AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng),
            AuthScheme::Falcon512Poseidon2 => {
                AuthSecretKey::new_falcon512_poseidon2_with_rng(&mut rng)
            },
            _ => anyhow::bail!("unsupported auth scheme for this test: {auth_scheme:?}"),
        };
        let pub_key = sec_key.public_key();

        secret_keys.push(sec_key);
        auth_schemes.push(auth_scheme);
        public_keys.push(pub_key);
    }

    // Create authenticators for required signers
    for secret_key in secret_keys.iter().take(threshold) {
        let authenticator = BasicAuthenticator::new(core::slice::from_ref(secret_key));
        authenticators.push(authenticator);
    }

    Ok((secret_keys, auth_schemes, public_keys, authenticators))
}

/// Layout expected by `update_signers_and_threshold` when looking up the new multisig config in
/// the advice map: `[threshold, num_approvers, 0, 0, (PUB_KEY, SCHEME_WORD) for each approver]`.
/// Public keys are appended in reverse so the procedure pops them in ascending index order.
pub(super) fn build_update_signers_config_vector(
    threshold: u64,
    num_of_approvers: u64,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
) -> Vec<Felt> {
    let mut config_and_pubkeys_vector = Vec::new();
    config_and_pubkeys_vector.extend_from_slice(&[
        Felt::new_unchecked(threshold),
        Felt::new_unchecked(num_of_approvers),
        Felt::ZERO,
        Felt::ZERO,
    ]);

    let scheme_word = [Felt::from(auth_scheme.as_u8()), Felt::ZERO, Felt::ZERO, Felt::ZERO];

    for public_key in public_keys.iter().rev() {
        let key_word: Word = public_key.to_commitment().into();
        config_and_pubkeys_vector.extend_from_slice(key_word.as_elements());
        config_and_pubkeys_vector.extend_from_slice(&scheme_word);
    }

    config_and_pubkeys_vector
}

/// Creates a multisig account with the specified configuration
fn create_multisig_account(
    threshold: u32,
    approvers: &[(PublicKey, AuthScheme)],
    asset_amount: u64,
    proc_threshold_map: Vec<(AccountProcedureRoot, u32)>,
) -> anyhow::Result<Account> {
    let approvers = approvers
        .iter()
        .map(|(pub_key, auth_scheme)| Approver::new(pub_key.to_commitment(), *auth_scheme))
        .collect();
    let approver_set = ApproverSet::new(approvers, threshold)?;

    let multisig_account = AccountBuilder::new([0; 32])
        .with_components(Auth::Multisig { approver_set, proc_threshold_map })
        .with_component(BasicWallet)
        .account_type(AccountType::Public)
        .with_assets(vec![FungibleAsset::mock(asset_amount)])
        .build_existing()?;

    Ok(multisig_account)
}

// ================================================================================================
// TESTS
// ================================================================================================

/// Tests basic 2-of-2 multisig functionality with note creation.
///
/// This test verifies that a multisig account with 2 approvers and threshold 2
/// can successfully execute a transaction that creates an output note when both
/// required signatures are provided.
///
/// **Roles:**
/// - 2 Approvers (multisig signers)
/// - 1 Multisig Contract
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_2_of_2_with_note_creation(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // Setup keys and authenticators
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    // Create multisig account
    let multisig_starting_balance = 10u64;
    let mut multisig_account =
        create_multisig_account(2, &approvers, multisig_starting_balance, vec![])?;

    let output_note_asset = FungibleAsset::mock(0);

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    // Create output note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;

    // Create spawn note to generate the output note
    let input_note = mock_chain_builder.add_spawn_note([&output_note])?;

    let mut mock_chain = mock_chain_builder.build().unwrap();

    let salt = Word::from([Felt::ONE; 4]);

    // Build base mock transaction
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .authenticated_input_note(input_note.id())
        .expected_output_note(RawOutputNote::Full(output_note))
        .auth_args(salt);

    // Execute transaction without signatures - should fail
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // Get signatures from both approvers
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;

    // Execute transaction with signatures - should succeed
    let mock_tx_execute = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_patch(mock_tx_execute.account_patch())?;

    mock_chain.add_pending_executed_transaction(&mock_tx_execute)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        multisig_account
            .vault()
            .get_balance(AssetId::new_fungible(AccountId::try_from(
                ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            )?))?
            .as_u64(),
        multisig_starting_balance - output_note_asset.unwrap_fungible().amount().as_u64()
    );

    Ok(())
}

/// Tests 2-of-4 multisig with all possible signer combinations.
///
/// This test verifies that a multisig account with 4 approvers and threshold 2
/// can successfully execute transactions when signed by any 2 of the 4 approvers.
/// It tests all 6 possible combinations of 2 signers to ensure the multisig
/// implementation correctly validates signatures from any valid subset.
///
/// **Tested combinations:** (0,1), (0,2), (0,3), (1,2), (1,3), (2,3)
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_2_of_4_all_signer_combinations(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // Setup keys and authenticators (4 approvers, all 4 can sign)
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    // Create multisig account with 4 approvers but threshold of 2
    let multisig_account = create_multisig_account(2, &approvers, 10, vec![])?;

    let mut mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    // Test different combinations of 2 signers out of 4
    let signer_combinations = [
        (0, 1), // First two
        (0, 2), // First and third
        (0, 3), // First and fourth
        (1, 2), // Second and third
        (1, 3), // Second and fourth
        (2, 3), // Last two
    ];

    for (i, (signer1_idx, signer2_idx)) in signer_combinations.iter().enumerate() {
        let salt = Word::from([Felt::new_unchecked(10 + i as u64); 4]);

        // Build base mock transaction
        let mock_tx_builder = mock_chain.build_transaction(multisig_account.id()).auth_args(salt);

        // Execute transaction without signatures first to get tx summary
        let tx_summary = mock_tx_builder
            .clone()
            .build()?
            .execute()
            .await
            .unwrap_err()
            .unwrap_unauthorized_err();

        // Get signatures from the specific combination of signers
        let msg = tx_summary.as_ref().to_commitment();
        let tx_summary = SigningInputs::TransactionSummary(tx_summary);

        let sig_1 = authenticators[*signer1_idx]
            .get_signature(public_keys[*signer1_idx].to_commitment(), &tx_summary)
            .await?;
        let sig_2 = authenticators[*signer2_idx]
            .get_signature(public_keys[*signer2_idx].to_commitment(), &tx_summary)
            .await?;

        // Execute transaction with signatures - should succeed for any combination
        let mock_tx_execute = mock_tx_builder
            .add_signature(public_keys[*signer1_idx].to_commitment(), msg, sig_1)
            .add_signature(public_keys[*signer2_idx].to_commitment(), msg, sig_2)
            .build()?;

        let executed_tx = mock_tx_execute.execute().await.unwrap_or_else(|_| {
            panic!("Transaction should succeed with signers {signer1_idx} and {signer2_idx}")
        });

        // Apply the transaction to the mock chain for the next iteration
        mock_chain.add_pending_executed_transaction(&executed_tx)?;
        mock_chain.prove_next_block()?;
    }

    Ok(())
}

/// Tests multisig replay protection to prevent transaction re-execution.
///
/// This test verifies that a 2-of-3 multisig account properly prevents replay attacks
/// by rejecting attempts to execute the same transaction twice. The first execution
/// should succeed with valid signatures, but the second attempt with identical
/// parameters should fail with ERR_TX_ALREADY_EXECUTED.
///
/// **Roles:**
/// - 3 Approvers (2 signers required)
/// - 1 Multisig Contract
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_replay_protection(#[case] auth_scheme: AuthScheme) -> anyhow::Result<()> {
    // Setup keys and authenticators (3 approvers, but only 2 signers)
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    // Create 2/3 multisig account
    let multisig_account = create_multisig_account(2, &approvers, 20, vec![])?;

    let mut mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new_unchecked(3); 4]);
    let ref_block = mock_chain.latest_block_header().block_num();

    // Build base mock transaction
    let mock_tx_builder = mock_chain.build_transaction(multisig_account.id()).auth_args(salt);

    // Execute transaction without signatures first to get tx summary
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // Get signatures from 2 of the 3 approvers
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;

    // Execute transaction with signatures - should succeed (first execution)
    let mock_tx_execute = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_2.clone())
        .build()?
        .execute()
        .await?;

    // Apply the transaction to the mock chain
    mock_chain.add_pending_executed_transaction(&mock_tx_execute)?;
    mock_chain.prove_next_block()?;

    // Attempt to execute the same transaction again - should fail due to replay protection.
    // Must rebuild from the updated mock chain to pick up the new account state. The reference
    // block is pinned to the original one because the signed message commits to the reference
    // block commitment: against a newer reference block the signatures would not verify and the
    // transaction would fail authentication before the replay protection check is reached.
    let mock_tx_replay = mock_chain
        .build_transaction(multisig_account.id())
        .reference_block(ref_block)
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .auth_args(salt)
        .build()?;

    // This should fail due to replay protection
    let result = mock_tx_replay.execute().await;
    assert_transaction_executor_error!(result, ERR_TX_ALREADY_EXECUTED);

    Ok(())
}

/// Tests that multisig signatures go stale once the chain moves past the signed reference block.
///
/// Approvers sign a valid 2/3 transaction summary that sets an expiration delta. The chain then
/// advances past that delta, and re-executing against the newer reference block fails
/// authentication because the signatures are bound to the original block commitment and
/// expiration.
///
/// **Roles:**
/// - 3 Approvers (2 signers required)
/// - 1 Multisig Contract
/// - 1 Transaction Script setting the expiration delta
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_stale_signatures_fail_after_expiration(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let multisig_account = create_multisig_account(2, &approvers, 20, vec![])?;

    let mut mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new_unchecked(5); 4]);
    let expiration_delta = core::num::NonZeroU16::new(3).unwrap();
    let expiration_script = ExpirationTransactionScript::new(expiration_delta);
    let ref_block = mock_chain.latest_block_header().block_num();

    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(expiration_script.into())
        .tx_script_args(expiration_script.tx_script_args())
        .auth_args(salt);

    // Execute without signatures to obtain the transaction summary to sign.
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // The summary binds the expiration delta set by the transaction script.
    assert_eq!(tx_summary.params().expiration_delta(), expiration_delta.get());
    let original_block_commitment = tx_summary.block_commitment();

    let msg = tx_summary.to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;

    // Sanity check: against the signed reference block the signatures authenticate the tx.
    mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_2.clone())
        .build()?
        .execute()
        .await?;

    // Advance the chain past the expiration window of the signed transaction.
    mock_chain.prove_until_block(ref_block + 5)?;

    // Re-executing against the newer reference block fails authentication: the summary now
    // commits to a different block commitment, so the collected signatures do not cover it.
    let stale_summary = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(expiration_script.into())
        .tx_script_args(expiration_script.tx_script_args())
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    assert_ne!(stale_summary.block_commitment(), original_block_commitment);
    assert_ne!(stale_summary.to_commitment(), msg);

    Ok(())
}

/// Tests multisig signer update functionality.
///
/// This test verifies that a multisig account can:
/// 1. Execute a transaction script to update signers and threshold
/// 2. Create a second transaction signed by the new owners
/// 3. Properly handle multisig authentication with the updated signers
///
/// **Roles:**
/// - 2 Original Approvers (multisig signers)
/// - 4 New Approvers (updated multisig signers)
/// - 1 Multisig Contract
/// - 1 Transaction Script calling multisig procedures
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_update_signers(#[case] auth_scheme: AuthScheme) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let multisig_account = create_multisig_account(2, &approvers, 10, vec![])?;

    // SECTION 1: Execute a transaction script to update signers and threshold
    // ================================================================================

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let output_note_asset = FungibleAsset::mock(0);

    // Create output note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;

    let mut mock_chain = mock_chain_builder.clone().build().unwrap();

    let salt = Word::from([Felt::new_unchecked(3); 4]);

    // Setup new signers
    let mut advice_map = AdviceMap::default();
    let (_new_secret_keys, _new_auth_schemes, new_public_keys, _new_authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;

    let threshold = 3u64;
    let num_of_approvers = 4u64;

    let config_and_pubkeys_vector = build_update_signers_config_vector(
        threshold,
        num_of_approvers,
        &new_public_keys,
        auth_scheme,
    );
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    // Create a transaction script that calls the update_signers procedure
    let tx_script_code = "
        @transaction_script
        pub proc main
            call.::miden::standards::components::auth::multisig::update_signers_and_threshold
        end
    ";

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script(tx_script_code)?;

    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };

    // Pass the MULTISIG_CONFIG_HASH as the tx_script_args
    let tx_script_args: Word = multisig_config_hash;

    // Build base mock transaction
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(tx_script)
        .tx_script_args(tx_script_args)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt);

    // Execute transaction without signatures first to get tx summary
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // Get signatures from both approvers
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;

    // Execute transaction with signatures - should succeed
    let update_approvers_tx = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await?;

    // Verify the transaction executed successfully
    assert_eq!(
        update_approvers_tx.account_patch().final_nonce(),
        Some(multisig_account.nonce() + Felt::ONE)
    );

    mock_chain.add_pending_executed_transaction(&update_approvers_tx)?;
    mock_chain.prove_next_block()?;

    // Apply the delta to get the updated account with new signers
    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_patch(update_approvers_tx.account_patch())?;

    // Verify that the public keys were actually updated in storage
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = StorageMapKey::from_index(i as u32);
        let storage_item = updated_multisig_account
            .storage()
            .get_map_item(AuthMultisig::approver_public_keys_slot(), storage_key)
            .unwrap();

        let expected_word: Word = expected_key.to_commitment().into();

        assert_eq!(storage_item, expected_word, "Public key {} doesn't match expected value", i);
    }

    // Verify the threshold was updated by checking the config storage slot
    let threshold_config_storage = updated_multisig_account
        .storage()
        .get_item(AuthMultisig::threshold_config_slot())
        .unwrap();

    assert_eq!(
        threshold_config_storage[0],
        Felt::new_unchecked(threshold),
        "Threshold was not updated correctly"
    );
    assert_eq!(
        threshold_config_storage[1],
        Felt::new_unchecked(num_of_approvers),
        "Num approvers was not updated correctly"
    );

    // Extract public keys using the interface function
    let extracted_pub_keys = get_public_keys_from_account(&updated_multisig_account);

    // Verify that we have the expected number of public keys (4 new ones)
    assert_eq!(
        extracted_pub_keys.len(),
        4,
        "get_public_keys_from_account should return 4 public keys after update"
    );

    // Verify that the extracted public keys match the new ones we set
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let expected_word: Word = expected_key.to_commitment().into();

        // Find the matching key in extracted keys (order might be different)
        let found_key = extracted_pub_keys.iter().find(|&key| *key == expected_word);

        assert!(
            found_key.is_some(),
            "Public key {} not found in extracted keys: expected {:?}, got {:?}",
            i,
            expected_word,
            extracted_pub_keys
        );
    }

    // SECTION 2: Create a second transaction signed by the new owners
    // ================================================================================

    // Now test creating a note with the new signers
    // Setup authenticators for the new signers (we need 3 out of 4 for threshold 3)
    let mut new_authenticators = Vec::new();
    for secret_key in _new_secret_keys.iter().take(3) {
        let authenticator = BasicAuthenticator::new(core::slice::from_ref(secret_key));
        new_authenticators.push(authenticator);
    }

    // Create a new output note for the second transaction with new signers
    let output_note_new: Note = P2idNote::builder()
        .sender(updated_multisig_account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap())
        .asset(output_note_asset)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::empty()))
        .build()?
        .into();

    // Create a new spawn note for the second transaction
    let input_note_new = create_spawn_note([&output_note_new])?;

    let salt_new = Word::from([Felt::new_unchecked(4); 4]);

    // Build the new mock chain with the updated account and notes
    let mut new_mock_chain_builder =
        MockChainBuilder::with_accounts([updated_multisig_account.clone()]).unwrap();
    new_mock_chain_builder.add_output_note(RawOutputNote::Full(input_note_new.clone()));
    let new_mock_chain = new_mock_chain_builder.build().unwrap();

    // Build base mock transaction for the new signers
    let mock_tx_builder_new = new_mock_chain
        .build_transaction(updated_multisig_account.id())
        .authenticated_input_note(input_note_new.id())
        .auth_args(salt_new);

    // Execute transaction without signatures first to get tx summary
    let tx_summary_new = mock_tx_builder_new
        .clone()
        .expected_output_note(RawOutputNote::Full(output_note.clone()))
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // Get signatures from 3 of the 4 new approvers (threshold is 3)
    let msg_new = tx_summary_new.as_ref().to_commitment();
    let tx_summary_new = SigningInputs::TransactionSummary(tx_summary_new);

    let sig_1_new = new_authenticators[0]
        .get_signature(new_public_keys[0].to_commitment(), &tx_summary_new)
        .await?;
    let sig_2_new = new_authenticators[1]
        .get_signature(new_public_keys[1].to_commitment(), &tx_summary_new)
        .await?;
    let sig_3_new = new_authenticators[2]
        .get_signature(new_public_keys[2].to_commitment(), &tx_summary_new)
        .await?;

    // SECTION 3: Properly handle multisig authentication with the updated signers
    // ================================================================================

    // Execute transaction with new signatures - should succeed
    let mock_tx_execute_new = mock_tx_builder_new
        .expected_output_note(RawOutputNote::Full(output_note_new))
        .add_signature(new_public_keys[0].to_commitment(), msg_new, sig_1_new)
        .add_signature(new_public_keys[1].to_commitment(), msg_new, sig_2_new)
        .add_signature(new_public_keys[2].to_commitment(), msg_new, sig_3_new)
        .build()?
        .execute()
        .await?;

    // Verify the transaction executed successfully with new signers
    assert_eq!(
        mock_tx_execute_new.account_patch().final_nonce(),
        Some(updated_multisig_account.nonce() + Felt::ONE)
    );

    Ok(())
}

/// Tests multisig signer update functionality with owner removal.
///
/// This test verifies that a multisig account can:
/// 1. Start with 5 owners and threshold 4
/// 2. Execute a transaction to remove 3 owners (updating to 2 owners)
/// 3. Verify that all removed owners' storage slots are properly cleared
///
/// **Roles:**
/// - 5 Original Approvers (multisig signers, threshold 4)
/// - 2 Updated Approvers (after removing 3 owners)
/// - 1 Multisig Contract
/// - 1 Transaction Script calling multisig procedures
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_update_signers_remove_owner(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // Setup 5 original owners with threshold 4
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let multisig_account = create_multisig_account(4, &approvers, 10, vec![])?;

    // Build mock chain
    let mock_chain_builder = MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let mut mock_chain = mock_chain_builder.build().unwrap();

    // Setup new signers (remove the last 3 owners, keeping first 2)
    let new_public_keys = &public_keys[0..2];
    let threshold = 1u64;
    let num_of_approvers = 2u64;

    let config_and_pubkeys_vector = build_update_signers_config_vector(
        threshold,
        num_of_approvers,
        new_public_keys,
        auth_scheme,
    );
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);
    let mut advice_map = AdviceMap::default();
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    // Create transaction script
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script("@transaction_script\npub proc main\n    call.::miden::standards::components::auth::multisig::update_signers_and_threshold\nend")?;

    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };

    let salt = Word::from([Felt::new_unchecked(3); 4]);

    // Build base mock transaction
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(tx_script)
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt);

    // Execute without signatures to get tx summary
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // Get signatures from 4 of the 5 original approvers (threshold is 4)
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;
    let sig_3 = authenticators[2]
        .get_signature(public_keys[2].to_commitment(), &tx_summary)
        .await?;
    let sig_4 = authenticators[3]
        .get_signature(public_keys[3].to_commitment(), &tx_summary)
        .await?;

    // Execute with signatures
    let update_approvers_tx = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(public_keys[2].to_commitment(), msg, sig_3)
        .add_signature(public_keys[3].to_commitment(), msg, sig_4)
        .build()?
        .execute()
        .await?;

    // Verify transaction success
    assert_eq!(
        update_approvers_tx.account_patch().final_nonce(),
        Some(multisig_account.nonce() + Felt::ONE)
    );

    mock_chain.add_pending_executed_transaction(&update_approvers_tx)?;
    mock_chain.prove_next_block()?;

    // Apply delta to get updated account
    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_patch(update_approvers_tx.account_patch())?;

    // Verify public keys were updated
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = StorageMapKey::from_index(i as u32);
        let storage_item = updated_multisig_account
            .storage()
            .get_map_item(AuthMultisig::approver_public_keys_slot(), storage_key)
            .unwrap();
        let expected_word: Word = expected_key.to_commitment().into();
        assert_eq!(storage_item, expected_word, "Public key {} doesn't match", i);
    }

    // Verify threshold and num_approvers
    let threshold_config = updated_multisig_account
        .storage()
        .get_item(AuthMultisig::threshold_config_slot())
        .unwrap();
    assert_eq!(threshold_config[0], Felt::new_unchecked(threshold), "Threshold not updated");
    assert_eq!(
        threshold_config[1],
        Felt::new_unchecked(num_of_approvers),
        "Num approvers not updated"
    );

    // Verify extracted public keys
    let extracted_pub_keys = get_public_keys_from_account(&updated_multisig_account);
    assert_eq!(extracted_pub_keys.len(), 2, "Should have 2 public keys after update");

    for expected_key in new_public_keys.iter() {
        let expected_word: Word = expected_key.to_commitment().into();
        assert!(
            extracted_pub_keys.contains(&expected_word),
            "Public key not found in extracted keys"
        );
    }

    // Verify removed owners' slots are empty (indices 2, 3, and 4 should be cleared)
    for removed_idx in 2..5 {
        let removed_owner_key = StorageMapKey::from_index(removed_idx as u32);
        let removed_owner_slot = updated_multisig_account
            .storage()
            .get_map_item(AuthMultisig::approver_public_keys_slot(), removed_owner_key)
            .unwrap();
        assert_eq!(
            removed_owner_slot,
            Word::empty(),
            "Removed owner's slot at index {} should be empty",
            removed_idx
        );
    }

    // Verify only 2 non-empty keys remain (at indices 0 and 1)
    let mut non_empty_count = 0;
    for i in 0..5 {
        let storage_key = StorageMapKey::from_index(i as u32);
        let storage_item = updated_multisig_account
            .storage()
            .get_map_item(AuthMultisig::approver_public_keys_slot(), storage_key)
            .unwrap();

        if storage_item != Word::empty() {
            non_empty_count += 1;
            assert!(i < 2, "Found non-empty key at index {} which should be removed", i);

            let expected_word: Word = new_public_keys.get(i).unwrap().to_commitment().into();
            assert_eq!(storage_item, expected_word, "Key at index {} doesn't match", i);
        }
    }
    assert_eq!(
        non_empty_count, 2,
        "Should have exactly 2 non-empty keys after removing 3 owners"
    );

    Ok(())
}

/// Tests that signer updates are rejected when stored procedure threshold overrides would become
/// unreachable for the new signer set.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_update_signers_rejects_unreachable_proc_thresholds(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    // Configure a procedure override that is valid for the initial signer set (3-of-3),
    // but invalid after updating to 2 signers. The override editing procedure is hardened to the
    // same level, as `AuthMultisig::new` requires for an override above the default.
    let multisig_account = create_multisig_account(
        2,
        &approvers,
        10,
        vec![
            (BasicWallet::receive_asset_root(), 3),
            (AuthMultisig::set_procedure_threshold_root(), 3),
        ],
    )?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let new_public_keys = &public_keys[0..2];
    let threshold = 2u64;
    let num_of_approvers = 2u64;

    let config_and_pubkeys_vector = build_update_signers_config_vector(
        threshold,
        num_of_approvers,
        new_public_keys,
        auth_scheme,
    );
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);
    let mut advice_map = AdviceMap::default();
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script("@transaction_script\npub proc main\n    call.::miden::standards::components::auth::multisig::update_signers_and_threshold\nend")?;

    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };
    let salt = Word::from([Felt::new_unchecked(8); 4]);

    let result = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(tx_script)
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PROC_THRESHOLD_EXCEEDS_NUM_APPROVERS);

    Ok(())
}

/// Tests that `update_signers_and_threshold` rejects a signer set containing duplicate public keys.
///
/// Without this check a duplicated key lets a single signature satisfy multiple approver slots
/// (signatures are looked up in the advice map by public key, not by signer index, and are not
/// consumed on lookup), which would defeat the distinct-approvers policy.
#[tokio::test]
async fn test_multisig_update_signers_rejects_duplicate_public_keys() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let (_secret_keys, auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let multisig_account = create_multisig_account(2, &approvers, 10, vec![])?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    // Update to a signer set of [PK_A, PK_A, PK_B]: the first key is repeated.
    let duplicate_public_keys =
        vec![public_keys[0].clone(), public_keys[0].clone(), public_keys[1].clone()];
    let threshold = 2u64;
    let num_of_approvers = 3u64;

    let config_and_pubkeys_vector = build_update_signers_config_vector(
        threshold,
        num_of_approvers,
        &duplicate_public_keys,
        auth_scheme,
    );
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);
    let mut advice_map = AdviceMap::default();
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script(
        "
        @transaction_script
        pub proc main
            call.::miden::standards::components::auth::multisig::update_signers_and_threshold
        end
        ",
    )?;

    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };
    let salt = Word::from([Felt::new_unchecked(9); 4]);

    let result = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(tx_script)
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_DUPLICATE_APPROVER_PUBLIC_KEY);

    Ok(())
}

/// Tests that newly added approvers cannot sign transactions before the signer update is executed.
///
/// This is a regression test to ensure that unauthorized parties cannot add their own public keys
/// to the multisig configuration and immediately use them to sign transactions before
/// the current approvers have validated and executed the signer update.
///
/// **Test Flow:**
/// 1. Create a multisig account with 2 original approvers
/// 2. Prepare a signer update transaction with new approvers
/// 3. Try to sign the transaction with the NEW approvers (should fail)
/// 4. Verify that only the CURRENT approvers can sign the update transaction
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_new_approvers_cannot_sign_before_update(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // SECTION 1: Create a multisig account with 2 original approvers
    // ================================================================================

    let (_secret_keys, auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let multisig_account = create_multisig_account(2, &approvers, 10, vec![])?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new_unchecked(5); 4]);

    // SECTION 2: Prepare a signer update transaction with new approvers
    // ================================================================================

    // Get the multisig package

    // Setup new signers (these should NOT be able to sign the update transaction)
    let mut advice_map = AdviceMap::default();
    let (_new_secret_keys, _new_auth_schemes, new_public_keys, new_authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;

    let threshold = 3u64;
    let num_of_approvers = 4u64;

    let config_and_pubkeys_vector = build_update_signers_config_vector(
        threshold,
        num_of_approvers,
        &new_public_keys,
        auth_scheme,
    );
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    // Create a transaction script that calls the update_signers procedure
    let tx_script_code = "
        @transaction_script
        pub proc main
            call.::miden::standards::components::auth::multisig::update_signers_and_threshold
        end
    ";

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script(tx_script_code)?;

    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };

    // Pass the MULTISIG_CONFIG_HASH as the tx_script_args
    let tx_script_args: Word = multisig_config_hash;

    // Build base mock transaction
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(tx_script)
        .tx_script_args(tx_script_args)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt);

    // Execute transaction without signatures first to get tx summary
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // SECTION 3: Try to sign the transaction with the NEW approvers (should fail)
    // ================================================================================

    // Get signatures from the NEW approvers (these should NOT work)
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary.clone());

    let new_sig_1 = new_authenticators[0]
        .get_signature(new_public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;
    let new_sig_2 = new_authenticators[1]
        .get_signature(new_public_keys[1].to_commitment(), &tx_summary_signing)
        .await?;

    // Try to execute transaction with NEW signatures - should FAIL
    let mock_tx_with_new_sigs = mock_tx_builder
        .add_signature(new_public_keys[0].to_commitment(), msg, new_sig_1)
        .add_signature(new_public_keys[1].to_commitment(), msg, new_sig_2)
        .build()?;

    // SECTION 4: Verify that only the CURRENT approvers can sign the update transaction
    // ================================================================================

    // Should fail - new approvers not yet authorized
    let result = mock_tx_with_new_sigs.execute().await;

    // Assert that the transaction fails as expected
    assert!(
        result.is_err(),
        "Transaction should fail when signed by unauthorized new approvers"
    );

    Ok(())
}

/// Tests that 1-of-2 approvers can consume a note but 2-of-2 are required to send a note.
///
/// This test verifies that a multisig account with 2 approvers and threshold 2, but a procedure
/// threshold of 1 for note consumption, can:
/// 1. Consume a note when only one approver signs the transaction
/// 2. Send a note only when both approvers sign the transaction (default threshold)
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_proc_threshold_overrides(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // Setup keys and authenticators
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let proc_threshold_map = vec![(BasicWallet::receive_asset_root(), 1)];

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    // Create multisig account
    let multisig_starting_balance = 10u64;
    let mut multisig_account =
        create_multisig_account(2, &approvers, multisig_starting_balance, proc_threshold_map)?;

    // SECTION 1: Test note consumption with 1 signature
    // ================================================================================

    // 1. create a mock note from some random account
    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;

    let mut mock_chain = mock_chain_builder.build()?;

    // 2. consume without signatures
    let salt = Word::from([Felt::ONE; 4]);
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .authenticated_input_note(note.id())
        .auth_args(salt);

    // consume without signatures
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // 3. get signature from one approver
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary.clone());
    let sig = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;

    // 4. execute with signature
    let tx_result = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig)
        .build()?
        .execute()
        .await;

    assert!(tx_result.is_ok(), "Note consumption with 1 signature should succeed");

    // Apply the transaction to the account
    multisig_account.apply_patch(tx_result.as_ref().unwrap().account_patch())?;
    mock_chain.add_pending_executed_transaction(&tx_result.unwrap())?;
    mock_chain.prove_next_block()?;

    // SECTION 2: Test note sending requires 2 signatures
    // ================================================================================

    let salt2 = Word::from([Felt::new_unchecked(2); 4]);

    // Create output note to send 5 units from the account
    let asset = FungibleAsset::mock(5);
    let output_note: Note = P2idNote::builder()
        .sender(multisig_account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap())
        .asset(asset)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([Felt::new_unchecked(42); 4])))
        .build()?
        .into();
    let send_note_transaction_script = TransactionScript::from(SendNotesTransactionScript::new(
        &multisig_account.code_interface(),
        &[output_note.clone().into()],
    )?);

    // Build base mock transaction for note sending
    let mock_tx_builder2 = mock_chain
        .build_transaction(multisig_account.id())
        .expected_output_note(RawOutputNote::Full(output_note))
        .tx_script(send_note_transaction_script)
        .auth_args(salt2);

    // Execute transaction without signatures to get tx summary
    let tx_summary2 = mock_tx_builder2
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    // Get signature from only ONE approver
    let msg2 = tx_summary2.as_ref().to_commitment();
    let tx_summary2_signing = SigningInputs::TransactionSummary(tx_summary2.clone());

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary2_signing)
        .await?;

    // Try to execute with only 1 signature - should FAIL
    let result = mock_tx_builder2
        .clone()
        .add_signature(public_keys[0].to_commitment(), msg2, sig_1)
        .build()?
        .execute()
        .await;
    // Expected: transaction should fail with insufficient signatures
    result.unwrap_err().unwrap_unauthorized_err();

    // Now get signatures from BOTH approvers
    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary2_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary2_signing)
        .await?;

    // Execute with 2 signatures - should SUCCEED
    let result = mock_tx_builder2
        .add_signature(public_keys[0].to_commitment(), msg2, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg2, sig_2)
        .build()?
        .execute()
        .await;

    assert!(result.is_ok(), "Transaction should succeed with 2 signatures for note sending");

    // Apply the transaction to the account
    multisig_account.apply_patch(result.as_ref().unwrap().account_patch())?;
    mock_chain.add_pending_executed_transaction(&result.unwrap())?;
    mock_chain.prove_next_block()?;

    assert_eq!(multisig_account.vault().get_balance(asset.id())?.as_u64(), 6);

    Ok(())
}

/// Tests setting a per-procedure threshold override and clearing it via `proc_threshold == 0`.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_set_procedure_threshold(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let mut multisig_account = create_multisig_account(2, &approvers, 10, vec![])?;
    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let one_sig_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let clear_check_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mut mock_chain = mock_chain_builder.build().unwrap();
    let proc_root = BasicWallet::receive_asset_root().as_word();

    let set_script_code = format!(
        r#"
        @transaction_script
        pub proc main
            push.{proc_root}
            push.1
            call.::miden::standards::components::auth::multisig::set_procedure_threshold
            dropw
            drop
        end
        "#
    );
    let set_script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script(set_script_code)?;

    // 1) Set override to 1 (requires default 2 signatures).
    let set_salt = Word::from([Felt::new_unchecked(50); 4]);

    let set_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(set_script)
        .auth_args(set_salt);
    let set_summary = set_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let set_msg = set_summary.as_ref().to_commitment();
    let set_summary = SigningInputs::TransactionSummary(set_summary);
    let set_sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &set_summary)
        .await?;
    let set_sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &set_summary)
        .await?;

    let set_tx = set_builder
        .add_signature(public_keys[0].to_commitment(), set_msg, set_sig_1)
        .add_signature(public_keys[1].to_commitment(), set_msg, set_sig_2)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_patch(set_tx.account_patch())?;
    mock_chain.add_pending_executed_transaction(&set_tx)?;
    mock_chain.prove_next_block()?;

    // 2) Verify receive_asset can now execute with one signature.
    let one_sig_salt = Word::from([Felt::new_unchecked(51); 4]);

    let one_sig_builder = mock_chain
        .build_transaction(multisig_account.id())
        .authenticated_input_note(one_sig_note.id())
        .auth_args(one_sig_salt);
    let one_sig_summary = one_sig_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let one_sig_msg = one_sig_summary.as_ref().to_commitment();
    let one_sig_summary = SigningInputs::TransactionSummary(one_sig_summary);
    let one_sig = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &one_sig_summary)
        .await?;

    let one_sig_tx = one_sig_builder
        .add_signature(public_keys[0].to_commitment(), one_sig_msg, one_sig)
        .build()?
        .execute()
        .await
        .expect("override=1 should allow receive_asset with one signature");
    multisig_account.apply_patch(one_sig_tx.account_patch())?;
    mock_chain.add_pending_executed_transaction(&one_sig_tx)?;
    mock_chain.prove_next_block()?;

    // 3) Clear override by setting threshold to zero.
    let clear_script_code = format!(
        r#"
        @transaction_script
        pub proc main
            push.{proc_root}
            push.0
            call.::miden::standards::components::auth::multisig::set_procedure_threshold
            dropw
            drop
        end
        "#
    );
    let clear_script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script(clear_script_code)?;
    let clear_salt = Word::from([Felt::new_unchecked(52); 4]);

    let clear_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(clear_script)
        .auth_args(clear_salt);
    let clear_summary = clear_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let clear_msg = clear_summary.as_ref().to_commitment();
    let clear_summary = SigningInputs::TransactionSummary(clear_summary);
    let clear_sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &clear_summary)
        .await?;
    let clear_sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &clear_summary)
        .await?;

    let clear_tx = clear_builder
        .add_signature(public_keys[0].to_commitment(), clear_msg, clear_sig_1)
        .add_signature(public_keys[1].to_commitment(), clear_msg, clear_sig_2)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_patch(clear_tx.account_patch())?;
    mock_chain.add_pending_executed_transaction(&clear_tx)?;
    mock_chain.prove_next_block()?;

    // 4) After clear, one signature should no longer be sufficient for receive_asset.
    let clear_check_salt = Word::from([Felt::new_unchecked(53); 4]);

    let clear_check_builder = mock_chain
        .build_transaction(multisig_account.id())
        .authenticated_input_note(clear_check_note.id())
        .auth_args(clear_check_salt);
    let clear_check_summary = clear_check_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let clear_check_msg = clear_check_summary.as_ref().to_commitment();
    let clear_check_summary = SigningInputs::TransactionSummary(clear_check_summary);
    let clear_check_sig = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &clear_check_summary)
        .await?;

    let clear_check_result = clear_check_builder
        .add_signature(public_keys[0].to_commitment(), clear_check_msg, clear_check_sig)
        .build()?
        .execute()
        .await;

    assert!(
        matches!(clear_check_result, Err(TransactionExecutorError::Unauthorized(_))),
        "override cleared via threshold=0 should restore default threshold requirements"
    );

    Ok(())
}

/// Tests setting an override threshold above num_approvers is rejected.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_set_procedure_threshold_rejects_exceeding_approvers(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let multisig_account = create_multisig_account(2, &approvers, 10, vec![])?;
    let proc_root = BasicWallet::receive_asset_root().as_word();

    let script_code = format!(
        r#"
        @transaction_script
        pub proc main
            push.{proc_root}
            push.3
            call.::miden::standards::components::auth::multisig::set_procedure_threshold
        end
        "#
    );
    let script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script(script_code)?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();
    let salt = Word::from([Felt::new_unchecked(54); 4]);

    let mock_tx_init = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(script.clone())
        .auth_args(salt)
        .build()?;

    let result = mock_tx_init.execute().await;

    assert_transaction_executor_error!(result, ERR_PROC_THRESHOLD_EXCEEDS_NUM_APPROVERS);

    Ok(())
}

/// Tests that `set_procedure_threshold` validates against the *current* num_approvers, not the
/// initial one. If `update_signers_and_threshold` reduces num_approvers earlier in the
/// same transaction, a subsequent `set_procedure_threshold` must use the post-update num_approvers
/// for its bound check.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_set_procedure_threshold_uses_current_num_approvers(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // Start with 3 approvers, threshold 2.
    let (_secret_keys, auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let multisig_account = create_multisig_account(2, &approvers, 10, vec![])?;
    let proc_root = BasicWallet::receive_asset_root().as_word();

    // Build a new config that reduces num_approvers to 1 (and threshold to 1).
    let mut advice_map = AdviceMap::default();
    let (_new_sec, _new_schemes, new_public_keys, _new_auth) =
        setup_keys_and_authenticators_with_scheme(1, 1, auth_scheme)?;

    let new_threshold = 1u64;
    let new_num_of_approvers = 1u64;
    let config_and_pubkeys_vector = build_update_signers_config_vector(
        new_threshold,
        new_num_of_approvers,
        &new_public_keys,
        auth_scheme,
    );
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);
    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };

    // Same transaction: first reduce num_approvers to 1, then try to set a per-procedure
    // override of 2 — which exceeds the *current* num_approvers and must be rejected.
    let script_code = format!(
        r#"
        @transaction_script
        pub proc main
            call.::miden::standards::components::auth::multisig::update_signers_and_threshold
            push.{proc_root}
            push.2
            call.::miden::standards::components::auth::multisig::set_procedure_threshold
            dropw
            drop
        end
        "#
    );
    let script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script(script_code)?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();
    let salt = Word::from([Felt::from_u8(55); 4]);

    let mock_tx = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(script)
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt)
        .build()?;

    let result = mock_tx.execute().await;

    assert_transaction_executor_error!(result, ERR_PROC_THRESHOLD_EXCEEDS_NUM_APPROVERS);

    Ok(())
}

/// Executes a fully-signed 2-of-4 multisig transaction whose script `call`s one of the public
/// component getters, so the getter is exercised through the 16-felt `call` ABI (a getter that
/// returns at any operand-stack depth other than 16 aborts in `restore_context` with
/// `InvalidStackDepthOnReturn`).
async fn execute_multisig_getter_call<F>(build_script: F) -> anyhow::Result<()>
where
    F: FnOnce(&[PublicKey]) -> String,
{
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 2, AuthScheme::EcdsaK256Keccak)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let multisig_account = create_multisig_account(2, &approvers, 10, vec![])?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let script_code = build_script(&public_keys);
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisig::code())?
        .compile_tx_script(&script_code)?;

    let salt = Word::from([Felt::from_u8(77); 4]);

    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(tx_script)
        .auth_args(salt);

    // First pass without signatures: the getter `call` must return cleanly so the transaction
    // reaches authentication and only fails there for missing signatures.
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;

    // Second pass with a valid quorum: the whole transaction, getter included, executes.
    mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Regression test for the `call` ABI of `get_threshold_and_num_approvers`.
///
/// The script asserts the returned `[default_threshold, num_approvers]` matches the 2-of-4
/// configuration, which both proves the getter returns at operand-stack depth 16 and that it
/// yields the correct values.
#[tokio::test]
async fn test_get_threshold_and_num_approvers_call_abi() -> anyhow::Result<()> {
    execute_multisig_getter_call(|_| {
        "
        @transaction_script
        pub proc main
            call.::miden::standards::components::auth::multisig::get_threshold_and_num_approvers
            # => [default_threshold, num_approvers, pad(14)]
            push.2 eq assert
            # => [num_approvers, pad(14)]
            push.4 eq assert
            # => [pad(14)]
            exec.::miden::core::sys::truncate_stack
        end
        "
        .to_string()
    })
    .await
}

/// Regression test for the `call` ABI of `get_signer_at`.
///
/// The signer at index `0` is queried and the script asserts the returned scheme id matches
/// `EcdsaK256Keccak`, exercising the getter's five-felt output through the 16-felt `call` ABI.
#[tokio::test]
async fn test_get_signer_at_call_abi() -> anyhow::Result<()> {
    let expected_scheme_id = AuthScheme::EcdsaK256Keccak.as_u8();
    execute_multisig_getter_call(move |_| {
        format!(
            r#"
        @transaction_script
        pub proc main
            # query the signer at index 0
            push.0
            call.::miden::standards::components::auth::multisig::get_signer_at
            # => [PUB_KEY, scheme_id, pad(11)]
            movup.4 eq.{expected_scheme_id} assert.err="expected scheme ID {expected_scheme_id}"
            # => [PUB_KEY, pad(11)]
            dropw
            # => [pad(12)]
            exec.::miden::core::sys::truncate_stack
        end
        "#
        )
    })
    .await
}

/// Regression test for the `call` ABI of `is_signer` when the queried key is a signer.
///
/// A real approver public key is pushed by the script; the getter must return `1`.
#[tokio::test]
async fn test_is_signer_true_call_abi() -> anyhow::Result<()> {
    execute_multisig_getter_call(|public_keys| {
        let pub_key = public_keys[0].to_commitment();
        format!(
            r#"
        @transaction_script
        pub proc main
            push.{pub_key}
            call.::miden::standards::components::auth::multisig::is_signer
            # => [is_signer, pad(15)]
            assert
            # => [pad(15)]
            exec.::miden::core::sys::truncate_stack
        end
        "#
        )
    })
    .await
}

/// Regression test for the `call` ABI of `is_signer` when the queried key is not a signer.
///
/// A key that is not part of the approver set is pushed by the script; the getter must return `0`
/// after iterating over every approver.
#[tokio::test]
async fn test_is_signer_false_call_abi() -> anyhow::Result<()> {
    execute_multisig_getter_call(|_| {
        // A word that is not any approver's public key commitment.
        let non_signer = Word::from([Felt::from_u8(0xff); 4]);
        format!(
            r#"
        @transaction_script
        pub proc main
            push.{non_signer}
            call.::miden::standards::components::auth::multisig::is_signer
            # => [is_signer, pad(15)]
            assertz
            # => [pad(15)]
            exec.::miden::core::sys::truncate_stack
        end
        "#
        )
    })
    .await
}
