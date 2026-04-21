use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::{Felt};
use miden_standards::account::auth::multisig_smart::{
    ProcedurePolicy,
    ProcedurePolicyNoteRestriction,
};
use miden_standards::account::auth::{AuthMultisigSmart, AuthMultisigSmartConfig};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_OR_OUTPUT_NOTES;
use miden_testing::{MockChainBuilder, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

type MultisigTestSetup =
    (Vec<AuthSecretKey>, Vec<AuthScheme>, Vec<PublicKey>, Vec<BasicAuthenticator>);

/// Sets up secret keys, auth schemes, public keys, and authenticators for a specific scheme.
fn setup_keys_and_authenticators_with_scheme(
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

    for secret_key in secret_keys.iter().take(threshold) {
        authenticators.push(BasicAuthenticator::new(core::slice::from_ref(secret_key)));
    }

    Ok((secret_keys, auth_schemes, public_keys, authenticators))
}

/// Builds a multisig smart account with the given approvers, threshold, starting balance, and
/// procedure policy map. Uses `BasicWallet` so the account exposes `receive_asset` and friends.
fn create_multisig_smart_account(
    threshold: u32,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
    starting_balance: u64,
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
) -> anyhow::Result<Account> {
    let approvers: Vec<_> =
        public_keys.iter().map(|pk| (pk.to_commitment(), auth_scheme)).collect();
    let config = AuthMultisigSmartConfig::new(approvers, threshold)?
        .with_proc_policies(proc_policy_map)?;

    let asset =
        FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?, starting_balance)?;

    let multisig_account = AccountBuilder::new([0; 32])
        .with_auth_component(AuthMultisigSmart::new(config)?)
        .with_component(BasicWallet)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(core::iter::once(asset.into()))
        .build_existing()?;

    Ok(multisig_account)
}

// ================================================================================================
// TESTS
// ================================================================================================

/// A 3-of-3 multisig with a `receive_asset` procedure policy that lowers the threshold to 1
/// should let a single-signature transaction that only calls `receive_asset` succeed.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_receive_asset_policy_overrides_default_three_of_three_to_one_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 3, auth_scheme)?;

    let receive_asset_one_signature_policy = ProcedurePolicy::with_immediate_threshold(1)?;
    let proc_policy_map =
        vec![(BasicWallet::receive_asset_digest(), receive_asset_one_signature_policy)];

    let mut multisig_account =
        create_multisig_smart_account(3, &public_keys, auth_scheme, 10, proc_policy_map)?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mut mock_chain = mock_chain_builder.build()?;

    let salt = Word::from([Felt::new(11); 4]);
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_summary) => tx_summary,
        error => panic!("expected abort with tx summary: {error:?}"),
    };

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary);
    let one_signature = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;

    let tx_result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .add_signature(public_keys[0].to_commitment(), msg, one_signature)
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    assert!(
        tx_result.is_ok(),
        "receive_asset policy threshold=1 should override the default 3-of-3 requirement"
    );

    multisig_account.apply_delta(tx_result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&tx_result.unwrap())?;
    mock_chain.prove_next_block()?;

    Ok(())
}

/// A procedure policy with `NoInputOrOutputNotes` restriction must abort any transaction that
/// reaches that procedure while carrying input or output notes.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_proc_policy_no_notes_constraint_is_enforced(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        auth_scheme,
        100,
        vec![(
            BasicWallet::receive_asset_digest(),
            ProcedurePolicy::with_immediate_threshold(1)?
                .with_note_restriction(ProcedurePolicyNoteRestriction::NoInputOrOutputNotes),
        )],
    )?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mock_chain = mock_chain_builder.build()?;

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(Word::from([Felt::new(903); 4]))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_OR_OUTPUT_NOTES
    );

    Ok(())
}
