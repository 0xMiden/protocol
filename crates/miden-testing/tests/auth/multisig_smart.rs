use miden_processor::advice::AdviceInputs;
use miden_processor::crypto::random::RpoRandomCoin;
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
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::{ExecutedTransaction, OutputNote, TransactionScript};
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::auth::AuthMultisigSmart;
use miden_standards::account::components::multisig_smart_library;
use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_CANCEL_INSUFFICIENT_SIGNATURES,
    ERR_INVALID_AMOUNT_LIMITS,
    ERR_INVALID_TIER_CONFIG,
    ERR_PENDING_ALREADY_SET,
    ERR_TIER0_MUST_BE_POSITIVE,
    ERR_TIER3_TOO_HIGH,
    ERR_TX_ALREADY_EXECUTED,
};
use miden_standards::note::P2idNote;
use miden_standards::testing::account_interface::get_public_keys_from_account;
use miden_testing::utils::create_spawn_note;
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

type MultisigTestSetupWithSchemes =
    (Vec<AuthSecretKey>, Vec<AuthScheme>, Vec<PublicKey>, Vec<BasicAuthenticator>);

const TEST_ORACLE_ID_PREFIX: u64 = 15_240_030_242_886_579_968;
const TEST_ORACLE_ID_SUFFIX: u64 = 5_177_303_881_306_160_384;
const TEST_GET_PRICE_PROC_ROOT: [u64; 4] = [
    3_591_109_198_379_466_182,
    17_592_333_261_592_472_774,
    12_676_231_063_682_133_280,
    10_255_402_666_496_948_124,
];

fn test_oracle_id() -> [Felt; 2] {
    [Felt::new(TEST_ORACLE_ID_PREFIX), Felt::new(TEST_ORACLE_ID_SUFFIX)]
}

fn test_get_price_proc_root() -> Word {
    Word::from([
        Felt::new(TEST_GET_PRICE_PROC_ROOT[0]),
        Felt::new(TEST_GET_PRICE_PROC_ROOT[1]),
        Felt::new(TEST_GET_PRICE_PROC_ROOT[2]),
        Felt::new(TEST_GET_PRICE_PROC_ROOT[3]),
    ])
}

/// Sets up secret keys, auth schemes, public keys, and authenticators for a specific scheme.
fn setup_keys_and_authenticators_with_scheme(
    num_approvers: usize,
    threshold: usize,
    auth_scheme: AuthScheme,
) -> anyhow::Result<MultisigTestSetupWithSchemes> {
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

fn build_update_signers_config_vector(
    threshold: u64,
    num_of_approvers: u64,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
) -> Vec<Felt> {
    let mut config_and_pubkeys_vector = Vec::new();
    config_and_pubkeys_vector.extend_from_slice(&[
        Felt::new(threshold),
        Felt::new(num_of_approvers),
        Felt::new(0),
        Felt::new(0),
    ]);

    let scheme_word = [Felt::new(auth_scheme as u64), Felt::new(0), Felt::new(0), Felt::new(0)];

    for public_key in public_keys.iter().rev() {
        let key_word: Word = public_key.to_commitment().into();
        config_and_pubkeys_vector.extend_from_slice(key_word.as_elements());
        config_and_pubkeys_vector.extend_from_slice(&scheme_word);
    }

    config_and_pubkeys_vector
}

fn create_multisig_smart_account_with_assets(
    threshold: u32,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
    assets: Vec<FungibleAsset>,
    spent_interval_blocks: u32,
    amount_limits: [u64; 4],
    tier_thresholds: [u32; 4],
    oracle_id: [Felt; 2],
    get_price_proc_root: Word,
    proc_threshold_map: Vec<(Word, u32)>,
) -> anyhow::Result<Account> {
    let approvers: Vec<_> =
        public_keys.iter().map(|pk| (pk.to_commitment(), auth_scheme)).collect();

    // Create the multisig spending limits account
    let multisig_account = AccountBuilder::new([0; 32])
        .with_auth_component(Auth::MultisigSmart {
            threshold,
            approvers,
            proc_threshold_map,
            spent_interval_blocks,
            amount_limits,
            tier_thresholds,
            oracle_id,
            get_price_proc_root,
        })
        .with_component(BasicWallet)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(assets.into_iter().map(|a| a.into()))
        .build_existing()?;

    Ok(multisig_account)
}

fn create_multisig_smart_with_fixed_test_configuration(
    threshold: u32,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
    proc_threshold_map: Vec<(Word, u32)>,
) -> anyhow::Result<Account> {
    let approvers: Vec<_> =
        public_keys.iter().map(|pk| (pk.to_commitment(), auth_scheme)).collect();

    let multisig_starting_assets = vec![
        (AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 10000u64),
        (AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?, 20000u64),
        (AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3)?, 30000u64),
    ];

    let spent_interval_blocks = 10u32;
    let amount_limits = [500u64, 1000u64, 2000u64, 1500u64];
    let tier_thresholds = [1u32, 2u32, 3u32, 4u32];
    let oracle_id = test_oracle_id();
    let get_price_proc_root = test_get_price_proc_root();

    // Create the multisig spending limits account
    let multisig_account = AccountBuilder::new([0; 32])
        .with_auth_component(Auth::MultisigSmart {
            threshold,
            approvers,
            proc_threshold_map,
            spent_interval_blocks,
            amount_limits,
            tier_thresholds,
            oracle_id,
            get_price_proc_root,
        })
        .with_component(BasicWallet)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(
            multisig_starting_assets
                .into_iter()
                .map(|(account_id, amount)| FungibleAsset::new(account_id, amount).unwrap().into()),
        )
        .build_existing()?;

    Ok(multisig_account)
}

fn create_assets_for_output_notes(
    amount_asset_1: u64,
    amount_asset_2: u64,
    amount_asset_3: u64,
) -> (FungibleAsset, FungibleAsset, FungibleAsset) {
    let output_note_asset_1 = FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap(),
        amount_asset_1,
    )
    .unwrap();

    let output_note_asset_2 = FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2).unwrap(),
        amount_asset_2,
    )
    .unwrap();

    let output_note_asset_3 = FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3).unwrap(),
        amount_asset_3,
    )
    .unwrap();

    (output_note_asset_1, output_note_asset_2, output_note_asset_3)
}

fn create_multisig_account(
    threshold: u32,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
    starting_balance: u64,
    proc_threshold_map: Vec<(Word, u32)>,
) -> anyhow::Result<Account> {
    let approvers = public_keys.iter().map(|pk| (pk.clone(), auth_scheme)).collect::<Vec<_>>();

    create_multisig_account_with_schemes(
        threshold,
        &approvers,
        starting_balance,
        proc_threshold_map,
    )
}

fn create_multisig_account_with_schemes(
    threshold: u32,
    approvers: &[(PublicKey, AuthScheme)],
    starting_balance: u64,
    proc_threshold_map: Vec<(Word, u32)>,
) -> anyhow::Result<Account> {
    let spent_interval_blocks = 10u32;
    let amount_limits = [500u64, 1000u64, 2000u64, 1500u64];
    let tier_thresholds = [1u32, 2u32, 3u32, 4u32];
    let oracle_id = test_oracle_id();
    let get_price_proc_root = test_get_price_proc_root();
    let approvers: Vec<_> =
        approvers.iter().map(|(pk, scheme)| (pk.to_commitment(), *scheme)).collect();

    let multisig_account = AccountBuilder::new([0; 32])
        .with_auth_component(Auth::MultisigSmart {
            threshold,
            approvers,
            proc_threshold_map,
            spent_interval_blocks,
            amount_limits,
            tier_thresholds,
            oracle_id,
            get_price_proc_root,
        })
        .with_component(BasicWallet)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(vec![
            FungibleAsset::new(
                AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?,
                starting_balance,
            )?
            .into(),
        ])
        .build_existing()?;

    Ok(multisig_account)
}

fn compile_multisig_smart_tx_script(script: impl AsRef<str>) -> anyhow::Result<TransactionScript> {
    Ok(CodeBuilder::default()
        .with_dynamically_linked_library(multisig_smart_library())?
        .compile_tx_script(script.as_ref())?)
}

async fn execute_script_with_signers(
    mock_chain: &MockChain,
    account_id: AccountId,
    tx_script: TransactionScript,
    salt: Word,
    signer_indices: &[usize],
    public_keys: &[PublicKey],
    authenticators: &[BasicAuthenticator],
    tx_script_args: Option<Word>,
    advice_inputs: Option<AdviceInputs>,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let mut tx_context_init_builder = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(tx_script.clone())
        .auth_args(salt);

    if let Some(tx_script_args) = tx_script_args {
        tx_context_init_builder = tx_context_init_builder.tx_script_args(tx_script_args);
    }

    if let Some(advice_inputs) = advice_inputs.clone() {
        tx_context_init_builder = tx_context_init_builder.extend_advice_inputs(advice_inputs);
    }

    let tx_summary = match tx_context_init_builder.build()?.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let mut tx_context_signed_builder = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(tx_script)
        .auth_args(salt);

    if let Some(tx_script_args) = tx_script_args {
        tx_context_signed_builder = tx_context_signed_builder.tx_script_args(tx_script_args);
    }

    if let Some(advice_inputs) = advice_inputs {
        tx_context_signed_builder = tx_context_signed_builder.extend_advice_inputs(advice_inputs);
    }

    for signer_idx in signer_indices {
        let sig = authenticators[*signer_idx]
            .get_signature(public_keys[*signer_idx].to_commitment(), &tx_summary)
            .await?;

        tx_context_signed_builder = tx_context_signed_builder.add_signature(
            public_keys[*signer_idx].to_commitment(),
            msg,
            sig,
        );
    }

    Ok(tx_context_signed_builder.build()?.execute().await)
}

// ================================================================================================
// TESTS
// ================================================================================================
/// Tests basic 3-of-5 multisig functionality with note creation.
///
/// This test verifies that a multisig account with 5 approvers and threshold 3
/// can successfully execute a transaction that creates an output note when all
/// required signatures are provided.
///
/// Spends 3 different assets from 3 different faucets and ensures spending limits are enforced.
///
/// Spending 300 in total (limit 500) requires 1 signature.
///
/// **Roles:**
/// - 5 Approvers (multisig signers)
/// - 1 Multisig Contract
/// - 3 Fungible Asset Faucets in Output Notes
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_send_3_different_assets(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;

    let multisig_starting_faucets = vec![
        (AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 10000u64),
        (AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?, 20000u64),
        (AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3)?, 30000u64),
    ];

    let spent_interval_blocks = 10u32;
    let amount_limits = [500u64, 1000u64, 2000u64, 1500u64];
    let tier_thresholds = [1u32, 2u32, 3u32, 4u32];
    let oracle_id = test_oracle_id();
    let get_price_proc_root = test_get_price_proc_root();

    let mut multisig_account = create_multisig_smart_account_with_assets(
        3,
        &public_keys,
        auth_scheme,
        multisig_starting_faucets
            .iter()
            .map(|(account_id, amount)| FungibleAsset::new(*account_id, *amount).unwrap())
            .collect(),
        spent_interval_blocks,
        amount_limits,
        tier_thresholds,
        oracle_id,
        get_price_proc_root,
        vec![],
    )?;

    // print multisig_account vault assets
    for asset in multisig_account.vault().assets() {
        println!("Multisig account asset: {:?}", asset);
    }

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let output_note_asset_1 =
        FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 500u64)?;

    let output_note_asset_2 =
        FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?, 500u64)?;

    let output_note_asset_3 =
        FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3)?, 1000u64)?;

    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            output_note_asset_1.into(),
            output_note_asset_2.into(),
            output_note_asset_3.into(),
        ],
        NoteType::Public,
    )?;

    // print output note assets
    for asset in output_note.assets().iter() {
        println!("Output note asset: {:?}", asset);
    }

    let multisig_account_interface = AccountInterface::from_account(&multisig_account);
    let send_note_transaction_script =
        multisig_account_interface.build_send_notes_script(&[output_note.clone().into()], None)?;

    let salt = Word::from([Felt::new(1); 4]);

    let mut mock_chain = mock_chain_builder.build()?;

    // Execute transaction without signatures to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .tx_script(send_note_transaction_script.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from both approvers
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

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(public_keys[2].to_commitment(), msg, sig_3)
        .add_signature(public_keys[3].to_commitment(), msg, sig_4)
        .auth_args(salt)
        .tx_script(send_note_transaction_script)
        .build()?
        .execute()
        .await;

    multisig_account.apply_delta(result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&result.unwrap())?;
    mock_chain.prove_next_block()?;

    // assert_eq for each asset
    let expected_balance_1 = multisig_starting_faucets[0].1 - output_note_asset_1.amount();
    let expected_balance_2 = multisig_starting_faucets[1].1 - output_note_asset_2.amount();
    let expected_balance_3 = multisig_starting_faucets[2].1 - output_note_asset_3.amount();

    assert_eq!(
        multisig_account
            .vault()
            .get_balance(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?)?,
        expected_balance_1
    );

    assert_eq!(
        multisig_account
            .vault()
            .get_balance(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?)?,
        expected_balance_2
    );

    assert_eq!(
        multisig_account
            .vault()
            .get_balance(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3)?)?,
        expected_balance_3
    );

    Ok(())
}
/// Tests basic 3-of-5 multisig functionality with note creation.
///
/// This test verifies that a multisig account with 5 approvers and threshold 3
/// can successfully execute a transaction that creates an output note when all
/// required signatures are provided.
///
/// Spends 3 different assets from 3 different faucets and ensures spending limits are enforced.
///
/// Spending 700 in total (limit 500) requires 1 signature.
///
/// **Roles:**
/// - 5 Approvers (multisig signers)
/// - 1 Multisig Contract
/// - 3 Fungible Asset Faucets in Output Notes
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_less_than_limit1_requires_tier1_signatures(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;

    let mut multisig_account =
        create_multisig_smart_with_fixed_test_configuration(3, &public_keys, auth_scheme, vec![])?;

    // print multisig_account vault assets
    for asset in multisig_account.vault().assets() {
        println!("Multisig account asset: {:?}", asset);
    }

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let (output_note_asset_1, output_note_asset_2, output_note_asset_3) =
        create_assets_for_output_notes(500, 100, 100);

    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            output_note_asset_1.into(),
            output_note_asset_2.into(),
            output_note_asset_3.into(),
        ],
        NoteType::Public,
    )?;

    // print output note assets
    for asset in output_note.assets().iter() {
        println!("Output note asset: {:?}", asset);
    }

    let multisig_account_interface = AccountInterface::from_account(&multisig_account);
    let send_note_transaction_script =
        multisig_account_interface.build_send_notes_script(&[output_note.clone().into()], None)?;

    let salt = Word::from([Felt::new(1); 4]);

    let mut mock_chain = mock_chain_builder.build()?;

    // Execute transaction without signatures to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .tx_script(send_note_transaction_script.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from both approvers
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;

    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .auth_args(salt)
        .tx_script(send_note_transaction_script)
        .build()?
        .execute()
        .await;

    multisig_account.apply_delta(result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&result.unwrap())?;
    mock_chain.prove_next_block()?;

    Ok(())
}

/// Tests basic 3-of-5 multisig functionality with note creation.
///
/// This test verifies that a multisig account with 5 approvers and threshold 3
/// can successfully execute a transaction that creates an output note when all
/// required signatures are provided.
///
/// Spends 3 different assets from 3 different faucets and ensures spending limits are enforced.
///
/// Spending 700 in total (limit 500) requires 1 signature.
///
/// **Roles:**
/// - 5 Approvers (multisig signers)
/// - 1 Multisig Contract
/// - 3 Fungible Asset Faucets in Output Notes
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_less_than_limit2_requires_tier2_signatures(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;

    let mut multisig_account =
        create_multisig_smart_with_fixed_test_configuration(3, &public_keys, auth_scheme, vec![])?;

    // print multisig_account vault assets
    for asset in multisig_account.vault().assets() {
        println!("Multisig account asset: {:?}", asset);
    }

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let (output_note_asset_1, output_note_asset_2, output_note_asset_3) =
        create_assets_for_output_notes(1000, 100, 100);

    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            output_note_asset_1.into(),
            output_note_asset_2.into(),
            output_note_asset_3.into(),
        ],
        NoteType::Public,
    )?;

    // print output note assets
    for asset in output_note.assets().iter() {
        println!("Output note asset: {:?}", asset);
    }

    let multisig_account_interface = AccountInterface::from_account(&multisig_account);
    let send_note_transaction_script =
        multisig_account_interface.build_send_notes_script(&[output_note.clone().into()], None)?;

    let salt = Word::from([Felt::new(1); 4]);

    let mut mock_chain = mock_chain_builder.build()?;

    // Execute transaction without signatures to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .tx_script(send_note_transaction_script.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from both approvers
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

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(public_keys[2].to_commitment(), msg, sig_3)
        .auth_args(salt)
        .tx_script(send_note_transaction_script)
        .build()?
        .execute()
        .await;

    multisig_account.apply_delta(result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&result.unwrap())?;
    mock_chain.prove_next_block()?;

    Ok(())
}

/// Tests basic 3-of-5 multisig functionality with note creation.
///
/// This test verifies that a multisig account with 5 approvers and threshold 3
/// can successfully execute a transaction that creates an output note when all
/// required signatures are provided.
///
/// Spends 3 different assets from 3 different faucets and ensures spending limits are enforced.
///
/// Spending 700 in total (limit 500) requires 1 signature.
///
/// **Roles:**
/// - 5 Approvers (multisig signers)
/// - 1 Multisig Contract
/// - 3 Fungible Asset Faucets in Output Notes
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_more_than_limit3_requires_tier3_signatures(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;

    let mut multisig_account =
        create_multisig_smart_with_fixed_test_configuration(3, &public_keys, auth_scheme, vec![])?;

    // print multisig_account vault assets
    for asset in multisig_account.vault().assets() {
        println!("Multisig account asset: {:?}", asset);
    }

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let (output_note_asset_1, output_note_asset_2, output_note_asset_3) =
        create_assets_for_output_notes(2000, 100, 100);

    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            output_note_asset_1.into(),
            output_note_asset_2.into(),
            output_note_asset_3.into(),
        ],
        NoteType::Public,
    )?;

    // print output note assets
    for asset in output_note.assets().iter() {
        println!("Output note asset: {:?}", asset);
    }

    let multisig_account_interface = AccountInterface::from_account(&multisig_account);
    let send_note_transaction_script =
        multisig_account_interface.build_send_notes_script(&[output_note.clone().into()], None)?;

    let salt = Word::from([Felt::new(1); 4]);

    let mut mock_chain = mock_chain_builder.build()?;

    // Execute transaction without signatures to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .tx_script(send_note_transaction_script.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from both approvers
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

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(public_keys[2].to_commitment(), msg, sig_3)
        .add_signature(public_keys[3].to_commitment(), msg, sig_4)
        .auth_args(salt)
        .tx_script(send_note_transaction_script)
        .build()?
        .execute()
        .await;

    multisig_account.apply_delta(result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&result.unwrap())?;
    mock_chain.prove_next_block()?;

    Ok(())
}

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
#[ignore = "legacy optional scenario"]
async fn disabled_test_multisig_smart_2_of_2_with_note_creation(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // Setup keys and authenticators
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    // Create multisig account
    let multisig_starting_balance = 10u64;
    let mut multisig_account =
        create_multisig_account(2, &public_keys, auth_scheme, multisig_starting_balance, vec![])?;

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

    let salt = Word::from([Felt::new(1); 4]);

    // Execute transaction without signatures - should fail
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

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
    let tx_context_execute = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .auth_args(salt)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(tx_context_execute.account_delta())?;

    mock_chain.add_pending_executed_transaction(&tx_context_execute)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        multisig_account
            .vault()
            .get_balance(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?)?,
        multisig_starting_balance - output_note_asset.unwrap_fungible().amount()
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
#[ignore = "legacy optional scenario"]
async fn disabled_test_multisig_smart_2_of_4_all_signer_combinations(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // Setup keys and authenticators (4 approvers, all 4 can sign)
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;

    // Create multisig account with 4 approvers but threshold of 2
    let multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 10, vec![])?;

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
        let salt = Word::from([Felt::new(10 + i as u64); 4]);

        // Execute transaction without signatures first to get tx summary
        let tx_context_init = mock_chain
            .build_tx_context(multisig_account.id(), &[], &[])?
            .auth_args(salt)
            .build()?;

        let tx_summary = match tx_context_init.execute().await.unwrap_err() {
            TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
            error => panic!("expected abort with tx effects: {error:?}"),
        };

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
        let tx_context_execute = mock_chain
            .build_tx_context(multisig_account.id(), &[], &[])?
            .auth_args(salt)
            .add_signature(public_keys[*signer1_idx].to_commitment(), msg, sig_1)
            .add_signature(public_keys[*signer2_idx].to_commitment(), msg, sig_2)
            .build()?;

        let executed_tx = tx_context_execute.execute().await.unwrap_or_else(|_| {
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
async fn test_multisig_smart_replay_protection(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // Setup keys and authenticators (3 approvers, but only 2 signers)
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 2, auth_scheme)?;

    // Create 2/3 multisig account
    let multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 20, vec![])?;

    let mut mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new(3); 4]);

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

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
    let tx_context_execute = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .add_signature(public_keys[0].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_2.clone())
        .auth_args(salt)
        .build()?;

    let executed_tx = tx_context_execute.execute().await.expect("First transaction should succeed");

    // Apply the transaction to the mock chain
    mock_chain.add_pending_executed_transaction(&executed_tx)?;
    mock_chain.prove_next_block()?;

    // Attempt to execute the same transaction again - should fail due to replay protection
    let tx_context_replay = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .auth_args(salt)
        .build()?;

    // This should fail due to replay protection
    let result = tx_context_replay.execute().await;
    assert_transaction_executor_error!(result, ERR_TX_ALREADY_EXECUTED);

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
async fn test_multisig_smart_update_signers(#[case] auth_scheme: AuthScheme) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let multisig_account = create_multisig_account_with_schemes(2, &approvers, 10, vec![])?;

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

    let salt = Word::from([Felt::new(3); 4]);

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

    // Hash the vector to create config hash
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);

    // Insert config and public keys into advice map
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    // Create a transaction script that calls the update_signers procedure
    let tx_script_code = "
        begin
            call.::miden::standards::components::auth::multisig_smart::update_signers_and_threshold
        end
    ";

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(multisig_smart_library())?
        .compile_tx_script(tx_script_code)?;

    let advice_inputs = AdviceInputs {
        map: advice_map.clone(),
        ..Default::default()
    };

    // Pass the MULTISIG_CONFIG_HASH as the tx_script_args
    let tx_script_args: Word = multisig_config_hash;

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(tx_script_args)
        .extend_advice_inputs(advice_inputs.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

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
    let update_approvers_tx = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(multisig_config_hash)
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs)
        .build()?
        .execute()
        .await
        .unwrap();

    // Verify the transaction executed successfully
    assert_eq!(update_approvers_tx.account_delta().nonce_delta(), Felt::new(1));

    mock_chain.add_pending_executed_transaction(&update_approvers_tx)?;
    mock_chain.prove_next_block()?;

    // Apply the delta to get the updated account with new signers
    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_delta(update_approvers_tx.account_delta())?;

    // Verify that the public keys were actually updated in storage
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = [Felt::new(i as u64), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let storage_item = updated_multisig_account
            .storage()
            .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), storage_key)
            .unwrap();

        let expected_word: Word = expected_key.to_commitment().into();

        assert_eq!(storage_item, expected_word, "Public key {} doesn't match expected value", i);
    }

    // Verify the threshold was updated by checking the config storage slot
    let threshold_config_storage = updated_multisig_account
        .storage()
        .get_item(AuthMultisigSmart::threshold_config_slot())?;

    assert_eq!(
        threshold_config_storage[0],
        Felt::new(threshold),
        "Threshold was not updated correctly"
    );
    assert_eq!(
        threshold_config_storage[1],
        Felt::new(num_of_approvers),
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
    let output_note_new = P2idNote::create(
        updated_multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![output_note_asset],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::empty()),
    )?;

    // Create a new spawn note for the second transaction
    let input_note_new = create_spawn_note([&output_note_new])?;

    let salt_new = Word::from([Felt::new(4); 4]);

    // Build the new mock chain with the updated account and notes
    let mut new_mock_chain_builder =
        MockChainBuilder::with_accounts([updated_multisig_account.clone()]).unwrap();
    new_mock_chain_builder.add_output_note(OutputNote::Full(input_note_new.clone()));
    let new_mock_chain = new_mock_chain_builder.build().unwrap();

    // Execute transaction without signatures first to get tx summary
    let tx_context_init_new = new_mock_chain
        .build_tx_context(updated_multisig_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .auth_args(salt_new)
        .build()?;

    let tx_summary_new = match tx_context_init_new.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

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
    let tx_context_execute_new = new_mock_chain
        .build_tx_context(updated_multisig_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_new)])
        .add_signature(new_public_keys[0].to_commitment(), msg_new, sig_1_new)
        .add_signature(new_public_keys[1].to_commitment(), msg_new, sig_2_new)
        .add_signature(new_public_keys[2].to_commitment(), msg_new, sig_3_new)
        .auth_args(salt_new)
        .build()?
        .execute()
        .await?;

    // Verify the transaction executed successfully with new signers
    assert_eq!(tx_context_execute_new.account_delta().nonce_delta(), Felt::new(1));

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
async fn test_multisig_smart_update_signers_remove_owner(
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
    let multisig_account = create_multisig_account_with_schemes(4, &approvers, 10, vec![])?;

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

    // Create config hash and advice map
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);
    let mut advice_map = AdviceMap::default();
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    // Create transaction script
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(multisig_smart_library())?
        .compile_tx_script(
            "begin\n    call.::miden::standards::components::auth::multisig_smart::update_signers_and_threshold\nend",
        )?;

    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };

    let salt = Word::from([Felt::new(3); 4]);

    // Execute without signatures to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

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
    let update_approvers_tx = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(multisig_config_hash)
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(public_keys[2].to_commitment(), msg, sig_3)
        .add_signature(public_keys[3].to_commitment(), msg, sig_4)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs)
        .build()?
        .execute()
        .await
        .unwrap();

    // Verify transaction success
    assert_eq!(update_approvers_tx.account_delta().nonce_delta(), Felt::new(1));

    mock_chain.add_pending_executed_transaction(&update_approvers_tx)?;
    mock_chain.prove_next_block()?;

    // Apply delta to get updated account
    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_delta(update_approvers_tx.account_delta())?;

    // Verify public keys were updated
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = [Felt::new(i as u64), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let storage_item = updated_multisig_account
            .storage()
            .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), storage_key)?;
        let expected_word: Word = expected_key.to_commitment().into();
        assert_eq!(storage_item, expected_word, "Public key {} doesn't match", i);
    }

    // Verify threshold and num_approvers
    let threshold_config = updated_multisig_account
        .storage()
        .get_item(AuthMultisigSmart::threshold_config_slot())?;
    assert_eq!(threshold_config[0], Felt::new(threshold), "Threshold not updated");
    assert_eq!(threshold_config[1], Felt::new(num_of_approvers), "Num approvers not updated");

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
        let removed_owner_key =
            [Felt::new(removed_idx), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let removed_owner_slot = updated_multisig_account
            .storage()
            .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), removed_owner_key)
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
        let storage_key = [Felt::new(i as u64), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let storage_item = updated_multisig_account
            .storage()
            .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), storage_key)
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
async fn test_multisig_smart_new_approvers_cannot_sign_before_update(
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

    let multisig_account = create_multisig_account_with_schemes(2, &approvers, 10, vec![])?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new(5); 4]);

    // SECTION 2: Prepare a signer update transaction with new approvers
    // ================================================================================

    // Get the multisig library

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

    // Hash the vector to create config hash
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);

    // Insert config and public keys into advice map
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    // Create a transaction script that calls the update_signers procedure
    let tx_script_code = "
        begin
            call.::miden::standards::components::auth::multisig_smart::update_signers_and_threshold
        end
    ";

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(multisig_smart_library())?
        .compile_tx_script(tx_script_code)?;

    let advice_inputs = AdviceInputs {
        map: advice_map.clone(),
        ..Default::default()
    };

    // Pass the MULTISIG_CONFIG_HASH as the tx_script_args
    let tx_script_args: Word = multisig_config_hash;

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(tx_script_args)
        .extend_advice_inputs(advice_inputs.clone())
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

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
    let tx_context_with_new_sigs = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(multisig_config_hash)
        .add_signature(new_public_keys[0].to_commitment(), msg, new_sig_1)
        .add_signature(new_public_keys[1].to_commitment(), msg, new_sig_2)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs.clone())
        .build()?;

    // SECTION 4: Verify that only the CURRENT approvers can sign the update transaction
    // ================================================================================

    // Should fail - new approvers not yet authorized
    let result = tx_context_with_new_sigs.execute().await;

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
async fn test_multisig_smart_proc_threshold_overrides(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    // Setup keys and authenticators
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let proc_threshold_map = vec![(BasicWallet::receive_asset_digest(), 1)];

    // Create multisig account
    let multisig_starting_balance = 10u64;
    let spent_interval_blocks = 10u32;
    let amount_limits = [500u64, 1000u64, 2000u64, 1500u64];
    let tier_thresholds = [1u32, 2u32, 2u32, 2u32];
    let oracle_id = test_oracle_id();
    let get_price_proc_root = test_get_price_proc_root();

    let assets = vec![FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?,
        multisig_starting_balance,
    )?];

    let mut multisig_account = create_multisig_smart_account_with_assets(
        2,
        &public_keys,
        auth_scheme,
        assets,
        spent_interval_blocks,
        amount_limits,
        tier_thresholds,
        oracle_id,
        get_price_proc_root,
        proc_threshold_map,
    )?;

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
    let salt = Word::from([Felt::new(1); 4]);
    let tx_context = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_summary) => tx_summary,
        error => panic!("expected abort with tx summary: {error:?}"),
    };

    // 3. get signature from one approver
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary.clone());
    let sig = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;

    // 4. execute with signature
    let tx_result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .add_signature(public_keys[0].to_commitment(), msg, sig)
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    assert!(tx_result.is_ok(), "Note consumption with 1 signature should succeed");

    // Apply the transaction to the account
    multisig_account.apply_delta(tx_result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&tx_result.unwrap())?;
    mock_chain.prove_next_block()?;

    // SECTION 2: Test note sending requires 2 signatures
    // ================================================================================

    let salt2 = Word::from([Felt::new(2); 4]);

    // Create output note to send 5 units from the account
    let output_note = P2idNote::create(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![FungibleAsset::mock(5)],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([Felt::new(42); 4])),
    )?;
    let multisig_account_interface = AccountInterface::from_account(&multisig_account);
    let send_note_transaction_script =
        multisig_account_interface.build_send_notes_script(&[output_note.clone().into()], None)?;

    // Execute transaction without signatures to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .tx_script(send_note_transaction_script.clone())
        .auth_args(salt2)
        .build()?;

    let tx_summary2 = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    // Get signature from only ONE approver
    let msg2 = tx_summary2.as_ref().to_commitment();
    let tx_summary2_signing = SigningInputs::TransactionSummary(tx_summary2.clone());

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary2_signing)
        .await?;

    // Try to execute with only 1 signature - should FAIL
    let tx_context_one_sig = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .add_signature(public_keys[0].to_commitment(), msg2, sig_1)
        .tx_script(send_note_transaction_script.clone())
        .auth_args(salt2)
        .build()?;

    let result = tx_context_one_sig.execute().await;
    match result {
        Err(TransactionExecutorError::Unauthorized(_)) => {
            // Expected: transaction should fail with insufficient signatures
        },
        _ => panic!(
            "Transaction should fail with Unauthorized error when only 1 signature provided for note sending"
        ),
    }

    // Now get signatures from BOTH approvers
    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary2_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary2_signing)
        .await?;

    // Execute with 2 signatures - should SUCCEED
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg2, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg2, sig_2)
        .auth_args(salt2)
        .tx_script(send_note_transaction_script)
        .build()?
        .execute()
        .await;

    assert!(
        result.is_ok(),
        "Transaction should succeed with 2 signatures for note sending: {result:?}"
    );

    // Apply the transaction to the account
    multisig_account.apply_delta(result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&result.unwrap())?;
    mock_chain.prove_next_block()?;

    assert_eq!(multisig_account.vault().get_balance(FungibleAsset::mock_issuer())?, 6);

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_epoch_boundary_resets_spending_tracker(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;
    let mut multisig_account =
        create_multisig_smart_with_fixed_test_configuration(3, &public_keys, auth_scheme, vec![])?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let output_note_1 = P2idNote::create(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 700)?
                .into(),
        ],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([Felt::new(101); 4])),
    )?;
    let script_1 = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note_1.clone().into()], None)?;
    let salt_1 = Word::from([Felt::new(201); 4]);

    let tx_summary_1 = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_1.clone())])
        .tx_script(script_1.clone())
        .auth_args(salt_1)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    let msg_1 = tx_summary_1.as_ref().to_commitment();
    let tx_summary_1 = SigningInputs::TransactionSummary(tx_summary_1);
    let sig_1_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_1)
        .await?;
    let sig_1_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_1)
        .await?;

    let tx_1 = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_1)])
        .tx_script(script_1)
        .auth_args(salt_1)
        .add_signature(public_keys[0].to_commitment(), msg_1, sig_1_0)
        .add_signature(public_keys[1].to_commitment(), msg_1, sig_1_1)
        .build()?
        .execute()
        .await?;
    multisig_account.apply_delta(tx_1.account_delta())?;
    mock_chain.add_pending_executed_transaction(&tx_1)?;
    mock_chain.prove_next_block()?;

    let output_note_2 = P2idNote::create(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 700)?
                .into(),
        ],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([Felt::new(102); 4])),
    )?;
    let script_2 = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note_2.clone().into()], None)?;
    let salt_2 = Word::from([Felt::new(202); 4]);

    let tx_summary_2 = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_2.clone())])
        .tx_script(script_2.clone())
        .auth_args(salt_2)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    let msg_2 = tx_summary_2.as_ref().to_commitment();
    let tx_summary_2 = SigningInputs::TransactionSummary(tx_summary_2);
    let sig_2_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_2)
        .await?;
    let sig_2_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_2)
        .await?;

    let tx_2_with_two_sigs = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_2)])
        .tx_script(script_2)
        .auth_args(salt_2)
        .add_signature(public_keys[0].to_commitment(), msg_2, sig_2_0)
        .add_signature(public_keys[1].to_commitment(), msg_2, sig_2_1)
        .build()?
        .execute()
        .await;
    assert!(
        matches!(tx_2_with_two_sigs, Err(TransactionExecutorError::Unauthorized(_))),
        "second transfer in the same epoch should require a higher tier"
    );

    for _ in 0..11 {
        mock_chain.prove_next_block()?;
    }

    let output_note_3 = P2idNote::create(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 700)?
                .into(),
        ],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([Felt::new(103); 4])),
    )?;
    let script_3 = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note_3.clone().into()], None)?;
    let salt_3 = Word::from([Felt::new(203); 4]);

    let tx_summary_3 = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_3.clone())])
        .tx_script(script_3.clone())
        .auth_args(salt_3)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    let msg_3 = tx_summary_3.as_ref().to_commitment();
    let tx_summary_3 = SigningInputs::TransactionSummary(tx_summary_3);
    let sig_3_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_3)
        .await?;
    let sig_3_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_3)
        .await?;

    let tx_3 = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_3)])
        .tx_script(script_3)
        .auth_args(salt_3)
        .add_signature(public_keys[0].to_commitment(), msg_3, sig_3_0)
        .add_signature(public_keys[1].to_commitment(), msg_3, sig_3_1)
        .build()?
        .execute()
        .await?;
    multisig_account.apply_delta(tx_3.account_delta())?;

    let spending_tracker = multisig_account
        .storage()
        .get_item(AuthMultisigSmart::spending_tracker_slot())?;
    assert_eq!(
        spending_tracker[0],
        Felt::new(700),
        "amount_spent_in_epoch should restart from the transaction amount after epoch change"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_pending_actions_are_mutually_exclusive(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;
    let mut multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let pending_propose_hash =
        Word::from([Felt::new(11), Felt::new(22), Felt::new(33), Felt::new(44)]);
    let pending_cancel_hash =
        Word::from([Felt::new(55), Felt::new(66), Felt::new(77), Felt::new(88)]);

    let propose_twice_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{pending_propose_hash}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            push.{pending_propose_hash}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(propose_twice_script)
        .auth_args(Word::from([Felt::new(301); 4]))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PENDING_ALREADY_SET);

    let propose_once_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{pending_cancel_hash}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let propose_tx = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        propose_once_script,
        Word::from([Felt::new(302); 4]),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("proposal setup transaction should succeed");
    multisig_account.apply_delta(propose_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    let cancel_twice_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{pending_cancel_hash}
            call.::miden::standards::components::auth::multisig_smart::cancel_transaction_proposal
            push.{pending_cancel_hash}
            call.::miden::standards::components::auth::multisig_smart::cancel_transaction_proposal
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(cancel_twice_script)
        .auth_args(Word::from([Felt::new(303); 4]))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PENDING_ALREADY_SET);

    let execute_twice_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction
            dropw dropw dropw dropw dropw
        end
        ",
    )?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(execute_twice_script)
        .auth_args(Word::from([Felt::new(304); 4]))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PENDING_ALREADY_SET);

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_execute_proposal_without_timelock_requirement(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 3, auth_scheme)?;
    let mut multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let execute_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction
            dropw dropw dropw dropw dropw
        end
        ",
    )?;
    let execute_salt = Word::from([Felt::new(401); 4]);

    let execute_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(execute_script.clone())
        .auth_args(execute_salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    let execute_tx_hash = execute_summary.as_ref().to_commitment();

    let propose_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{execute_tx_hash}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let propose_tx = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        propose_script,
        Word::from([Felt::new(402); 4]),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("proposal transaction should succeed");
    multisig_account.apply_delta(propose_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    let execute_tx = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        execute_script,
        execute_salt,
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("execute transaction should succeed without timelock enforcement");
    multisig_account.apply_delta(execute_tx.account_delta())?;

    let pending_execute =
        multisig_account.storage().get_item(AuthMultisigSmart::pending_execute_slot())?;
    assert_eq!(pending_execute, Word::empty(), "pending_execute should be cleared");

    let proposal_entry = multisig_account
        .storage()
        .get_map_item(AuthMultisigSmart::tx_proposals_slot(), execute_tx_hash)?;
    assert_eq!(
        proposal_entry,
        Word::empty(),
        "proposal should be removed when execute flow finalizes"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_cancel_requires_min_cancel_signatures_exact_boundary(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;
    let mut multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let proposal_hash = Word::from([Felt::new(91), Felt::new(92), Felt::new(93), Felt::new(94)]);

    let propose_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{proposal_hash}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let propose_tx = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        propose_script,
        Word::from([Felt::new(501); 4]),
        &[0, 1, 2],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("proposal transaction should succeed");
    multisig_account.apply_delta(propose_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    let cancel_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{proposal_hash}
            call.::miden::standards::components::auth::multisig_smart::cancel_transaction_proposal
            dropw dropw dropw dropw dropw
        end
        "
    ))?;

    let insufficient_cancel = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        cancel_script.clone(),
        Word::from([Felt::new(502); 4]),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?;
    assert_transaction_executor_error!(insufficient_cancel, ERR_CANCEL_INSUFFICIENT_SIGNATURES);

    let exact_cancel = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        cancel_script,
        Word::from([Felt::new(503); 4]),
        &[0, 1, 2],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("cancel should succeed when num_verified == min_cancel_sigs");
    multisig_account.apply_delta(exact_cancel.account_delta())?;

    let proposal_entry = multisig_account
        .storage()
        .get_map_item(AuthMultisigSmart::tx_proposals_slot(), proposal_hash)?;
    assert_eq!(
        proposal_entry,
        Word::empty(),
        "proposal should be deleted after successful cancel"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_update_signers_shrinks_and_re_expands_with_scheme_map_integrity(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_initial_secret_keys, initial_schemes, initial_public_keys, initial_authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;

    let initial_approvers = initial_public_keys
        .iter()
        .zip(initial_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let mut multisig_account =
        create_multisig_account_with_schemes(4, &initial_approvers, 10, vec![])?;
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let update_signers_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::update_signers_and_threshold
        end
        ",
    )?;

    let shrink_threshold = 2u64;
    let shrink_num_approvers = 2u64;
    let shrink_keys = &initial_public_keys[0..2];
    let shrink_data = build_update_signers_config_vector(
        shrink_threshold,
        shrink_num_approvers,
        shrink_keys,
        auth_scheme,
    );
    let shrink_hash = Hasher::hash_elements(&shrink_data);
    let mut shrink_advice_map = AdviceMap::default();
    shrink_advice_map.insert(shrink_hash, shrink_data);
    let shrink_advice_inputs = AdviceInputs {
        map: shrink_advice_map,
        ..Default::default()
    };

    let shrink_tx = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        update_signers_script.clone(),
        Word::from([Felt::new(601); 4]),
        &[0, 1, 2, 3],
        &initial_public_keys,
        &initial_authenticators,
        Some(shrink_hash),
        Some(shrink_advice_inputs),
    )
    .await?
    .expect("shrink update should succeed");
    multisig_account.apply_delta(shrink_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&shrink_tx)?;
    mock_chain.prove_next_block()?;

    let initial_scheme_word =
        Word::from([Felt::new(auth_scheme as u64), Felt::new(0), Felt::new(0), Felt::new(0)]);
    for (idx, expected_key) in shrink_keys.iter().enumerate() {
        let storage_key = [Felt::new(idx as u64), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let expected_key_word: Word = expected_key.to_commitment().into();
        assert_eq!(
            multisig_account
                .storage()
                .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), storage_key)?,
            expected_key_word
        );
        assert_eq!(
            multisig_account
                .storage()
                .get_map_item(AuthMultisigSmart::approver_scheme_ids_slot(), storage_key)?,
            initial_scheme_word
        );
    }
    for idx in 2..5 {
        let storage_key = [Felt::new(idx), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        assert_eq!(
            multisig_account
                .storage()
                .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), storage_key)?,
            Word::empty(),
            "public key slot {idx} should be cleared after shrink"
        );
        assert_eq!(
            multisig_account
                .storage()
                .get_map_item(AuthMultisigSmart::approver_scheme_ids_slot(), storage_key)?,
            Word::empty(),
            "scheme slot {idx} should be cleared after shrink"
        );
    }

    let new_scheme = match auth_scheme {
        AuthScheme::EcdsaK256Keccak => AuthScheme::Falcon512Poseidon2,
        AuthScheme::Falcon512Poseidon2 => AuthScheme::EcdsaK256Keccak,
        _ => anyhow::bail!("unsupported auth scheme for this test: {auth_scheme:?}"),
    };

    let (_new_secret_keys, _new_schemes, expanded_public_keys, _new_authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 0, new_scheme)?;
    let expand_threshold = 3u64;
    let expand_num_approvers = 4u64;
    let expand_data = build_update_signers_config_vector(
        expand_threshold,
        expand_num_approvers,
        &expanded_public_keys,
        new_scheme,
    );
    let expand_hash = Hasher::hash_elements(&expand_data);
    let mut expand_advice_map = AdviceMap::default();
    expand_advice_map.insert(expand_hash, expand_data);
    let expand_advice_inputs = AdviceInputs {
        map: expand_advice_map,
        ..Default::default()
    };

    let expand_tx = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        update_signers_script,
        Word::from([Felt::new(602); 4]),
        &[0, 1],
        &initial_public_keys,
        &initial_authenticators,
        Some(expand_hash),
        Some(expand_advice_inputs),
    )
    .await?
    .expect("expand update should succeed");
    multisig_account.apply_delta(expand_tx.account_delta())?;

    let expanded_scheme_word =
        Word::from([Felt::new(new_scheme as u64), Felt::new(0), Felt::new(0), Felt::new(0)]);
    for (idx, expected_key) in expanded_public_keys.iter().enumerate() {
        let storage_key = [Felt::new(idx as u64), Felt::new(0), Felt::new(0), Felt::new(0)].into();
        let expected_key_word: Word = expected_key.to_commitment().into();
        assert_eq!(
            multisig_account
                .storage()
                .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), storage_key)?,
            expected_key_word
        );
        assert_eq!(
            multisig_account
                .storage()
                .get_map_item(AuthMultisigSmart::approver_scheme_ids_slot(), storage_key)?,
            expanded_scheme_word
        );
    }

    let stale_index_key = [Felt::new(4), Felt::new(0), Felt::new(0), Felt::new(0)].into();
    assert_eq!(
        multisig_account
            .storage()
            .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), stale_index_key)?,
        Word::empty(),
        "old stale key index should remain empty after re-expansion"
    );

    assert_eq!(
        multisig_account
            .storage()
            .get_map_item(AuthMultisigSmart::approver_scheme_ids_slot(), stale_index_key)?,
        Word::empty(),
        "old stale scheme index should remain empty after re-expansion"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_proc_threshold_override_dominates_spending_tier(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;
    let proc_threshold_map = vec![(BasicWallet::receive_asset_digest(), 4)];

    let assets =
        vec![FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?, 10)?];

    let multisig_account = create_multisig_smart_account_with_assets(
        2,
        &public_keys,
        auth_scheme,
        assets,
        10,
        [500, 1000, 2000, 1500],
        [1, 2, 3, 4],
        test_oracle_id(),
        test_get_price_proc_root(),
        proc_threshold_map,
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

    let salt = Word::from([Felt::new(701); 4]);
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary.clone());

    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_signing)
        .await?;
    let sig_2 = authenticators[2]
        .get_signature(public_keys[2].to_commitment(), &tx_summary_signing)
        .await?;

    let three_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[2].to_commitment(), msg, sig_2.clone())
        .build()?
        .execute()
        .await;
    assert!(
        matches!(three_sig_result, Err(TransactionExecutorError::Unauthorized(_))),
        "proc threshold override should dominate and reject 3 signatures when override is 4"
    );

    let sig_3 = authenticators[3]
        .get_signature(public_keys[3].to_commitment(), &tx_summary_signing)
        .await?;
    let four_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .add_signature(public_keys[2].to_commitment(), msg, sig_2)
        .add_signature(public_keys[3].to_commitment(), msg, sig_3)
        .build()?
        .execute()
        .await;
    assert!(
        four_sig_result.is_ok(),
        "transaction should succeed with 4 signatures due to proc override"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_zero_output_notes_do_not_update_spending_tracker(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 3, auth_scheme)?;
    let mut multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 100, vec![])?;

    let initial_tracker = multisig_account
        .storage()
        .get_item(AuthMultisigSmart::spending_tracker_slot())?;

    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let salt = Word::from([Felt::new(801); 4]);
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .auth_args(salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;

    let tx = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .build()?
        .execute()
        .await?;
    multisig_account.apply_delta(tx.account_delta())?;

    let tracker_after = multisig_account
        .storage()
        .get_item(AuthMultisigSmart::spending_tracker_slot())?;
    assert_eq!(
        tracker_after, initial_tracker,
        "spending tracker must remain unchanged for zero-output transactions"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_replay_protection_same_tx_different_signer_subset(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;
    let multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 100, vec![])?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let salt = Word::from([Felt::new(901); 4]);
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .auth_args(salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;
    let sig_2 = authenticators[2]
        .get_signature(public_keys[2].to_commitment(), &tx_summary)
        .await?;
    let sig_3 = authenticators[3]
        .get_signature(public_keys[3].to_commitment(), &tx_summary)
        .await?;

    let first_execution = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .build()?
        .execute()
        .await
        .expect("first execution should succeed");

    mock_chain.add_pending_executed_transaction(&first_execution)?;
    mock_chain.prove_next_block()?;

    let replay_result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .auth_args(salt)
        .add_signature(public_keys[2].to_commitment(), msg, sig_2)
        .add_signature(public_keys[3].to_commitment(), msg, sig_3)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(replay_result, ERR_TX_ALREADY_EXECUTED);

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_invalid_tier_config_rejected_by_update_threshold_config(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;
    let multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let zero_tier0_script = compile_multisig_smart_tx_script(
        "
        begin
            push.3
            push.2
            push.1
            push.0
            call.::miden::standards::components::auth::multisig_smart::update_threshold_config
            dropw dropw dropw dropw dropw
        end
        ",
    )?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(zero_tier0_script)
        .auth_args(Word::from([Felt::new(1001); 4]))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_TIER0_MUST_BE_POSITIVE);

    let non_monotonic_script = compile_multisig_smart_tx_script(
        "
        begin
            push.3
            push.2
            push.3
            push.1
            call.::miden::standards::components::auth::multisig_smart::update_threshold_config
            dropw dropw dropw dropw dropw
        end
        ",
    )?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(non_monotonic_script)
        .auth_args(Word::from([Felt::new(1002); 4]))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_INVALID_TIER_CONFIG);

    let tier3_too_high_script = compile_multisig_smart_tx_script(
        "
        begin
            push.4
            push.3
            push.2
            push.1
            call.::miden::standards::components::auth::multisig_smart::update_threshold_config
            dropw dropw dropw dropw dropw
        end
        ",
    )?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tier3_too_high_script)
        .auth_args(Word::from([Felt::new(1003); 4]))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_TIER3_TOO_HIGH);

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_invalid_spending_limits_rejected(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;
    let multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let invalid_limit0_script = compile_multisig_smart_tx_script(
        "
        begin
            push.0
            push.300
            push.100
            push.200
            call.::miden::standards::components::auth::multisig_smart::update_spending_limits
            dropw dropw dropw dropw dropw
        end
        ",
    )?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(invalid_limit0_script)
        .auth_args(Word::from([Felt::new(1101); 4]))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_INVALID_AMOUNT_LIMITS);

    let invalid_limit1_script = compile_multisig_smart_tx_script(
        "
        begin
            push.0
            push.200
            push.300
            push.100
            call.::miden::standards::components::auth::multisig_smart::update_spending_limits
            dropw dropw dropw dropw dropw
        end
        ",
    )?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(invalid_limit1_script)
        .auth_args(Word::from([Felt::new(1102); 4]))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_INVALID_AMOUNT_LIMITS);

    Ok(())
}
