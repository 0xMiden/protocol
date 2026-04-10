use miden_processor::advice::AdviceInputs;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::note::{NoteType, PartialNote};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionScript};
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::auth::multisig_smart::{
    AmountLimits,
    OracleId,
    OracleReaderConfig,
    ProcedurePolicy,
    ProcedurePolicyNoteRestriction,
    SpendingPolicyConfig,
    TierThresholds,
    TimelockControllerConfig,
};
use miden_standards::account::auth::{
    AuthMultisigSmart,
    AuthMultisigSmartConfig,
    AuthMultisigSmartPresets,
};
use miden_standards::account::components::multisig_smart_library;
use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_OR_OUTPUT_NOTES,
    ERR_CANCEL_INSUFFICIENT_SIGNATURES,
    ERR_INVALID_AMOUNT_LIMITS,
    ERR_INVALID_TIER_CONFIG,
    ERR_PENDING_ALREADY_SET,
    ERR_TIER0_MUST_BE_POSITIVE,
    ERR_TIER3_TOO_HIGH,
    ERR_TX_ALREADY_EXECUTED,
    ERR_TX_STILL_TIMELOCKED,
};
use miden_standards::note::P2idNote;
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

#[derive(Clone, Copy)]
enum TestOracleMode {
    OneToOneTracked,
    FixedPrice(u64),
    Untracked,
}

struct TestOracleFixture {
    account: Account,
    oracle_id: [Felt; 2],
    get_price_proc_root: Word,
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

fn build_test_oracle_fixture(mode: TestOracleMode) -> anyhow::Result<TestOracleFixture> {
    let oracle_code_source = match mode {
        TestOracleMode::OneToOneTracked => "
            use miden::core::sys

            pub proc get_median
                drop drop
                push.1
                exec.sys::truncate_stack
            end
            "
        .to_string(),
        TestOracleMode::FixedPrice(fixed_price) => format!(
            "
            use miden::core::sys

            pub proc get_median
                drop drop drop
                push.{fixed_price}
                push.1
                exec.sys::truncate_stack
            end
            "
        ),
        TestOracleMode::Untracked => "
            use miden::core::sys

            pub proc get_median
                drop drop drop
                push.0
                push.0
                exec.sys::truncate_stack
            end
            "
        .to_string(),
    };

    let oracle_component = AccountComponent::new(
        CodeBuilder::default().compile_component_code("test::oracle", oracle_code_source)?,
        vec![],
        AccountComponentMetadata::mock("test::oracle"),
    )?;
    let get_price_proc_root = oracle_component
        .get_procedure_root_by_path("test::oracle::get_median")
        .expect("test oracle component should export get_median");

    let account = AccountBuilder::new(rand::random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(oracle_component)
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    Ok(TestOracleFixture {
        oracle_id: [account.id().prefix().as_felt(), account.id().suffix()],
        get_price_proc_root,
        account,
    })
}

fn test_oracle_foreign_account_inputs(
    mock_chain: &MockChain,
    oracle_fixture: &TestOracleFixture,
) -> anyhow::Result<Vec<(Account, AccountWitness)>> {
    Ok(vec![mock_chain.get_foreign_account_inputs(oracle_fixture.account.id())?])
}

fn create_multisig_smart_account_with_assets_and_optional_oracle(
    threshold: u32,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
    assets: Vec<FungibleAsset>,
    amount_limits: [u64; 4],
    tier_thresholds: [u32; 4],
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
    oracle_config: Option<([Felt; 2], Word)>,
) -> anyhow::Result<Account> {
    let approvers: Vec<_> =
        public_keys.iter().map(|pk| (pk.to_commitment(), auth_scheme)).collect();
    let mut config = AuthMultisigSmartConfig::new(approvers, threshold)?
        .with_proc_policies(proc_policy_map)?
        .with_spending(SpendingPolicyConfig::new(
            100,
            AmountLimits::new(
                amount_limits[0],
                amount_limits[1],
                amount_limits[2],
                amount_limits[3],
            ),
            TierThresholds::new(
                tier_thresholds[0],
                tier_thresholds[1],
                tier_thresholds[2],
                tier_thresholds[3],
            ),
        ))
        .with_timelock_controller_config(TimelockControllerConfig::new(30, 2));

    if let Some(([prefix, suffix], get_price_proc_root)) = oracle_config {
        config = config.with_oracle_reader(OracleReaderConfig::new(
            OracleId::new(prefix, suffix),
            get_price_proc_root,
        ));
    }

    let multisig_account = AccountBuilder::new([0; 32])
        .with_auth_component(AuthMultisigSmart::new(config)?)
        .with_component(BasicWallet)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(assets.into_iter().map(|a| a.into()))
        .build_existing()?;

    Ok(multisig_account)
}

fn create_multisig_smart_account_with_assets(
    threshold: u32,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
    assets: Vec<FungibleAsset>,
    amount_limits: [u64; 4],
    tier_thresholds: [u32; 4],
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
) -> anyhow::Result<Account> {
    create_multisig_smart_account_with_assets_and_optional_oracle(
        threshold,
        public_keys,
        auth_scheme,
        assets,
        amount_limits,
        tier_thresholds,
        proc_policy_map,
        None,
    )
}

fn create_multisig_smart_account_with_assets_and_oracle(
    threshold: u32,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
    assets: Vec<FungibleAsset>,
    amount_limits: [u64; 4],
    tier_thresholds: [u32; 4],
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
    oracle_fixture: &TestOracleFixture,
) -> anyhow::Result<Account> {
    create_multisig_smart_account_with_assets_and_optional_oracle(
        threshold,
        public_keys,
        auth_scheme,
        assets,
        amount_limits,
        tier_thresholds,
        proc_policy_map,
        Some((oracle_fixture.oracle_id, oracle_fixture.get_price_proc_root)),
    )
}

fn create_multisig_smart_with_fixed_test_configuration_and_oracle(
    threshold: u32,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
    oracle_fixture: &TestOracleFixture,
) -> anyhow::Result<Account> {
    let multisig_starting_assets = vec![
        (AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 10000u64),
        (AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?, 20000u64),
        (AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3)?, 30000u64),
    ];

    create_multisig_smart_account_with_assets_and_oracle(
        threshold,
        public_keys,
        auth_scheme,
        multisig_starting_assets
            .into_iter()
            .map(|(account_id, amount)| FungibleAsset::new(account_id, amount).unwrap())
            .collect(),
        [500, 1000, 2000, 1500],
        [1, 2, 3, 4],
        proc_policy_map,
        oracle_fixture,
    )
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
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
) -> anyhow::Result<Account> {
    let approvers = public_keys.iter().map(|pk| (pk.clone(), auth_scheme)).collect::<Vec<_>>();

    create_multisig_account_with_schemes(threshold, &approvers, starting_balance, proc_policy_map)
}

fn create_multisig_account_with_schemes(
    threshold: u32,
    approvers: &[(PublicKey, AuthScheme)],
    starting_balance: u64,
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
) -> anyhow::Result<Account> {
    let num_approvers = approvers.len() as u32;
    let public_keys = approvers.iter().map(|(pk, _)| pk.clone()).collect::<Vec<_>>();
    let auth_scheme = approvers
        .first()
        .map(|(_, scheme)| *scheme)
        .expect("smart multisig tests require at least one approver");

    create_multisig_smart_account_with_assets(
        threshold,
        &public_keys,
        auth_scheme,
        vec![FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?,
            starting_balance,
        )?],
        [500, 1000, 2000, 1500],
        [1, 2u32.min(num_approvers), 3u32.min(num_approvers), num_approvers],
        proc_policy_map,
    )
}

fn compile_multisig_smart_tx_script(script: impl AsRef<str>) -> anyhow::Result<TransactionScript> {
    Ok(CodeBuilder::default()
        .with_dynamically_linked_library(multisig_smart_library())?
        .compile_tx_script(script.as_ref())?)
}

fn compile_timelocked_send_note_script(
    output_note: &PartialNote,
) -> anyhow::Result<TransactionScript> {
    let mut script = format!(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction

            push.{recipient}
            push.{note_type}
            push.{tag}
            exec.::miden::protocol::output_note::create
        ",
        recipient = output_note.recipient_digest(),
        note_type = Felt::from(output_note.metadata().note_type()),
        tag = Felt::from(output_note.metadata().tag()),
    );

    for asset in output_note.assets().iter() {
        script.push_str(&format!(
            "
                padw push.0 push.0 push.0 dup.7
                push.{asset_value}
                push.{asset_key}
                call.::miden::standards::wallets::basic::move_asset_to_note
                dropw dropw dropw dropw
            ",
            asset_key = asset.to_key_word(),
            asset_value = asset.to_value_word(),
        ));
    }

    script.push_str(&format!(
        "
            push.{attachment}
            push.{attachment_kind}
            push.{attachment_scheme}
            movup.6
            exec.::miden::protocol::output_note::set_attachment
        end
        ",
        attachment = output_note.metadata().to_attachment_word(),
        attachment_kind = output_note.metadata().attachment().attachment_kind().as_u8(),
        attachment_scheme = output_note.metadata().attachment().attachment_scheme().as_u32(),
    ));

    compile_multisig_smart_tx_script(script)
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
    foreign_accounts: Option<Vec<(Account, AccountWitness)>>,
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

    if let Some(foreign_accounts) = foreign_accounts.clone() {
        tx_context_init_builder = tx_context_init_builder.foreign_accounts(foreign_accounts);
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

    if let Some(foreign_accounts) = foreign_accounts {
        tx_context_signed_builder = tx_context_signed_builder.foreign_accounts(foreign_accounts);
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

async fn execute_script_with_signers_at(
    mock_chain: &MockChain,
    reference_block: u32,
    account_id: AccountId,
    tx_script: TransactionScript,
    salt: Word,
    signer_indices: &[usize],
    public_keys: &[PublicKey],
    authenticators: &[BasicAuthenticator],
    tx_script_args: Option<Word>,
    advice_inputs: Option<AdviceInputs>,
    foreign_accounts: Option<Vec<(Account, AccountWitness)>>,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let mut tx_context_init_builder = mock_chain
        .build_tx_context_at(reference_block, account_id, &[], &[])?
        .tx_script(tx_script.clone())
        .auth_args(salt);

    if let Some(tx_script_args) = tx_script_args {
        tx_context_init_builder = tx_context_init_builder.tx_script_args(tx_script_args);
    }

    if let Some(advice_inputs) = advice_inputs.clone() {
        tx_context_init_builder = tx_context_init_builder.extend_advice_inputs(advice_inputs);
    }

    if let Some(foreign_accounts) = foreign_accounts.clone() {
        tx_context_init_builder = tx_context_init_builder.foreign_accounts(foreign_accounts);
    }

    let tx_summary = match tx_context_init_builder.build()?.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let mut tx_context_signed_builder = mock_chain
        .build_tx_context_at(reference_block, account_id, &[], &[])?
        .tx_script(tx_script)
        .auth_args(salt);

    if let Some(tx_script_args) = tx_script_args {
        tx_context_signed_builder = tx_context_signed_builder.tx_script_args(tx_script_args);
    }

    if let Some(advice_inputs) = advice_inputs {
        tx_context_signed_builder = tx_context_signed_builder.extend_advice_inputs(advice_inputs);
    }

    if let Some(foreign_accounts) = foreign_accounts {
        tx_context_signed_builder = tx_context_signed_builder.foreign_accounts(foreign_accounts);
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

async fn execute_script_with_signers_at_and_outputs(
    mock_chain: &MockChain,
    reference_block: u32,
    account_id: AccountId,
    tx_script: TransactionScript,
    expected_output_notes: Vec<RawOutputNote>,
    salt: Word,
    signer_indices: &[usize],
    public_keys: &[PublicKey],
    authenticators: &[BasicAuthenticator],
    foreign_accounts: Option<Vec<(Account, AccountWitness)>>,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let mut tx_context_init_builder = mock_chain
        .build_tx_context_at(reference_block, account_id, &[], &[])?
        .extend_expected_output_notes(expected_output_notes.clone())
        .tx_script(tx_script.clone())
        .auth_args(salt);

    if let Some(foreign_accounts) = foreign_accounts.clone() {
        tx_context_init_builder = tx_context_init_builder.foreign_accounts(foreign_accounts);
    }

    let tx_summary = match tx_context_init_builder.build()?.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let mut tx_context_signed_builder = mock_chain
        .build_tx_context_at(reference_block, account_id, &[], &[])?
        .extend_expected_output_notes(expected_output_notes)
        .tx_script(tx_script)
        .auth_args(salt);

    if let Some(foreign_accounts) = foreign_accounts {
        tx_context_signed_builder = tx_context_signed_builder.foreign_accounts(foreign_accounts);
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
async fn test_multisig_smart_spending_tiers_require_expected_signature_counts(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let cases = [
        ("tier1", [500, 100, 100], 2usize),
        ("tier2", [1000, 100, 100], 3usize),
        ("tier3", [2000, 100, 100], 4usize),
    ];

    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;

    for (case_name, [amount_asset_1, amount_asset_2, amount_asset_3], required_signatures) in cases
    {
        let mut multisig_account = create_multisig_smart_with_fixed_test_configuration_and_oracle(
            3,
            &public_keys,
            auth_scheme,
            vec![],
            &oracle_fixture,
        )?;

        let mut mock_chain_builder = MockChainBuilder::with_accounts([
            multisig_account.clone(),
            oracle_fixture.account.clone(),
        ])
        .unwrap();

        let (output_note_asset_1, output_note_asset_2, output_note_asset_3) =
            create_assets_for_output_notes(amount_asset_1, amount_asset_2, amount_asset_3);

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

        let send_note_transaction_script = AccountInterface::from_account(&multisig_account)
            .build_send_notes_script(&[output_note.clone().into()], None)?;

        let salt = Word::from([Felt::new(required_signatures as u64); 4]);
        let mut mock_chain = mock_chain_builder.build()?;

        let tx_summary = match mock_chain
            .build_tx_context(multisig_account.id(), &[], &[])?
            .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
            .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
            .tx_script(send_note_transaction_script.clone())
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

        let mut signed_context = mock_chain
            .build_tx_context(multisig_account.id(), &[], &[])?
            .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
            .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
            .auth_args(salt)
            .tx_script(send_note_transaction_script);

        for signer_idx in 0..required_signatures {
            let signature = authenticators[signer_idx]
                .get_signature(public_keys[signer_idx].to_commitment(), &tx_summary)
                .await?;
            signed_context = signed_context.add_signature(
                public_keys[signer_idx].to_commitment(),
                msg,
                signature,
            );
        }

        let result = signed_context.build()?.execute().await;
        assert!(
            result.is_ok(),
            "case {case_name:?} with {auth_scheme:?} should succeed with {required_signatures} signatures"
        );

        let result = result.unwrap();
        multisig_account.apply_delta(result.account_delta())?;
        mock_chain.add_pending_executed_transaction(&result)?;
        mock_chain.prove_next_block()?;
    }

    Ok(())
}

#[test]
fn test_multisig_smart_oracle_config_is_stored_and_used() -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, AuthScheme::EcdsaK256Keccak)?;

    let multisig_account = create_multisig_smart_account_with_assets_and_oracle(
        2,
        &public_keys,
        AuthScheme::EcdsaK256Keccak,
        vec![FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?,
            100,
        )?],
        [500, 1000, 2000, 1500],
        [1, 2, 2, 2],
        vec![],
        &oracle_fixture,
    )?;

    assert_eq!(
        multisig_account.storage().get_item(AuthMultisigSmart::oracle_config_slot())?,
        Word::from([
            oracle_fixture.oracle_id[0],
            oracle_fixture.oracle_id[1],
            Felt::new(0),
            Felt::new(0),
        ])
    );
    assert_eq!(
        multisig_account
            .storage()
            .get_item(AuthMultisigSmart::get_price_proc_root_slot())?,
        oracle_fixture.get_price_proc_root
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_oracle_pricing_uses_foreign_value_instead_of_raw_amount(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::FixedPrice(1_200))?;
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 3, auth_scheme)?;

    let assets = vec![FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?,
        100,
    )?];
    let mut multisig_account = create_multisig_smart_account_with_assets_and_oracle(
        1,
        &public_keys,
        auth_scheme,
        assets,
        [500, 1000, 2000, 1500],
        [1, 2, 3, 3],
        vec![],
        &oracle_fixture,
    )?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap();
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 1)?
                .into(),
        ],
        NoteType::Public,
    )?;

    let tx_script = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note.clone().into()], None)?;
    let salt = Word::from([Felt::new(77); 4]);

    let mock_chain = mock_chain_builder.build()?;
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
        .tx_script(tx_script.clone())
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

    let two_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
        .tx_script(tx_script.clone())
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_1.clone())
        .build()?
        .execute()
        .await;
    assert!(
        matches!(two_sig_result, Err(TransactionExecutorError::Unauthorized(_))),
        "oracle fixed-price response should escalate a raw amount of 1 into tier_2"
    );

    let sig_2 = authenticators[2]
        .get_signature(public_keys[2].to_commitment(), &tx_summary)
        .await?;
    let three_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .tx_script(tx_script)
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .add_signature(public_keys[2].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(three_sig_result.account_delta())?;

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_oracle_untracked_assets_do_not_raise_spending_tier(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::Untracked)?;
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 2, auth_scheme)?;

    let assets = vec![FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?,
        5_000,
    )?];
    let mut multisig_account = create_multisig_smart_account_with_assets_and_oracle(
        1,
        &public_keys,
        auth_scheme,
        assets,
        [500, 1000, 2000, 1500],
        [2, 2, 2, 2],
        vec![],
        &oracle_fixture,
    )?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap();
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 2_500)?
                .into(),
        ],
        NoteType::Public,
    )?;

    let tx_script = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note.clone().into()], None)?;
    let salt = Word::from([Felt::new(78); 4]);

    let mock_chain = mock_chain_builder.build()?;
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
        .tx_script(tx_script.clone())
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
    let sig = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg, sig)
        .auth_args(salt)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(result.account_delta())?;

    Ok(())
}

#[tokio::test]
async fn test_multisig_smart_oracle_pricing_missing_foreign_account_fails() -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, AuthScheme::EcdsaK256Keccak)?;

    let multisig_account = create_multisig_smart_account_with_assets_and_oracle(
        2,
        &public_keys,
        AuthScheme::EcdsaK256Keccak,
        vec![FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?,
            1_000,
        )?],
        [500, 1000, 2000, 1500],
        [1, 2, 2, 2],
        vec![],
        &oracle_fixture,
    )?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap();
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 700)?
                .into(),
        ],
        NoteType::Public,
    )?;

    let tx_script = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note.clone().into()], None)?;
    let mock_chain = mock_chain_builder.build()?;

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .tx_script(tx_script)
        .auth_args(Word::from([Felt::new(79); 4]))
        .build()?
        .execute()
        .await;

    assert!(
        matches!(result, Err(TransactionExecutorError::TransactionProgramExecutionFailed(_))),
        "oracle-priced spending should fail when the configured foreign oracle account is not provided"
    );

    Ok(())
}

#[tokio::test]
async fn test_multisig_smart_oracle_pricing_wrong_proc_root_fails() -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, AuthScheme::EcdsaK256Keccak)?;

    let multisig_account = create_multisig_smart_account_with_assets_and_optional_oracle(
        2,
        &public_keys,
        AuthScheme::EcdsaK256Keccak,
        vec![FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?,
            1_000,
        )?],
        [500, 1000, 2000, 1500],
        [1, 2, 2, 2],
        vec![],
        Some((
            oracle_fixture.oracle_id,
            Word::from([Felt::new(999), Felt::new(998), Felt::new(997), Felt::new(996)]),
        )),
    )?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap();
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 700)?
                .into(),
        ],
        NoteType::Public,
    )?;

    let tx_script = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note.clone().into()], None)?;
    let mock_chain = mock_chain_builder.build()?;

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .tx_script(tx_script)
        .auth_args(Word::from([Felt::new(80); 4]))
        .build()?
        .execute()
        .await;

    assert!(
        matches!(result, Err(TransactionExecutorError::TransactionProgramExecutionFailed(_))),
        "oracle-priced spending should fail when the configured proc root does not exist"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_high_spending_escalates_above_default_threshold(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;

    let assets = vec![FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?,
        5_000,
    )?];
    let mut multisig_account = create_multisig_smart_account_with_assets_and_oracle(
        2,
        &public_keys,
        auth_scheme,
        assets,
        [500, 1000, 2000, 1500],
        [1, 2, 3, 5],
        vec![],
        &oracle_fixture,
    )?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap();
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 2_500)?
                .into(),
        ],
        NoteType::Public,
    )?;

    let tx_script = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note.clone().into()], None)?;
    let salt = Word::from([Felt::new(11); 4]);

    let mut mock_chain = mock_chain_builder.build()?;
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
        .tx_script(tx_script.clone())
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

    let four_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
        .tx_script(tx_script.clone())
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[2].to_commitment(), msg, sig_2.clone())
        .add_signature(public_keys[3].to_commitment(), msg, sig_3.clone())
        .build()?
        .execute()
        .await;
    assert!(
        matches!(four_sig_result, Err(TransactionExecutorError::Unauthorized(_))),
        "high spending should require the tier-3 threshold of 5 signatures"
    );

    let sig_4 = authenticators[4]
        .get_signature(public_keys[4].to_commitment(), &tx_summary)
        .await?;
    let five_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .tx_script(tx_script)
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .add_signature(public_keys[2].to_commitment(), msg, sig_2)
        .add_signature(public_keys[3].to_commitment(), msg, sig_3)
        .add_signature(public_keys[4].to_commitment(), msg, sig_4)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(five_sig_result.account_delta())?;
    mock_chain.add_pending_executed_transaction(&five_sig_result)?;
    mock_chain.prove_next_block()?;

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_low_spending_uses_tier_threshold_instead_of_high_default(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;

    let assets = vec![FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?,
        1_000,
    )?];
    let mut multisig_account = create_multisig_smart_account_with_assets_and_oracle(
        4,
        &public_keys,
        auth_scheme,
        assets,
        [500, 1000, 2000, 1500],
        [2, 3, 4, 5],
        vec![],
        &oracle_fixture,
    )?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap();
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 300)?
                .into(),
        ],
        NoteType::Public,
    )?;

    let tx_script = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note.clone().into()], None)?;
    let salt = Word::from([Felt::new(12); 4]);

    let mut mock_chain = mock_chain_builder.build()?;
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
        .tx_script(tx_script.clone())
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
    let one_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
        .tx_script(tx_script.clone())
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0.clone())
        .build()?
        .execute()
        .await;
    assert!(
        matches!(one_sig_result, Err(TransactionExecutorError::Unauthorized(_))),
        "low spending should still reject a single signature when tier-0 threshold is 2"
    );

    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;
    let two_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .tx_script(tx_script)
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(two_sig_result.account_delta())?;
    mock_chain.add_pending_executed_transaction(&two_sig_result)?;
    mock_chain.prove_next_block()?;

    Ok(())
}

/// Mirrors the base multisig override behavior for smart multisig: even if the account default
/// threshold is 3-of-3, a `receive_asset` immediate-only policy with threshold 1 must allow the
/// note-consumption path to execute with a single signature.
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

    let assets =
        vec![FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?, 10)?];
    let mut multisig_account = create_multisig_smart_account_with_assets(
        3,
        &public_keys,
        auth_scheme,
        assets,
        [500, 1000, 2000, 1500],
        [3, 3, 3, 3],
        proc_policy_map,
    )?;

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

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_delayed_only_proc_rejects_signed_direct_path(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 2, auth_scheme)?;
    let multisig_account = create_multisig_account(
        2,
        &public_keys,
        auth_scheme,
        100,
        vec![(
            AuthMultisigSmartPresets::update_timelock_controller(),
            ProcedurePolicy::with_delay_threshold(1)?,
        )],
    )?;
    let account_id = multisig_account.id();
    let mock_chain = MockChainBuilder::with_accounts([multisig_account]).unwrap().build()?;

    let update_timelock_script = compile_multisig_smart_tx_script(
        "
        begin
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_timelock_controller
            drop
            drop
        end
        ",
    )?;

    let blind_inputs = SigningInputs::Blind(Word::from([Felt::new(900); 4]));
    let blind_msg = blind_inputs.to_commitment();
    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &blind_inputs)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &blind_inputs)
        .await?;

    let result = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(update_timelock_script)
        .auth_args(Word::from([Felt::new(901); 4]))
        .add_signature(public_keys[0].to_commitment(), blind_msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), blind_msg, sig_1)
        .build()?
        .execute()
        .await;

    match result {
        Err(TransactionExecutorError::TransactionProgramExecutionFailed(_)) => {},
        Err(err) => panic!("expected transaction program failure, got: {err}"),
        Ok(_) => panic!("execution was unexpectedly successful"),
    }

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_delayed_only_execute_lane_still_returns_tx_summary_on_dry_run(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let multisig_account = create_multisig_account(
        2,
        &public_keys,
        auth_scheme,
        100,
        vec![(
            AuthMultisigSmartPresets::update_timelock_controller(),
            ProcedurePolicy::with_delay_threshold(1)?,
        )],
    )?;
    let account_id = multisig_account.id();
    let mock_chain = MockChainBuilder::with_accounts([multisig_account]).unwrap().build()?;

    let execute_update_timelock_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_timelock_controller
            drop
            drop
        end
        ",
    )?;

    let result = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(execute_update_timelock_script)
        .auth_args(Word::from([Felt::new(902); 4]))
        .build()?
        .execute()
        .await;

    match result {
        Err(TransactionExecutorError::Unauthorized(_)) => Ok(()),
        error => panic!("expected unauthorized dry-run with tx summary, got: {error:?}"),
    }
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_proc_policy_no_notes_constraint_is_enforced(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let multisig_account = create_multisig_account(
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

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_low_spending_send_note_uses_tier_threshold_over_default(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let assets =
        vec![FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?, 10)?];
    let mut multisig_account = create_multisig_smart_account_with_assets_and_oracle(
        2,
        &public_keys,
        auth_scheme,
        assets,
        [500, 1000, 2000, 1500],
        [1, 2, 2, 2],
        vec![],
        &oracle_fixture,
    )?;

    let output_note = P2idNote::create(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![FungibleAsset::mock(5)],
        NoteType::Public,
        Default::default(),
        &mut RandomCoin::new(Word::from([Felt::new(42); 4])),
    )?;
    let send_note_transaction_script = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note.clone().into()], None)?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap()
            .build()?;
    let salt = Word::from([Felt::new(2); 4]);

    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
        .tx_script(send_note_transaction_script.clone())
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
    let sig = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg, sig)
        .auth_args(salt)
        .tx_script(send_note_transaction_script)
        .build()?
        .execute()
        .await;

    assert!(
        result.is_ok(),
        "low spending should use tier_0=1 instead of the default threshold of 2"
    );

    multisig_account.apply_delta(result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&result.unwrap())?;
    mock_chain.prove_next_block()?;

    assert_eq!(multisig_account.vault().get_balance(FungibleAsset::mock_issuer())?, 5);

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_spending_window_boundary_resets_spending_tracker(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(5, 5, auth_scheme)?;
    let mut multisig_account = create_multisig_smart_with_fixed_test_configuration_and_oracle(
        3,
        &public_keys,
        auth_scheme,
        vec![],
        &oracle_fixture,
    )?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap()
            .build()?;

    let output_note_1 = P2idNote::create(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 700)?
                .into(),
        ],
        NoteType::Public,
        Default::default(),
        &mut RandomCoin::new(Word::from([Felt::new(101); 4])),
    )?;
    let script_1 = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note_1.clone().into()], None)?;
    let salt_1 = Word::from([Felt::new(201); 4]);

    let tx_summary_1 = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note_1.clone())])
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
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note_1)])
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
        &mut RandomCoin::new(Word::from([Felt::new(102); 4])),
    )?;
    let script_2 = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note_2.clone().into()], None)?;
    let salt_2 = Word::from([Felt::new(202); 4]);

    let tx_summary_2 = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note_2.clone())])
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
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note_2)])
        .tx_script(script_2)
        .auth_args(salt_2)
        .add_signature(public_keys[0].to_commitment(), msg_2, sig_2_0)
        .add_signature(public_keys[1].to_commitment(), msg_2, sig_2_1)
        .build()?
        .execute()
        .await;
    assert!(
        matches!(tx_2_with_two_sigs, Err(TransactionExecutorError::Unauthorized(_))),
        "second transfer in the same spending window should require a higher tier"
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
        &mut RandomCoin::new(Word::from([Felt::new(103); 4])),
    )?;
    let script_3 = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note_3.clone().into()], None)?;
    let salt_3 = Word::from([Felt::new(203); 4]);

    let tx_summary_3 = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note_3.clone())])
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
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note_3)])
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
        "amount_spent_in_window should restart from the transaction amount after a window reset"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_update_spending_window_policy_resets_tracker(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 2, auth_scheme)?;
    let mut multisig_account = create_multisig_smart_with_fixed_test_configuration_and_oracle(
        2,
        &public_keys,
        auth_scheme,
        vec![],
        &oracle_fixture,
    )?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap()
            .build()?;

    // Seed spending tracker with a successful transfer.
    let output_note = P2idNote::create(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![
            FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, 700)?
                .into(),
        ],
        NoteType::Public,
        Default::default(),
        &mut RandomCoin::new(Word::from([Felt::new(111); 4])),
    )?;
    let send_script = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note.clone().into()], None)?;

    let send_salt = Word::from([Felt::new(211); 4]);
    let send_tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
        .tx_script(send_script.clone())
        .auth_args(send_salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };
    let send_msg = send_tx_summary.as_ref().to_commitment();
    let send_tx_summary = SigningInputs::TransactionSummary(send_tx_summary);
    let send_sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &send_tx_summary)
        .await?;
    let send_sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &send_tx_summary)
        .await?;

    let send_tx = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .tx_script(send_script)
        .auth_args(send_salt)
        .add_signature(public_keys[0].to_commitment(), send_msg, send_sig_0)
        .add_signature(public_keys[1].to_commitment(), send_msg, send_sig_1)
        .build()?
        .execute()
        .await?;
    multisig_account.apply_delta(send_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&send_tx)?;
    mock_chain.prove_next_block()?;

    let spending_tracker_before = multisig_account
        .storage()
        .get_item(AuthMultisigSmart::spending_tracker_slot())?;
    assert_eq!(
        spending_tracker_before[0],
        Felt::new(700),
        "seed transfer should update tracker before policy update",
    );

    let update_window_script = compile_multisig_smart_tx_script(
        "
        begin
            push.60
            call.::miden::standards::components::auth::multisig_smart::update_spending_window_policy
            dropw dropw dropw dropw dropw
        end
        ",
    )?;

    let update_tx = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        update_window_script,
        Word::from([Felt::new(212); 4]),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
        None,
    )
    .await?
    .expect("window update should succeed");
    multisig_account.apply_delta(update_tx.account_delta())?;

    let spending_window =
        multisig_account.storage().get_item(AuthMultisigSmart::spending_window_slot())?;
    assert_eq!(spending_window, Word::from([60u32, 0, 0, 0]));

    let spending_tracker_after = multisig_account
        .storage()
        .get_item(AuthMultisigSmart::spending_tracker_slot())?;
    assert_eq!(
        spending_tracker_after,
        Word::empty(),
        "spending tracker must be reset when spending window policy changes",
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
async fn test_multisig_smart_proposal_stores_unlock_timestamp_and_enforces_min_delay(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let oracle_fixture = build_test_oracle_fixture(TestOracleMode::OneToOneTracked)?;
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 3, auth_scheme)?;

    let assets = vec![FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?,
        5_000,
    )?];
    let mut multisig_account = create_multisig_smart_account_with_assets_and_oracle(
        2,
        &public_keys,
        auth_scheme,
        assets,
        [500, 1000, 2000, 1500],
        [1, 2, 2, 3],
        vec![],
        &oracle_fixture,
    )?;
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone(), oracle_fixture.account.clone()])
            .unwrap()
            .build()?;

    let output_note = P2idNote::create(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![FungibleAsset::mock(1_600)],
        NoteType::Public,
        Default::default(),
        &mut RandomCoin::new(Word::from([Felt::new(420); 4])),
    )?;
    let partial_output_note: PartialNote = output_note.clone().into();
    let execute_script = compile_timelocked_send_note_script(&partial_output_note)?;
    let execute_salt = Word::from([Felt::new(421); 4]);

    let proposal_reference_block = mock_chain.latest_block_header().block_num().as_u32();
    let proposal_reference_timestamp =
        mock_chain.block_header(proposal_reference_block as usize).timestamp();

    let execute_summary = match mock_chain
        .build_tx_context_at(proposal_reference_block, multisig_account.id(), &[], &[])?
        .foreign_accounts(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
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
    let propose_tx = execute_script_with_signers_at(
        &mock_chain,
        proposal_reference_block,
        multisig_account.id(),
        propose_script,
        Word::from([Felt::new(422); 4]),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
        None,
    )
    .await?
    .expect("proposal transaction should succeed");
    multisig_account.apply_delta(propose_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    let proposal_entry = multisig_account
        .storage()
        .get_map_item(AuthMultisigSmart::tx_proposals_slot(), execute_tx_hash)?;
    assert_eq!(
        proposal_entry,
        Word::from([proposal_reference_timestamp + 30, proposal_reference_timestamp, 2u32, 1u32,]),
        "proposal entry should store [unlock_timestamp, proposal_timestamp, min_cancel_sigs, is_set]"
    );

    let early_attempt_block = proposal_reference_block + 1;
    let early_execute_err = execute_script_with_signers_at_and_outputs(
        &mock_chain,
        early_attempt_block,
        multisig_account.id(),
        execute_script.clone(),
        vec![RawOutputNote::Full(output_note.clone())],
        execute_salt,
        &[0, 1],
        &public_keys,
        &authenticators,
        Some(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?),
    )
    .await?;
    assert_transaction_executor_error!(early_execute_err, ERR_TX_STILL_TIMELOCKED);

    let unlock_offset_blocks = 30 / MockChain::TIMESTAMP_STEP_SECS;
    let ready_block = proposal_reference_block + unlock_offset_blocks;
    while mock_chain.latest_block_header().block_num().as_u32() < ready_block {
        mock_chain.prove_next_block()?;
    }

    let execute_tx = execute_script_with_signers_at_and_outputs(
        &mock_chain,
        ready_block,
        multisig_account.id(),
        execute_script,
        vec![RawOutputNote::Full(output_note.clone())],
        execute_salt,
        &[0, 1],
        &public_keys,
        &authenticators,
        Some(test_oracle_foreign_account_inputs(&mock_chain, &oracle_fixture)?),
    )
    .await?
    .expect("execute transaction should succeed once unlock timestamp is reached");
    multisig_account.apply_delta(execute_tx.account_delta())?;

    let proposal_entry_after = multisig_account
        .storage()
        .get_map_item(AuthMultisigSmart::tx_proposals_slot(), execute_tx_hash)?;
    assert_eq!(
        proposal_entry_after,
        Word::empty(),
        "proposal should be removed after successful execution"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_stale_proposal_reference_expires_before_inclusion(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 3, auth_scheme)?;
    let multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    for _ in 0..5 {
        mock_chain.prove_next_block()?;
    }

    let stale_reference_block = 1u32;
    let proposal_hash = Word::from([Felt::new(71), Felt::new(72), Felt::new(73), Felt::new(74)]);
    let propose_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{proposal_hash}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;

    let proposal_tx = execute_script_with_signers_at(
        &mock_chain,
        stale_reference_block,
        multisig_account.id(),
        propose_script,
        Word::from([Felt::new(423); 4]),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
        None,
    )
    .await?
    .expect("proposal transaction should still execute against its stale reference block");

    mock_chain.add_pending_executed_transaction(&proposal_tx)?;
    let prove_err = mock_chain.prove_next_block().unwrap_err();
    assert!(
        prove_err.to_string().contains("expires at block number"),
        "proposal with a reference block older than propose_expiration_delta should expire before inclusion: {prove_err}"
    );

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
        None,
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
        None,
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
async fn test_multisig_smart_update_signers_uses_current_num_approvers_for_policy_validation(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let multisig_account = create_multisig_account(
        2,
        &public_keys,
        auth_scheme,
        100,
        vec![(
            BasicWallet::receive_asset_digest(),
            ProcedurePolicy::with_immediate_threshold(2)?,
        )],
    )?;
    let account_id = multisig_account.id();
    let mock_chain = MockChainBuilder::with_accounts([multisig_account]).unwrap().build()?;

    let update_signers_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::update_signers_and_threshold
        end
        ",
    )?;

    let shrink_data = build_update_signers_config_vector(1, 1, &public_keys[0..1], auth_scheme);
    let shrink_hash = Hasher::hash_elements(&shrink_data);
    let mut advice_map = AdviceMap::default();
    advice_map.insert(shrink_hash, shrink_data);
    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };

    let blind_inputs = SigningInputs::Blind(Word::from([Felt::new(906); 4]));
    let blind_msg = blind_inputs.to_commitment();
    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &blind_inputs)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &blind_inputs)
        .await?;

    let result = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(update_signers_script)
        .tx_script_args(shrink_hash)
        .auth_args(Word::from([Felt::new(905); 4]))
        .extend_advice_inputs(advice_inputs)
        .add_signature(public_keys[0].to_commitment(), blind_msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), blind_msg, sig_1)
        .build()?
        .execute()
        .await;

    match result {
        Err(TransactionExecutorError::TransactionProgramExecutionFailed(_)) => {},
        Err(err) => panic!("expected transaction program failure, got: {err}"),
        Ok(_) => panic!("execution was unexpectedly successful"),
    }

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
    let proc_policy_map = vec![(
        BasicWallet::receive_asset_digest(),
        ProcedurePolicy::with_immediate_threshold(4)?,
    )];

    let assets =
        vec![FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?, 10)?];

    let multisig_account = create_multisig_smart_account_with_assets(
        2,
        &public_keys,
        auth_scheme,
        assets,
        [500, 1000, 2000, 1500],
        [1, 2, 3, 4],
        proc_policy_map,
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
async fn test_multisig_smart_equal_tier_config_is_accepted_by_update_threshold_config(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let mut multisig_account = create_multisig_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let update_script = compile_multisig_smart_tx_script(
        "
        begin
            push.2
            push.2
            push.2
            push.1
            call.::miden::standards::components::auth::multisig_smart::update_threshold_config
            dropw dropw dropw dropw dropw
        end
        ",
    )?;

    let update_tx = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        update_script,
        Word::from([Felt::new(1000); 4]),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
        None,
    )
    .await?
    .expect("equal tier config update should succeed");
    multisig_account.apply_delta(update_tx.account_delta())?;

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
            push.5
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
