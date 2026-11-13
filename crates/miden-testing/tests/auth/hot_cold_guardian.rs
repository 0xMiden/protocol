use std::collections::BTreeMap;

use miden_processor::advice::AdviceInputs;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey, PublicKeyCommitment};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountProcedureRoot,
    AccountType,
    StorageMapKey,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionScript};
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::auth::hot_cold_guardian::MIN_DELAY_FLOOR_BLOCKS;
use miden_standards::account::auth::{
    Approver,
    AuthHotColdGuardian,
    AuthHotColdGuardianConfig,
    FeeConversionInfo,
    GuardianConfig,
    HotColdDelayConfig,
    HotColdPolicy,
    MultisigAuthArgs,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_COLD_KEY_IS_GUARDIAN_KEY,
    ERR_COLD_REQUIRED_NEEDS_SINGLE_CATEGORY,
    ERR_GUARDIAN_KEY_IS_USER_KEY,
    ERR_HOT_KEY_IS_GUARDIAN_KEY,
    ERR_MIN_DELAY_BELOW_FLOOR,
    ERR_NUM_HOT_KEYS_OUT_OF_BOUNDS,
    ERR_PROC_THRESHOLD_EXCEEDS_NUM_CATEGORIES,
};
use miden_testing::{
    Auth,
    MockChain,
    MockChainBuilder,
    MockTransactionBuilder,
    assert_transaction_executor_error,
};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use super::fee_payment::{VERIFICATION_BASE_FEE, assert_single_fee_note};
use super::multisig::MultisigAuthArgsExt;

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

/// A key of one of the categories together with the authenticator that signs with it.
struct Signer {
    public_key: PublicKey,
    authenticator: BasicAuthenticator,
}

impl Signer {
    fn new(auth_scheme: AuthScheme, rng: &mut ChaCha20Rng) -> Self {
        let secret_key = AuthSecretKey::with_scheme_and_rng(auth_scheme, rng)
            .expect("the auth scheme should be supported");
        let public_key = secret_key.public_key();
        let authenticator = BasicAuthenticator::new(core::slice::from_ref(&secret_key));
        Self { public_key, authenticator }
    }

    fn approver(&self) -> Approver {
        Approver::from(&self.public_key)
    }

    fn commitment(&self) -> PublicKeyCommitment {
        self.public_key.to_commitment()
    }

    fn commitment_word(&self) -> Word {
        self.commitment().into()
    }
}

/// The keys of a hot/cold/guardian account together with the account itself.
struct HotColdAccount {
    hot: Vec<Signer>,
    cold: Signer,
    guardian: Signer,
    account: Account,
}

impl HotColdAccount {
    /// Returns the configuration of the account's keys with the default delay configuration.
    fn config(
        hot: &[Signer],
        cold: &Signer,
        guardian: &Signer,
        proc_policies: BTreeMap<AccountProcedureRoot, HotColdPolicy>,
    ) -> anyhow::Result<AuthHotColdGuardianConfig> {
        Ok(AuthHotColdGuardianConfig::new(
            hot.iter().map(Signer::approver).collect(),
            cold.approver(),
            GuardianConfig::new(guardian.approver()),
            HotColdDelayConfig::default(),
        )?
        .with_proc_policies(proc_policies))
    }
}

/// Creates a public hot/cold/guardian account with `num_hot` hot keys, a `BasicWallet` and the
/// given amount of the mock fungible asset.
fn create_hot_cold_guardian_account(
    auth_scheme: AuthScheme,
    num_hot: usize,
    asset_amount: u64,
    proc_policies: BTreeMap<AccountProcedureRoot, HotColdPolicy>,
) -> anyhow::Result<HotColdAccount> {
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let hot: Vec<_> = (0..num_hot).map(|_| Signer::new(auth_scheme, &mut rng)).collect();
    let cold = Signer::new(auth_scheme, &mut rng);
    let guardian = Signer::new(auth_scheme, &mut rng);

    let config = HotColdAccount::config(&hot, &cold, &guardian, proc_policies)?;
    let account = AccountBuilder::new([0; 32])
        .account_type(AccountType::Public)
        .with_component(AuthHotColdGuardian::new(config))
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(asset_amount)])
        .build_existing()?;

    Ok(HotColdAccount { hot, cold, guardian, account })
}

/// Compiles a transaction script that links against the component package so it can `call.` the
/// component's exported procedures.
fn compile_tx_script(script: impl AsRef<str>) -> anyhow::Result<TransactionScript> {
    Ok(CodeBuilder::default()
        .with_dynamically_linked_package(AuthHotColdGuardian::code())?
        .compile_tx_script(script.as_ref())?)
}

/// Builds a salt word from a seed; every transaction of a test should use a distinct seed.
fn salt(seed: u32) -> Word {
    Word::from([Felt::from(seed); 4])
}

/// Dry-runs the transaction to obtain its summary, signs it with `signers` and executes it.
///
/// The outer error reports a test setup failure; the inner result is the execution outcome, so a
/// test can assert on `TransactionExecutorError::Unauthorized`.
async fn sign_and_execute(
    tx_builder: MockTransactionBuilder<'_>,
    signers: &[&Signer],
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let tx_summary = tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut signed_builder = tx_builder;
    for signer in signers {
        let signature =
            signer.authenticator.get_signature(signer.commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(signer.commitment(), msg, signature);
    }

    Ok(signed_builder.build()?.execute().await)
}

/// Layout expected by `update_hot_keys` when looking up the new hot keys in the advice map:
/// `[num_hot_keys, 0, 0, 0, (PUB_KEY, SCHEME_WORD) for each key]`, keys in reverse so the
/// procedure writes them in ascending index order.
fn build_update_hot_keys_config_vector(hot_keys: &[Approver]) -> Vec<Felt> {
    let mut config = vec![Felt::from(hot_keys.len() as u32), Felt::ZERO, Felt::ZERO, Felt::ZERO];
    for approver in hot_keys.iter().rev() {
        let key_word: Word = approver.pub_key().into();
        config.extend_from_slice(key_word.as_elements());
        config.extend_from_slice(&[
            Felt::from(approver.auth_scheme().as_u8()),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ]);
    }
    config
}

/// Builds the `update_hot_keys` transaction for the given new hot key set.
fn update_hot_keys_tx<'a>(
    mock_chain: &'a MockChain,
    account: &Account,
    new_hot_keys: &[Approver],
    salt_seed: u32,
) -> anyhow::Result<MockTransactionBuilder<'a>> {
    let config_data = build_update_hot_keys_config_vector(new_hot_keys);
    let config_hash = Hasher::hash_elements(&config_data);
    let script = compile_tx_script(
        "
        @transaction_script
        pub proc main
            call.::miden::standards::components::auth::hot_cold_guardian::update_hot_keys
        end
        ",
    )?;

    Ok(mock_chain
        .build_transaction(account.id())
        .tx_script(script)
        .tx_script_args(config_hash)
        .extend_advice_inputs(AdviceInputs::default().with_map([(config_hash, config_data)]))
        .multisig_auth_args(MultisigAuthArgs::new(
            mock_chain.latest_block_header().block_num(),
            salt(salt_seed),
        )))
}

/// Builds a transaction that calls `rotate_cold_key` or `update_guardian_public_key` with the
/// given key, since both take `[scheme_id, PUB_KEY]`.
fn rotate_key_tx<'a>(
    mock_chain: &'a MockChain,
    account: &Account,
    procedure: &str,
    new_key: &Signer,
    salt_seed: u32,
) -> anyhow::Result<MockTransactionBuilder<'a>> {
    let script = compile_tx_script(format!(
        "
        @transaction_script
        pub proc main
            push.{key_word}
            push.{scheme_id}
            call.::miden::standards::components::auth::hot_cold_guardian::{procedure}
            drop dropw
        end
        ",
        key_word = new_key.commitment_word(),
        scheme_id = new_key.public_key.auth_scheme() as u32,
    ))?;

    Ok(mock_chain.build_transaction(account.id()).tx_script(script).multisig_auth_args(
        MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt(salt_seed)),
    ))
}

/// Builds a `set_procedure_policy` transaction writing
/// `[immediate_threshold, 0, cold_required, 0]` for `proc_root`.
fn set_procedure_policy_tx<'a>(
    mock_chain: &'a MockChain,
    account: &Account,
    proc_root: AccountProcedureRoot,
    immediate_threshold: u32,
    cold_required: u32,
    salt_seed: u32,
) -> anyhow::Result<MockTransactionBuilder<'a>> {
    // `call.` does not consume operand-stack inputs, so the script drops what it pushed.
    let script = compile_tx_script(format!(
        "
        @transaction_script
        pub proc main
            push.{root}
            push.{cold_required}
            push.{immediate_threshold}
            call.::miden::standards::components::auth::hot_cold_guardian::set_procedure_policy
            drop drop dropw
        end
        ",
        root = proc_root.as_word(),
    ))?;

    Ok(mock_chain.build_transaction(account.id()).tx_script(script).multisig_auth_args(
        MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt(salt_seed)),
    ))
}

/// Builds an `update_delay_config` transaction.
fn update_delay_config_tx<'a>(
    mock_chain: &'a MockChain,
    account: &Account,
    min_delay: u32,
    propose_expiration_delta: u16,
    cancel_threshold: u32,
    salt_seed: u32,
) -> anyhow::Result<MockTransactionBuilder<'a>> {
    let script = compile_tx_script(format!(
        "
        @transaction_script
        pub proc main
            push.{cancel_threshold}
            push.{propose_expiration_delta}
            push.{min_delay}
            call.::miden::standards::components::auth::hot_cold_guardian::update_delay_config
            drop drop drop
        end
        ",
    ))?;

    Ok(mock_chain.build_transaction(account.id()).tx_script(script).multisig_auth_args(
        MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt(salt_seed)),
    ))
}

/// Reads a policy word from the account's procedure policy map.
fn policy_word(account: &Account, proc_root: AccountProcedureRoot) -> anyhow::Result<Word> {
    Ok(account.storage().get_map_item(
        AuthHotColdGuardian::procedure_policies_slot(),
        StorageMapKey::from_raw(proc_root.as_word()),
    )?)
}

// ================================================================================================
// TESTS
// ================================================================================================

/// An unpolicied transfer runs with any one user category plus the guardian, and with nothing
/// less: a single category alone, or hot and cold without the guardian, is rejected.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Eidos)]
#[tokio::test]
async fn test_hot_cold_guardian_transfer_paths(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let HotColdAccount { hot, cold, guardian, account } =
        create_hot_cold_guardian_account(auth_scheme, 2, 10, BTreeMap::new())?;

    let output_note_asset = FungibleAsset::mock(3);
    let mut builder = MockChainBuilder::with_accounts([account.clone()])?;
    let output_note = builder.add_p2id_note(
        account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into()?,
        &[output_note_asset],
        NoteType::Public,
    )?;
    let input_note = builder.add_spawn_note([&output_note])?;
    let mock_chain = builder.build()?;

    let transfer_tx = || {
        mock_chain
            .build_transaction(account.id())
            .authenticated_input_note(input_note.id())
            .expected_output_note(RawOutputNote::Full(output_note.clone()))
            .multisig_auth_args(MultisigAuthArgs::new(
                mock_chain.latest_block_header().block_num(),
                salt(1),
            ))
    };

    // A single category without the guardian is rejected.
    for signers in [vec![&hot[0]], vec![&cold], vec![&hot[0], &hot[1]]] {
        let result = sign_and_execute(transfer_tx(), &signers).await?;
        assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));
    }

    // Both user categories without the guardian are rejected: nothing runs without it.
    let result = sign_and_execute(transfer_tx(), &[&hot[0], &cold]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));

    // The guardian alone is rejected: it holds no authority of its own.
    let result = sign_and_execute(transfer_tx(), &[&guardian]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));

    // Any hot key plus the guardian is the daily path.
    for (i, hot_key) in hot.iter().enumerate() {
        sign_and_execute(transfer_tx(), &[hot_key, &guardian])
            .await?
            .map_err(|err| anyhow::anyhow!("hot key {i} plus the guardian failed: {err}"))?;
    }

    // The cold key plus the guardian can do everything the daily path can.
    let executed = sign_and_execute(transfer_tx(), &[&cold, &guardian]).await??;
    let mut account = account;
    account.apply_patch(executed.account_patch())?;
    assert_eq!(
        account.vault().get_balance(output_note_asset.id())?.as_u64(),
        10 - output_note_asset.unwrap_fungible().amount().as_u64()
    );

    Ok(())
}

/// Several hot keys count as one category: two hot keys plus the guardian cannot rotate the cold
/// key, which requires both categories, while one hot key plus the cold key plus the guardian can.
#[tokio::test]
async fn test_hot_cold_guardian_hot_keys_count_once() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let HotColdAccount { hot, cold, guardian, account } =
        create_hot_cold_guardian_account(auth_scheme, 3, 10, BTreeMap::new())?;
    let mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    let new_cold = Signer::new(auth_scheme, &mut ChaCha20Rng::from_seed(rand::random()));

    // All three hot keys plus the guardian are still one category.
    let tx = rotate_key_tx(&mock_chain, &account, "rotate_cold_key", &new_cold, 1)?;
    let result = sign_and_execute(tx, &[&hot[0], &hot[1], &hot[2], &guardian]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));

    // The new cold key must stay distinct from the guardian key.
    let tx = rotate_key_tx(&mock_chain, &account, "rotate_cold_key", &guardian, 2)?;
    let result = tx.build()?.execute().await;
    assert_transaction_executor_error!(result, ERR_COLD_KEY_IS_GUARDIAN_KEY);

    // One hot key, the cold key and the guardian rotate the cold key.
    let tx = rotate_key_tx(&mock_chain, &account, "rotate_cold_key", &new_cold, 1)?;
    let executed = sign_and_execute(tx, &[&hot[0], &cold, &guardian]).await??;

    let mut account = account;
    account.apply_patch(executed.account_patch())?;
    let category_key = StorageMapKey::empty();
    assert_eq!(
        account
            .storage()
            .get_map_item(AuthHotColdGuardian::cold_public_key_slot(), category_key)?,
        new_cold.commitment_word()
    );
    assert_eq!(
        account
            .storage()
            .get_map_item(AuthHotColdGuardian::cold_scheme_id_slot(), category_key)?,
        Word::from([auth_scheme as u32, 0, 0, 0])
    );

    Ok(())
}

/// Device management is reserved for the cold key: replacing the hot keys with a hot key plus
/// the guardian is rejected, with the cold key plus the guardian it succeeds, and stale entries
/// are cleared when the set shrinks.
#[tokio::test]
async fn test_hot_cold_guardian_update_hot_keys_requires_cold() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let HotColdAccount { hot, cold, guardian, mut account } =
        create_hot_cold_guardian_account(auth_scheme, 1, 10, BTreeMap::new())?;
    let mut mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let new_hot: Vec<_> = (0..3).map(|_| Signer::new(auth_scheme, &mut rng)).collect();
    let new_hot_approvers: Vec<_> = new_hot.iter().map(Signer::approver).collect();

    // A hot key plus the guardian cannot replace the hot keys.
    let tx = update_hot_keys_tx(&mock_chain, &account, &new_hot_approvers, 1)?;
    let result = sign_and_execute(tx, &[&hot[0], &guardian]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));

    // The new hot keys must be distinct from the guardian key, and there must be at least one.
    for (new_keys, expected_error) in [
        (vec![guardian.approver(), new_hot_approvers[0]], ERR_HOT_KEY_IS_GUARDIAN_KEY),
        (vec![], ERR_NUM_HOT_KEYS_OUT_OF_BOUNDS),
    ] {
        let tx = update_hot_keys_tx(&mock_chain, &account, &new_keys, 2)?;
        let result = tx.build()?.execute().await;
        assert_transaction_executor_error!(result, expected_error);
    }

    // The cold key plus the guardian replace the hot keys.
    let tx = update_hot_keys_tx(&mock_chain, &account, &new_hot_approvers, 1)?;
    let executed = sign_and_execute(tx, &[&cold, &guardian]).await??;
    account.apply_patch(executed.account_patch())?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        account.storage().get_item(AuthHotColdGuardian::config_slot())?,
        Word::from([3u32, 0, 0, 0])
    );
    for (i, signer) in new_hot.iter().enumerate() {
        assert_eq!(
            account.storage().get_map_item(
                AuthHotColdGuardian::hot_public_keys_slot(),
                StorageMapKey::from_index(i as u32)
            )?,
            signer.commitment_word()
        );
    }

    // The old hot key no longer counts.
    let fresh_cold = Signer::new(auth_scheme, &mut rng);
    let tx = rotate_key_tx(&mock_chain, &account, "rotate_cold_key", &fresh_cold, 3)?;
    let result = sign_and_execute(tx, &[&hot[0], &cold, &guardian]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));

    // Shrinking the set clears the stale entries.
    let tx = update_hot_keys_tx(&mock_chain, &account, &new_hot_approvers[..1], 4)?;
    let executed = sign_and_execute(tx, &[&new_hot[2], &cold, &guardian]).await??;
    account.apply_patch(executed.account_patch())?;

    assert_eq!(
        account.storage().get_item(AuthHotColdGuardian::config_slot())?,
        Word::from([1u32, 0, 0, 0])
    );
    for stale_index in 1..3u32 {
        let key = StorageMapKey::from_index(stale_index);
        assert_eq!(
            account
                .storage()
                .get_map_item(AuthHotColdGuardian::hot_public_keys_slot(), key)?,
            Word::empty()
        );
        assert_eq!(
            account
                .storage()
                .get_map_item(AuthHotColdGuardian::hot_scheme_ids_slot(), key)?,
            Word::empty()
        );
    }

    Ok(())
}

/// Rotating the guardian takes both user categories and the guardian's own signature, and the
/// new guardian key must not be a user key.
#[tokio::test]
async fn test_hot_cold_guardian_update_guardian_public_key() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let HotColdAccount { hot, cold, guardian, account } =
        create_hot_cold_guardian_account(auth_scheme, 2, 10, BTreeMap::new())?;
    let mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    let new_guardian = Signer::new(auth_scheme, &mut ChaCha20Rng::from_seed(rand::random()));

    // Without the guardian's consent the rotation does not run.
    let tx = rotate_key_tx(&mock_chain, &account, "update_guardian_public_key", &new_guardian, 1)?;
    let result = sign_and_execute(tx, &[&hot[0], &cold]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));

    // One user category is not enough either.
    let tx = rotate_key_tx(&mock_chain, &account, "update_guardian_public_key", &new_guardian, 1)?;
    let result = sign_and_execute(tx, &[&hot[0], &guardian]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));

    // The guardian key must stay distinct from the user keys, checked by the rotation itself.
    for user_key in [&cold, &hot[1]] {
        let tx = rotate_key_tx(&mock_chain, &account, "update_guardian_public_key", user_key, 2)?;
        let result = tx.build()?.execute().await;
        assert_transaction_executor_error!(result, ERR_GUARDIAN_KEY_IS_USER_KEY);
    }

    // Both categories plus the guardian rotate the guardian.
    let tx = rotate_key_tx(&mock_chain, &account, "update_guardian_public_key", &new_guardian, 1)?;
    let executed = sign_and_execute(tx, &[&hot[0], &cold, &guardian]).await??;

    let mut account = account;
    account.apply_patch(executed.account_patch())?;
    assert_eq!(
        account.storage().get_map_item(
            AuthHotColdGuardian::guardian_public_key_slot(),
            StorageMapKey::empty()
        )?,
        new_guardian.commitment_word()
    );

    Ok(())
}

/// Policies and the delay configuration take both categories plus the guardian; a policy set on
/// a wallet procedure is enforced on the next transaction.
#[tokio::test]
async fn test_hot_cold_guardian_set_procedure_policy_and_delay_config() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let HotColdAccount { hot, cold, guardian, mut account } =
        create_hot_cold_guardian_account(auth_scheme, 1, 10, BTreeMap::new())?;

    let mut builder = MockChainBuilder::with_accounts([account.clone()])?;
    let incoming_note = builder.add_p2id_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into()?,
        account.id(),
        &[FungibleAsset::mock(5)],
        NoteType::Public,
    )?;
    let mut mock_chain = builder.build()?;
    let receive_asset_root = BasicWallet::receive_asset_root();

    // Invalid policies are rejected before authentication.
    let tx = set_procedure_policy_tx(&mock_chain, &account, receive_asset_root, 3, 0, 1)?;
    let result = tx.build()?.execute().await;
    assert_transaction_executor_error!(result, ERR_PROC_THRESHOLD_EXCEEDS_NUM_CATEGORIES);

    let tx = set_procedure_policy_tx(&mock_chain, &account, receive_asset_root, 2, 1, 2)?;
    let result = tx.build()?.execute().await;
    assert_transaction_executor_error!(result, ERR_COLD_REQUIRED_NEEDS_SINGLE_CATEGORY);

    // A hot key plus the guardian cannot change policies.
    let tx = set_procedure_policy_tx(&mock_chain, &account, receive_asset_root, 2, 0, 3)?;
    let result = sign_and_execute(tx, &[&hot[0], &guardian]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));

    // Both categories plus the guardian require both categories for `receive_asset`.
    let tx = set_procedure_policy_tx(&mock_chain, &account, receive_asset_root, 2, 0, 3)?;
    let executed = sign_and_execute(tx, &[&hot[0], &cold, &guardian]).await??;
    account.apply_patch(executed.account_patch())?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    assert_eq!(policy_word(&account, receive_asset_root)?, Word::from([2u32, 0, 0, 0]));

    // Consuming a note now needs both categories.
    let consume_tx = || {
        mock_chain
            .build_transaction(account.id())
            .authenticated_input_note(incoming_note.id())
            .multisig_auth_args(MultisigAuthArgs::new(
                mock_chain.latest_block_header().block_num(),
                salt(4),
            ))
    };
    let result = sign_and_execute(consume_tx(), &[&hot[0], &guardian]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));
    sign_and_execute(consume_tx(), &[&hot[0], &cold, &guardian]).await??;

    // The delay configuration is bounded and takes both categories plus the guardian.
    let tx = update_delay_config_tx(&mock_chain, &account, MIN_DELAY_FLOOR_BLOCKS - 1, 20, 1, 5)?;
    let result = tx.build()?.execute().await;
    assert_transaction_executor_error!(result, ERR_MIN_DELAY_BELOW_FLOOR);

    let tx = update_delay_config_tx(&mock_chain, &account, MIN_DELAY_FLOOR_BLOCKS, 40, 2, 6)?;
    let result = sign_and_execute(tx, &[&hot[0], &guardian]).await?;
    assert!(matches!(result, Err(TransactionExecutorError::Unauthorized(_))));

    let tx = update_delay_config_tx(&mock_chain, &account, MIN_DELAY_FLOOR_BLOCKS, 40, 2, 6)?;
    let executed = sign_and_execute(tx, &[&hot[0], &cold, &guardian]).await??;
    account.apply_patch(executed.account_patch())?;
    assert_eq!(
        account.storage().get_item(AuthHotColdGuardian::delay_config_slot())?,
        Word::from([MIN_DELAY_FLOOR_BLOCKS, 40, 2, 0])
    );

    Ok(())
}

/// The presets of the component's own procedures are built into its code: they are not stored,
/// yet `get_procedure_policy` reports them, while a procedure without a preset reports no policy.
#[tokio::test]
async fn test_hot_cold_guardian_reports_preset_policies() -> anyhow::Result<()> {
    let HotColdAccount { hot, guardian, account, .. } =
        create_hot_cold_guardian_account(AuthScheme::EcdsaK256Keccak, 1, 10, BTreeMap::new())?;
    let mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;

    let preset_policies =
        AuthHotColdGuardian::preset_policies().into_iter().map(|(root, policy)| {
            (root, policy.immediate_threshold(), u32::from(policy.cold_required()))
        });
    let expected_policies = preset_policies.chain([(BasicWallet::receive_asset_root(), 0, 0)]);

    for (salt_seed, (proc_root, immediate_threshold, cold_required)) in (1..).zip(expected_policies)
    {
        assert_eq!(policy_word(&account, proc_root)?, Word::empty());

        let script = compile_tx_script(format!(
            r#"
            @transaction_script
            pub proc main
                push.{root}
                call.::miden::standards::components::auth::hot_cold_guardian::get_procedure_policy
                # => [immediate_threshold, cold_required, pad(14)]

                eq.{immediate_threshold} assert.err="unexpected immediate threshold"
                eq.{cold_required} assert.err="unexpected cold required flag"
                drop drop
            end
            "#,
            root = proc_root.as_word(),
        ))?;
        let tx = mock_chain.build_transaction(account.id()).tx_script(script).multisig_auth_args(
            MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt(salt_seed)),
        );
        sign_and_execute(tx, &[&hot[0], &guardian]).await??;
    }

    Ok(())
}

/// A stored policy replaces the preset: with `update_hot_keys` configured as `HotOrCold`, a hot key
/// plus the guardian can replace the hot keys.
#[tokio::test]
async fn test_hot_cold_guardian_stored_policy_replaces_preset() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let HotColdAccount { hot, guardian, account, .. } = create_hot_cold_guardian_account(
        auth_scheme,
        1,
        10,
        BTreeMap::from([(AuthHotColdGuardian::update_hot_keys_root(), HotColdPolicy::HotOrCold)]),
    )?;
    let mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    let new_hot = Signer::new(auth_scheme, &mut ChaCha20Rng::from_seed(rand::random()));

    let tx = update_hot_keys_tx(&mock_chain, &account, &[new_hot.approver()], 1)?;
    sign_and_execute(tx, &[&hot[0], &guardian]).await??;

    Ok(())
}

/// The component pays the transaction fee after the signatures are verified, within the max fee it
/// estimates when the auth args carry none.
#[tokio::test]
async fn test_hot_cold_guardian_pays_fee_note() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::Falcon512Eidos;
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let hot: Vec<_> = (0..2).map(|_| Signer::new(auth_scheme, &mut rng)).collect();
    let cold = Signer::new(auth_scheme, &mut rng);
    let guardian = Signer::new(auth_scheme, &mut rng);

    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let initial_fee_asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let mut account = builder.add_existing_wallet_with_assets(
        Auth::HotColdGuardian {
            hot_keys: hot.iter().map(Signer::approver).collect(),
            cold_key: cold.approver(),
            guardian_config: GuardianConfig::new(guardian.approver()),
            delay_config: HotColdDelayConfig::default(),
            proc_policy_map: BTreeMap::new(),
        },
        [initial_fee_asset.into()],
    )?;
    let mock_chain = builder.build()?;

    // no max fee is set, so the auth procedure estimates it, counting every hot key, the cold key
    // and the guardian as signers
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt(7))
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id));

    let tx_summary = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let msg = tx_summary.as_ref().to_commitment();
    let signed_auth_args = auth_args.with_max_fee_from_summary(&tx_summary)?;
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut signed_builder =
        mock_chain.build_transaction(account.id()).multisig_auth_args(signed_auth_args);
    for signer in [&hot[0], &guardian] {
        let signature =
            signer.authenticator.get_signature(signer.commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(signer.commitment(), msg, signature);
    }
    let executed = signed_builder.build()?.execute().await?;

    let paid_fee_asset = assert_single_fee_note(&executed)?;
    account.apply_patch(executed.account_patch())?;
    assert_eq!(
        account.vault().get_balance(initial_fee_asset.id())?.as_u64(),
        initial_fee_asset.amount().as_u64() - paid_fee_asset.amount().as_u64()
    );

    Ok(())
}
