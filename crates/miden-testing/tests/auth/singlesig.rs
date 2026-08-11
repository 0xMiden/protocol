use assert_matches::assert_matches;
use miden_processor::ExecutionError;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorage,
    AccountType,
};
use miden_protocol::asset::{AssetAmount, FungibleAsset, TokenSymbol};
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{Approver, AuthSingleSig};
use miden_standards::account::faucets::{
    Description,
    FungibleFaucet,
    TokenName,
    create_singlesig_user_fungible_faucet,
};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::BurnNote;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::BasicAuthenticator;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

// HELPER FUNCTIONS
// ================================================================================================

/// Sets up a singlesig account with a MockAccountComponent (which provides set_item).
/// Returns (account, mock_chain, note, authenticator).
fn setup_singlesig_with_mock_component(
    auth_scheme: AuthScheme,
) -> anyhow::Result<(Account, MockChain, Note, Option<BasicAuthenticator>)> {
    let mock_component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let (auth_components, authenticator) = Auth::BasicAuth { auth_scheme }.build_components();

    let account = AccountBuilder::new([0; 32])
        .with_components(auth_components)
        .with_component(mock_component)
        .account_type(AccountType::Public)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    // Create a mock note to consume (needed to make the transaction non-empty)
    let note = NoteBuilder::new(account.id(), &mut rand::rng())
        .build()
        .expect("failed to create mock note");
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mock_chain = builder.build()?;

    Ok((account, mock_chain, note, authenticator))
}

/// Tests that the singlesig auth procedure reads the initial (pre-rotation) public key
/// when verifying signatures. The transaction script overwrites the public key slot with
/// a bogus value before auth runs; the test verifies that authentication still succeeds
/// because the auth procedure uses `get_initial_item` to retrieve the original key,
/// rather than `get_item` which would return the overwritten (bogus) value.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_singlesig_auth_uses_initial_public_key(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (account, mock_chain, note, authenticator) =
        setup_singlesig_with_mock_component(auth_scheme)?;

    let pub_key_slot = AuthSingleSig::public_key_slot();
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

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(tx_script_src)?;
    let mock_tx = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(note)
        .authenticator(authenticator)
        .tx_script(tx_script)
        .build()?;

    mock_tx
        .execute()
        .await
        .expect("singlesig auth should use initial public key, not the rotated one");

    Ok(())
}

/// Rotated-key negative: tx rotates the pub-key slot to key B and the authenticator is set
/// up to sign with sec_b under key A's commitment. Auth reads the initial key (A) via
/// `get_initial_item`, so MASM verify must reject the bogus signature.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_singlesig_auth_rejects_rotated_key_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (account, mock_chain, note, _) = setup_singlesig_with_mock_component(auth_scheme)?;

    // Re-derive key A from the seed Auth::BasicAuth uses.
    let mut rng_a = ChaCha20Rng::from_seed(Default::default());
    let pub_key_a = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng_a)
        .expect("failed to derive original public key")
        .public_key();

    let mut rng_b = ChaCha20Rng::from_seed([1u8; 32]);
    let sec_key_b = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng_b)
        .expect("failed to create second secret key");
    let pub_key_b_commitment: Word = sec_key_b.public_key().to_commitment().into();

    // Bind sec_b to key A's commitment so MASM actually receives a signature and runs
    // verify against pub A, which must reject it.
    let authenticator = BasicAuthenticator::from_key_pairs(&[(sec_key_b, pub_key_a)]);

    let pub_key_slot = AuthSingleSig::public_key_slot();
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

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(tx_script_src)?;
    let mock_tx = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(note)
        .authenticator(Some(authenticator))
        .tx_script(tx_script)
        .build()?;

    let result = mock_tx.execute().await;

    match auth_scheme {
        AuthScheme::EcdsaK256Keccak => {
            assert_transaction_executor_error!(
                result,
                MasmError::from_static_str("invalid public key commitment")
            );
        },
        AuthScheme::Falcon512Poseidon2 => {
            // Falcon's h-vs-PK check in `load_h_s2_and_product` is a bare `assert_eqw`
            // without a named err, so we can only assert the failed-assertion shape.
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

// BURN NOTE AGAINST SINGLESIG USER FAUCET
// ================================================================================================

/// Sets up a singlesig user fungible faucet (built via the production
/// `create_singlesig_user_fungible_faucet` factory) with an existing token supply, and a BURN
/// note targeting it. Returns (faucet account, mock chain, burn note, authenticator).
fn setup_singlesig_user_faucet_with_burn_note(
    auth_scheme: AuthScheme,
) -> anyhow::Result<(Account, MockChain, Note, BasicAuthenticator)> {
    let mut rng = ChaCha20Rng::from_seed(Default::default());
    let sec_key = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng)?;
    let pub_key = sec_key.public_key().to_commitment();
    let authenticator = BasicAuthenticator::new(&[sec_key]);

    let auth_component = AuthSingleSig::new(Approver::new(pub_key, auth_scheme));

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

    let faucet_account = create_singlesig_user_fungible_faucet(
        [42u8; 32],
        faucet,
        auth_component,
        policy_manager,
        AccountType::Public,
    )?;
    // The factory builds a new account (nonce 0, carrying a seed); MockChain genesis accounts
    // must be existing (nonce != 0, no seed), so re-wrap the built code/storage/vault as such.
    let faucet_account = Account::new(
        faucet_account.id(),
        faucet_account.vault().clone(),
        faucet_account.storage().clone(),
        faucet_account.code().clone(),
        Felt::ONE,
        None,
    )?;

    let sender = AccountId::builder().account_type(AccountType::Private).build_with_seed([3; 32]);
    let asset = FungibleAsset::new(faucet_account.id(), 10)?;
    let mut note_rng = RandomCoin::new([Felt::from(7u32); 4].into());
    let burn_note: Note = BurnNote::builder()
        .sender(sender)
        .asset(asset)
        .generate_serial_number(&mut note_rng)
        .build()?
        .into();

    let mut builder = MockChain::builder();
    builder.add_account(faucet_account.clone())?;
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));
    let mock_chain = builder.build()?;

    Ok((faucet_account, mock_chain, burn_note, authenticator))
}

/// A BURN note targeted at a plain `AuthSingleSig` user faucet cannot be consumed without a
/// signature: unlike the removed `AuthSingleSigAcl`, `AuthSingleSig` has no exempt list, so every
/// call - including one that only reaches `receive_and_burn` - requires authentication.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_singlesig_burn_note_against_user_faucet_requires_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (faucet_account, mock_chain, burn_note, _authenticator) =
        setup_singlesig_user_faucet_with_burn_note(auth_scheme)?;

    let result = mock_chain
        .build_transaction(faucet_account.id())
        .authenticated_input_note(burn_note.id())
        .authenticator(None)
        .build()?
        .execute()
        .await;

    assert_matches!(result, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// The same BURN note succeeds once the faucet owner's signature is supplied, confirming that a
/// faucet built by `create_singlesig_user_fungible_faucet` can still burn assets, just not for
/// free. `AuthSingleSig` bumps the nonce unconditionally regardless of whether state changed
/// (see `singlesig.masm`), so a nonce-only assertion would not prove the burn ran; instead this
/// asserts the faucet's token supply actually dropped by the burned amount.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_singlesig_burn_note_against_user_faucet_succeeds_with_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (faucet_account, mock_chain, burn_note, authenticator) =
        setup_singlesig_user_faucet_with_burn_note(auth_scheme)?;

    let executed_transaction = mock_chain
        .build_transaction(faucet_account.id())
        .authenticated_input_note(burn_note.id())
        .authenticator(Some(authenticator))
        .build()?
        .execute()
        .await?;

    let mut updated_account = faucet_account.clone();
    updated_account.apply_patch(executed_transaction.account_patch())?;
    let updated_faucet = FungibleFaucet::try_from(updated_account.storage())?;

    assert_eq!(updated_faucet.token_supply(), AssetAmount::new(90)?);

    Ok(())
}
