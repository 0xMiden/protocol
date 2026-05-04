use core::slice;

use assert_matches::assert_matches;
use miden_processor::ExecutionError;
use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountStorage,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::code_builder::CodeBuilder;
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

    let (auth_component, authenticator) = Auth::BasicAuth { auth_scheme }.build_component();

    let account = AccountBuilder::new([0; 32])
        .with_auth_component(auth_component)
        .with_component(mock_component)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
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

        begin
            push.99.98.97.96
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?;
    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(authenticator)
        .tx_script(tx_script)
        .build()?;

    tx_context
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

        begin
            push.NEW_PUB_KEY
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
        new_pub_key = pub_key_b_commitment,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?;
    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(Some(authenticator))
        .tx_script(tx_script)
        .build()?;

    let result = tx_context.execute().await;

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
