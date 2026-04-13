use core::slice;

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
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::auth::BasicAuthenticator;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use crate::prove_and_verify_transaction;

// HELPER FUNCTIONS
// ================================================================================================

/// Sets up a singlesig account with a MockAccountComponent (which provides set_item).
/// Returns (account, mock_chain, note).
fn setup_singlesig_with_mock_component(
    auth_scheme: AuthScheme,
) -> anyhow::Result<(Account, MockChain, Note)> {
    let mock_component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let (auth_component, _authenticator) = Auth::BasicAuth { auth_scheme }.build_component();

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

    Ok((account, mock_chain, note))
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
    let (account, mock_chain, note) = setup_singlesig_with_mock_component(auth_scheme)?;

    // Build the authenticator separately (same seed as Auth::BasicAuth uses)
    let (_, authenticator) = Auth::BasicAuth { auth_scheme }.build_component();

    // Get the singlesig public key slot name
    let pub_key_slot = AuthSingleSig::public_key_slot();

    // This tx script rotates the public key to a bogus value during the transaction.
    // The auth procedure runs AFTER this script, so if it used `get_item` it would read
    // the bogus key and fail. Because it uses `get_initial_item`, it reads the original
    // key and signature verification succeeds.
    let tx_script_rotate_key = format!(
        r#"
        use mock::account

        const PUB_KEY_SLOT = word("{pub_key_slot}")

        begin
            # Overwrite the public key slot with a bogus value
            push.99.98.97.96
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_rotate_key)?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(authenticator)
        .tx_script(tx_script)
        .build()?;

    // This should succeed because the auth procedure reads the INITIAL public key,
    // not the rotated one.
    let executed_tx = tx_context
        .execute()
        .await
        .expect("singlesig auth should use initial public key, not the rotated one");

    prove_and_verify_transaction(executed_tx).await?;

    Ok(())
}

/// Tests the negative scenario: the transaction script rotates the public key to a new
/// *valid* key, and the authenticator signs with that new key. The auth procedure should
/// reject the signature because it reads the *initial* public key (key A), not the rotated
/// one (key B). This proves that even with a valid signature from the new key, the auth
/// procedure correctly uses the initial storage state.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_singlesig_auth_rejects_rotated_key_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_singlesig_with_mock_component(auth_scheme)?;

    // Generate a second valid key pair (key B) using a different seed.
    // The account was built with key A (seed = [0; 32] via Auth::BasicAuth).
    let mut rng_b = ChaCha20Rng::from_seed([1u8; 32]);
    let sec_key_b = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng_b)
        .expect("failed to create second secret key");
    let pub_key_b_commitment: Word = sec_key_b.public_key().to_commitment().into();

    // Create an authenticator that only knows key B (the new key).
    let authenticator_b = BasicAuthenticator::new(&[sec_key_b]);

    // Get the singlesig public key slot name
    let pub_key_slot = AuthSingleSig::public_key_slot();

    // This tx script rotates the public key to key B's valid commitment.
    // The authenticator will sign with key B, but the auth procedure reads the
    // initial key (key A) via `get_initial_item`, so verification should fail.
    let tx_script_rotate_key = format!(
        r#"
        use mock::account

        const PUB_KEY_SLOT = word("{pub_key_slot}")
        const NEW_PUB_KEY = word("{new_pub_key}")

        begin
            # Overwrite the public key slot with key B's valid public key commitment
            push.NEW_PUB_KEY
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
        new_pub_key = pub_key_b_commitment,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_rotate_key)?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(Some(authenticator_b))
        .tx_script(tx_script)
        .build()?;

    // This should FAIL because the auth procedure reads the initial key (A) but the
    // authenticator signs with key B. The signature verification will not match.
    let result = tx_context.execute().await;
    assert!(
        result.is_err(),
        "transaction should fail when signed with the rotated key instead of the initial key"
    );

    Ok(())
}
