extern crate alloc;

use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_standards::account::inspection::AccountSchemaCommitment;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};

// HELPERS
// ================================================================================================

/// Builds an account exposing the `BasicWallet` and `AccountSchemaCommitment` components.
fn create_schema_committed_account() -> anyhow::Result<Account> {
    let builder = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet);

    // Mirrors `build_with_schema_commitment`, but builds an existing account so the mock chain can
    // hold it without a seed.
    let schema_commitment = AccountSchemaCommitment::new(builder.storage_schemas())?;

    Ok(builder.with_component(schema_commitment).build_existing()?)
}

// TESTS
// ================================================================================================

/// `AccountSchemaCommitment::get_schema_commitment`, invoked via `call` from a transaction script,
/// returns the commitment to the account's storage schema and honours the 16-felt call ABI.
#[tokio::test]
async fn schema_commitment_get_schema_commitment() -> anyhow::Result<()> {
    let account = create_schema_committed_account()?;
    let expected_schema_commitment =
        account.storage().get_item(AccountSchemaCommitment::schema_commitment_slot())?;

    // The getter expects `[pad(16)]`, so the script pads the stack before the call.
    let tx_script_code = format!(
        r#"
        use miden::standards::components::inspection::schema_commitment

        @transaction_script
        pub proc main
            padw padw padw padw
            call.schema_commitment::get_schema_commitment
            # => [SCHEMA_COMMITMENT, pad(12), pad(16)]
            push.{expected_schema_commitment}
            assert_eqw.err="get_schema_commitment returned an unexpected commitment or violated the call ABI"
            dropw dropw dropw
        end
        "#
    );

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(AccountSchemaCommitment::code())?
        .compile_tx_script(tx_script_code)?;

    mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}
