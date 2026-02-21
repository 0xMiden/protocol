use miden_protocol::account::AccountId;
use miden_protocol::asset::NonFungibleAsset;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::testing::constants::{FUNGIBLE_ASSET_AMOUNT, NON_FUNGIBLE_ASSET_DATA};
use miden_protocol::{Felt, Hasher, Word};

use crate::TransactionContextBuilder;
use crate::kernel_tests::tx::ExecutionOutputExt;

#[tokio::test]
async fn test_create_fungible_asset_succeeds() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .build()?;

    let code = format!(
        "
        use $kernel::prologue
        use miden::protocol::faucet

        begin
            exec.prologue::prepare_transaction

            # create fungible asset
            push.{FUNGIBLE_ASSET_AMOUNT}
            exec.faucet::create_fungible_asset

            # truncate the stack
            swapw dropw
        end
        "
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    assert_eq!(
        exec_output.get_stack_word_be(0),
        Word::from([
            Felt::new(FUNGIBLE_ASSET_AMOUNT),
            Felt::new(0),
            faucet_id.suffix(),
            faucet_id.prefix().as_felt(),
        ])
    );
    Ok(())
}

#[tokio::test]
async fn test_create_non_fungible_asset_succeeds() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;

    let non_fungible_asset = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA);

    let code = format!(
        "
        use $kernel::prologue
        use miden::protocol::faucet

        begin
            exec.prologue::prepare_transaction

            # push non-fungible asset data hash onto the stack
            push.{non_fungible_asset_data_hash}
            exec.faucet::create_non_fungible_asset

            # truncate the stack
            swapw dropw
        end
        ",
        non_fungible_asset_data_hash = Hasher::hash(&NON_FUNGIBLE_ASSET_DATA),
    );

    let exec_output = &tx_context.execute_code(&code).await?;
    assert_eq!(exec_output.get_stack_word_be(0), Word::from(non_fungible_asset));

    Ok(())
}

#[tokio::test]
async fn test_validate_non_fungible_asset() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;

    let non_fungible_asset = Word::from(NonFungibleAsset::mock(&[1, 2, 3]));

    let code = format!(
        "
        use $kernel::asset

        begin
            push.{non_fungible_asset}
            exec.asset::validate_non_fungible_asset

            # truncate the stack
            swapw dropw
        end
        "
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_word_be(0), non_fungible_asset);
    Ok(())
}
