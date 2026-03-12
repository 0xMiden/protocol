use miden_protocol::account::AccountId;
use miden_protocol::asset::{
    AssetCallbackFlag,
    AssetId,
    AssetVaultKey,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::errors::MasmError;
use miden_protocol::errors::tx_kernel::{
    ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_AMOUNT,
    ERR_FUNGIBLE_ASSET_KEY_ACCOUNT_ID_MUST_BE_FUNGIBLE,
    ERR_FUNGIBLE_ASSET_KEY_ASSET_ID_MUST_BE_ZERO,
    ERR_FUNGIBLE_ASSET_VALUE_MOST_SIGNIFICANT_ELEMENTS_MUST_BE_ZERO,
    ERR_NON_FUNGIBLE_ASSET_ID_PREFIX_MUST_MATCH_HASH1,
    ERR_NON_FUNGIBLE_ASSET_ID_SUFFIX_MUST_MATCH_HASH0,
    ERR_NON_FUNGIBLE_ASSET_KEY_ACCOUNT_ID_MUST_BE_NON_FUNGIBLE,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::testing::constants::{FUNGIBLE_ASSET_AMOUNT, NON_FUNGIBLE_ASSET_DATA};
use miden_protocol::{Felt, Word};

use crate::executor::CodeExecutor;
use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::{TransactionContextBuilder, assert_execution_error};

#[tokio::test]
async fn test_create_fungible_asset_succeeds() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .build()?;
    let expected_asset = FungibleAsset::new(tx_context.account().id(), FUNGIBLE_ASSET_AMOUNT)?;

    let code = format!(
        "
        use $kernel::prologue
        use miden::protocol::faucet

        begin
            exec.prologue::prepare_transaction

            # create fungible asset
            push.{FUNGIBLE_ASSET_AMOUNT}
            exec.faucet::create_fungible_asset
            # => [ASSET_KEY, ASSET_VALUE]

            # truncate the stack
            exec.::miden::core::sys::truncate_stack
        end
        "
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), expected_asset.to_key_word());
    assert_eq!(exec_output.get_stack_word(4), expected_asset.to_value_word());

    Ok(())
}

#[tokio::test]
async fn test_create_non_fungible_asset_succeeds() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;

    let non_fungible_asset_details = NonFungibleAssetDetails::new(
        NonFungibleAsset::mock_issuer(),
        NON_FUNGIBLE_ASSET_DATA.to_vec(),
    )?;
    let non_fungible_asset = NonFungibleAsset::new(&non_fungible_asset_details)?;

    let code = format!(
        "
        use $kernel::prologue
        use miden::protocol::faucet

        begin
            exec.prologue::prepare_transaction

            # push non-fungible asset data hash onto the stack
            push.{NON_FUNGIBLE_ASSET_DATA_HASH}
            exec.faucet::create_non_fungible_asset

            # truncate the stack
            exec.::miden::core::sys::truncate_stack
        end
        ",
        NON_FUNGIBLE_ASSET_DATA_HASH = non_fungible_asset.to_value_word(),
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), non_fungible_asset.to_key_word());
    assert_eq!(exec_output.get_stack_word(4), non_fungible_asset.to_value_word());

    Ok(())
}

#[rstest::rstest]
#[case::account_is_not_non_fungible_faucet(
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?,
    AssetId::default(),
    ERR_NON_FUNGIBLE_ASSET_KEY_ACCOUNT_ID_MUST_BE_NON_FUNGIBLE
)]
#[case::asset_id_suffix_mismatch(
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into()?,
    AssetId::new(Felt::from(0u32), Felt::from(3u32)),
    ERR_NON_FUNGIBLE_ASSET_ID_SUFFIX_MUST_MATCH_HASH0
)]
#[case::asset_id_prefix_mismatch(
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into()?,
    AssetId::new(Felt::from(2u32), Felt::from(0u32)),
    ERR_NON_FUNGIBLE_ASSET_ID_PREFIX_MUST_MATCH_HASH1
)]
#[tokio::test]
async fn test_validate_non_fungible_asset(
    #[case] account_id: AccountId,
    #[case] asset_id: AssetId,
    #[case] expected_err: MasmError,
) -> anyhow::Result<()> {
    let code = format!(
        "
        use $kernel::non_fungible_asset

        begin
            # a random asset value
            push.[2, 3, 4, 5]
            # => [hash0 = 2, hash1 = 3, 4, 5]

            push.{account_id_prefix}
            push.{account_id_suffix}
            push.{asset_id_prefix}
            push.{asset_id_suffix}
            # => [ASSET_KEY, ASSET_VALUE]

            exec.non_fungible_asset::validate

            # truncate the stack
            swapdw dropw dropw
        end
        ",
        asset_id_suffix = asset_id.suffix(),
        asset_id_prefix = asset_id.prefix(),
        account_id_suffix = account_id.suffix(),
        account_id_prefix = account_id.prefix().as_felt(),
    );

    let exec_result = CodeExecutor::with_default_host().run(&code).await;

    assert_execution_error!(exec_result, expected_err);

    Ok(())
}

#[rstest::rstest]
#[case::account_is_not_fungible_faucet(
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?,
    AssetId::default(),
    Word::empty(),
    ERR_FUNGIBLE_ASSET_KEY_ACCOUNT_ID_MUST_BE_FUNGIBLE
)]
#[case::asset_id_suffix_is_non_zero(
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?,
    AssetId::new(Felt::from(1u32), Felt::from(0u32)),
    Word::empty(),
    ERR_FUNGIBLE_ASSET_KEY_ASSET_ID_MUST_BE_ZERO
)]
#[case::asset_id_prefix_is_non_zero(
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?,
    AssetId::new(Felt::from(0u32), Felt::from(1u32)),
    Word::empty(),
    ERR_FUNGIBLE_ASSET_KEY_ASSET_ID_MUST_BE_ZERO
)]
#[case::non_amount_value_is_non_zero(
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?,
    AssetId::default(),
    Word::from([0, 1, 0, 0u32]),
    ERR_FUNGIBLE_ASSET_VALUE_MOST_SIGNIFICANT_ELEMENTS_MUST_BE_ZERO
)]
#[case::amount_exceeds_max(
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?,
    AssetId::default(),
    Word::try_from([FungibleAsset::MAX_AMOUNT + 1, 0, 0, 0])?,
    ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_AMOUNT
)]
#[tokio::test]
async fn test_validate_fungible_asset(
    #[case] account_id: AccountId,
    #[case] asset_id: AssetId,
    #[case] asset_value: Word,
    #[case] expected_err: MasmError,
) -> anyhow::Result<()> {
    let code = format!(
        "
        use $kernel::fungible_asset

        begin
            push.{ASSET_VALUE}
            push.{account_id_prefix}
            push.{account_id_suffix}
            push.{asset_id_prefix}
            push.{asset_id_suffix}
            # => [ASSET_KEY, ASSET_VALUE]

            exec.fungible_asset::validate

            # truncate the stack
            swapdw dropw dropw
        end
        ",
        asset_id_suffix = asset_id.suffix(),
        asset_id_prefix = asset_id.prefix(),
        account_id_suffix = account_id.suffix(),
        account_id_prefix = account_id.prefix().as_felt(),
        ASSET_VALUE = asset_value,
    );

    let exec_result = CodeExecutor::with_default_host().run(&code).await;

    assert_execution_error!(exec_result, expected_err);

    Ok(())
}

#[rstest::rstest]
#[case::without_callbacks(AssetCallbackFlag::Disabled)]
#[case::with_callbacks(AssetCallbackFlag::Enabled)]
#[tokio::test]
async fn test_key_to_asset_metadata(#[case] callbacks: AssetCallbackFlag) -> anyhow::Result<()> {
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
    let vault_key = AssetVaultKey::new(AssetId::default(), faucet_id, callbacks)?;

    let code = format!(
        "
        use $kernel::asset

        begin
            push.{ASSET_KEY}
            exec.asset::key_to_callbacks_enabled
            # => [callbacks_enabled, ASSET_KEY]

            # truncate stack
            swapw dropw swap drop
            # => [callbacks_enabled]
        end
        ",
        ASSET_KEY = vault_key.to_word(),
    );

    let exec_output = CodeExecutor::with_default_host().run(&code).await?;

    assert_eq!(
        exec_output.get_stack_element(0).as_canonical_u64(),
        callbacks.as_u8() as u64,
        "MASM key_to_asset_category returned wrong value for {callbacks:?}"
    );

    Ok(())
}
