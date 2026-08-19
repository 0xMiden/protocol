use miden_protocol::account::AccountId;
use miden_protocol::asset::{
    AssetClass,
    AssetComposition,
    AssetId,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::errors::MasmError;
use miden_protocol::errors::protocol::ERR_VAULT_ASSET_METADATA_NON_ZERO_RESERVED_BITS;
use miden_protocol::errors::tx_kernel::{
    ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_AMOUNT,
    ERR_FUNGIBLE_ASSET_ID_ASSET_CLASS_MUST_BE_ZERO,
    ERR_FUNGIBLE_ASSET_ID_COMPOSITION_MUST_BE_FUNGIBLE,
    ERR_FUNGIBLE_ASSET_VALUE_MOST_SIGNIFICANT_ELEMENTS_MUST_BE_ZERO,
    ERR_VAULT_ASSET_METADATA_NOT_U32,
    ERR_VAULT_ASSET_METADATA_UNKNOWN_COMPOSITION,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::testing::constants::{FUNGIBLE_ASSET_AMOUNT, NON_FUNGIBLE_ASSET_DATA};
use miden_protocol::{Felt, Word};
use miden_standards::errors::standards::{
    ERR_NON_FUNGIBLE_ASSET_CLASS_PREFIX_MUST_MATCH_HASH1,
    ERR_NON_FUNGIBLE_ASSET_CLASS_SUFFIX_MUST_MATCH_HASH0,
    ERR_NON_FUNGIBLE_ASSET_ID_COMPOSITION_MUST_BE_NON_FUNGIBLE,
};

use crate::executor::CodeExecutor;
use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::{TestTransactionBuilder, assert_execution_error};

#[tokio::test]
async fn test_create_fungible_asset_succeeds() -> anyhow::Result<()> {
    let mock_tx =
        TestTransactionBuilder::with_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).build()?;
    let expected_asset = FungibleAsset::new(mock_tx.account().id(), FUNGIBLE_ASSET_AMOUNT)?;

    let code = format!(
        "
        use miden::tx_kernel_core::prologue
        use miden::standards::assets::fungible_asset

        begin
            exec.prologue::prepare_transaction

            # create fungible asset for the active faucet
            push.{FUNGIBLE_ASSET_AMOUNT}
            exec.::miden::protocol::active_account::get_id
            exec.fungible_asset::create
            # => [ASSET_ID, ASSET_VALUE]

            # truncate the stack
            exec.::miden::core::sys::truncate_stack
        end
        "
    );

    let exec_output = &mock_tx.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), expected_asset.to_id_word());
    assert_eq!(exec_output.get_stack_word(4), expected_asset.to_value_word());

    Ok(())
}

#[tokio::test]
async fn test_create_non_fungible_asset_succeeds() -> anyhow::Result<()> {
    let mock_tx =
        TestTransactionBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;

    let non_fungible_asset_details = NonFungibleAssetDetails::new(
        NonFungibleAsset::mock_issuer(),
        NON_FUNGIBLE_ASSET_DATA.to_vec(),
    );
    let non_fungible_asset = NonFungibleAsset::new(&non_fungible_asset_details);

    let code = format!(
        "
        use miden::tx_kernel_core::prologue
        use miden::standards::assets::non_fungible_asset

        begin
            exec.prologue::prepare_transaction

            # push non-fungible asset data hash onto the stack
            push.{NON_FUNGIBLE_ASSET_DATA_HASH}
            exec.::miden::protocol::active_account::get_id
            exec.non_fungible_asset::create

            # truncate the stack
            exec.::miden::core::sys::truncate_stack
        end
        ",
        NON_FUNGIBLE_ASSET_DATA_HASH = non_fungible_asset.to_value_word(),
    );

    let exec_output = &mock_tx.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), non_fungible_asset.to_id_word());
    assert_eq!(exec_output.get_stack_word(4), non_fungible_asset.to_value_word());

    Ok(())
}

const METADATA_BYTE_NONE: u64 = AssetComposition::None as u64;
const METADATA_BYTE_FUNGIBLE: u64 = AssetComposition::Fungible as u64;

/// Returns the third element of a synthesised asset ID, packing the faucet ID suffix with the
/// given metadata byte (lower 8 bits).
fn key_suffix_with_metadata(account_id: AccountId, metadata_byte: u64) -> Felt {
    Felt::try_from(account_id.suffix().as_canonical_u64() | metadata_byte)
        .expect("metadata byte only occupies the lower 8 bits")
}

/// The standards `validate` procedure rejects malformed non-fungible assets.
#[rstest::rstest]
#[case::composition_is_not_non_fungible(
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into()?,
    AssetClass::new(Felt::from(2u32), Felt::from(3u32)),
    METADATA_BYTE_FUNGIBLE,
    ERR_NON_FUNGIBLE_ASSET_ID_COMPOSITION_MUST_BE_NON_FUNGIBLE
)]
#[case::asset_class_suffix_mismatch(
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into()?,
    AssetClass::new(Felt::from(0u32), Felt::from(3u32)),
    METADATA_BYTE_NONE,
    ERR_NON_FUNGIBLE_ASSET_CLASS_SUFFIX_MUST_MATCH_HASH0
)]
#[case::asset_class_prefix_mismatch(
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into()?,
    AssetClass::new(Felt::from(2u32), Felt::from(0u32)),
    METADATA_BYTE_NONE,
    ERR_NON_FUNGIBLE_ASSET_CLASS_PREFIX_MUST_MATCH_HASH1
)]
#[tokio::test]
async fn test_validate_non_fungible_asset(
    #[case] account_id: AccountId,
    #[case] asset_class: AssetClass,
    #[case] metadata_byte: u64,
    #[case] expected_err: MasmError,
) -> anyhow::Result<()> {
    let code = format!(
        "
        use miden::standards::assets::non_fungible_asset

        begin
            # a random asset value
            push.[2, 3, 4, 5]
            # => [hash0 = 2, hash1 = 3, 4, 5]

            push.{account_id_prefix}
            push.{account_id_suffix}
            push.{asset_class_prefix}
            push.{asset_class_suffix}
            # => [ASSET_ID, ASSET_VALUE]

            exec.non_fungible_asset::validate

            # truncate the stack
            swapdw dropw dropw
        end
        ",
        asset_class_suffix = asset_class.suffix(),
        asset_class_prefix = asset_class.prefix(),
        account_id_suffix = key_suffix_with_metadata(account_id, metadata_byte),
        account_id_prefix = account_id.prefix().as_felt(),
    );

    let exec_result = CodeExecutor::with_default_host().run(&code).await;

    assert_execution_error!(exec_result, expected_err);

    Ok(())
}

/// A well-formed non-fungible asset passes the standards-side `validate` and leaves the asset ID
/// and value on the stack unchanged.
#[tokio::test]
async fn test_validate_non_fungible_asset_standards_succeeds() -> anyhow::Result<()> {
    let non_fungible_asset_details = NonFungibleAssetDetails::new(
        NonFungibleAsset::mock_issuer(),
        NON_FUNGIBLE_ASSET_DATA.to_vec(),
    );
    let non_fungible_asset = NonFungibleAsset::new(&non_fungible_asset_details);

    let code = format!(
        "
        use miden::standards::assets::non_fungible_asset

        begin
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            # => [ASSET_ID, ASSET_VALUE]

            exec.non_fungible_asset::validate

            # truncate the stack
            swapdw dropw dropw
        end
        ",
        ASSET_VALUE = non_fungible_asset.to_value_word(),
        ASSET_ID = non_fungible_asset.to_id_word(),
    );

    let exec_output = CodeExecutor::with_default_host().run(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), non_fungible_asset.to_id_word());
    assert_eq!(exec_output.get_stack_word(4), non_fungible_asset.to_value_word());

    Ok(())
}

/// The kernel treats the value of an asset that is not fungible as opaque.
///
/// An asset with `AssetComposition::None` is valid even when its asset class is not derived from
/// its value. The issuer and the metadata are still validated.
#[rstest::rstest]
#[case::asset_class_is_not_derived_from_value(METADATA_BYTE_NONE, None)]
#[case::metadata_reserved_bits_are_set(
    METADATA_BYTE_NONE | 0b100,
    Some(ERR_VAULT_ASSET_METADATA_NON_ZERO_RESERVED_BITS)
)]
#[tokio::test]
async fn test_validate_asset_with_non_fungible_composition(
    #[case] metadata_byte: u64,
    #[case] expected_err: Option<MasmError>,
    #[values("validate", "validate_id")] procedure: &str,
) -> anyhow::Result<()> {
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET)?;
    // an asset class that is deliberately unrelated to the asset value
    let asset_class = AssetClass::new(Felt::from(7u32), Felt::from(9u32));
    let asset_value = Word::from([2, 3, 4, 5u32]);
    let asset_id = Word::from([
        asset_class.suffix(),
        asset_class.prefix(),
        key_suffix_with_metadata(faucet_id, metadata_byte),
        faucet_id.prefix().as_felt(),
    ]);

    let code = format!(
        "
        use miden::tx_kernel_core::asset

        begin
            push.{asset_value}
            push.{asset_id}
            # => [ASSET_ID, ASSET_VALUE]

            exec.asset::{procedure}

            # truncate the stack
            swapdw dropw dropw
        end
        "
    );

    let exec_result = CodeExecutor::with_default_host().run(&code).await;

    match expected_err {
        Some(err) => assert_execution_error!(exec_result, err),
        None => {
            let exec_output = exec_result?;
            assert_eq!(exec_output.get_stack_word(0), asset_id);
            assert_eq!(exec_output.get_stack_word(4), asset_value);
        },
    }

    Ok(())
}

#[rstest::rstest]
#[case::account_is_not_fungible_faucet(
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?,
    AssetClass::default(),
    Word::empty(),
    METADATA_BYTE_NONE,
    ERR_FUNGIBLE_ASSET_ID_COMPOSITION_MUST_BE_FUNGIBLE
)]
#[case::asset_class_suffix_is_non_zero(
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?,
    AssetClass::new(Felt::from(1u32), Felt::from(0u32)),
    Word::empty(),
    METADATA_BYTE_FUNGIBLE,
    ERR_FUNGIBLE_ASSET_ID_ASSET_CLASS_MUST_BE_ZERO
)]
#[case::asset_class_prefix_is_non_zero(
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?,
    AssetClass::new(Felt::from(0u32), Felt::from(1u32)),
    Word::empty(),
    METADATA_BYTE_FUNGIBLE,
    ERR_FUNGIBLE_ASSET_ID_ASSET_CLASS_MUST_BE_ZERO
)]
#[case::non_amount_value_is_non_zero(
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?,
    AssetClass::default(),
    Word::from([0, 1, 0, 0u32]),
    METADATA_BYTE_FUNGIBLE,
    ERR_FUNGIBLE_ASSET_VALUE_MOST_SIGNIFICANT_ELEMENTS_MUST_BE_ZERO
)]
#[case::amount_exceeds_max(
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?,
    AssetClass::default(),
    Word::try_from([FungibleAsset::MAX_AMOUNT.as_u64() + 1, 0, 0, 0])?,
    METADATA_BYTE_FUNGIBLE,
    ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_AMOUNT
)]
#[tokio::test]
async fn test_validate_fungible_asset(
    #[case] account_id: AccountId,
    #[case] asset_class: AssetClass,
    #[case] asset_value: Word,
    #[case] metadata_byte: u64,
    #[case] expected_err: MasmError,
) -> anyhow::Result<()> {
    let code = format!(
        "
        use miden::tx_kernel_core::fungible_asset

        begin
            push.{ASSET_VALUE}
            push.{account_id_prefix}
            push.{account_id_suffix}
            push.{asset_class_prefix}
            push.{asset_class_suffix}
            # => [ASSET_ID, ASSET_VALUE]

            exec.fungible_asset::validate

            # truncate the stack
            swapdw dropw dropw
        end
        ",
        asset_class_suffix = asset_class.suffix(),
        asset_class_prefix = asset_class.prefix(),
        account_id_suffix = key_suffix_with_metadata(account_id, metadata_byte),
        account_id_prefix = account_id.prefix().as_felt(),
        ASSET_VALUE = asset_value,
    );

    let exec_result = CodeExecutor::with_default_host().run(&code).await;

    assert_execution_error!(exec_result, expected_err);

    Ok(())
}

#[rstest::rstest]
// Valid: composition=None, callbacks=disabled.
#[case::valid_none(0, None)]
// Valid: composition=Fungible, callbacks=disabled.
#[case::valid_fungible(METADATA_BYTE_FUNGIBLE, None)]
// Valid: composition=Custom.
#[case::valid_custom(AssetComposition::Custom as u64, None)]
// Metadata is not a valid u32 (does not fit in 32 bits).
#[case::not_u32(u32::MAX as u64 + 1, Some(ERR_VAULT_ASSET_METADATA_NOT_U32))]
// Metadata is not a valid byte.
#[case::not_u8(u16::MAX as u64, Some(ERR_VAULT_ASSET_METADATA_NON_ZERO_RESERVED_BITS))]
// Reserved bit 2 is set.
#[case::reserved_bit_2_set(0b100, Some(ERR_VAULT_ASSET_METADATA_NON_ZERO_RESERVED_BITS))]
// Reserved bit 3 is set.
#[case::reserved_bits_set(0b1000, Some(ERR_VAULT_ASSET_METADATA_NON_ZERO_RESERVED_BITS))]
// Composition value 3 is the unused bit pattern within the 2-bit field.
#[case::unknown_composition(0b011, Some(ERR_VAULT_ASSET_METADATA_UNKNOWN_COMPOSITION))]
#[tokio::test]
async fn test_validate_asset_metadata(
    #[case] asset_metadata: u64,
    #[case] expected_err: Option<MasmError>,
) -> anyhow::Result<()> {
    let code = format!(
        "
        use miden::tx_kernel_core::asset

        begin
            push.{asset_metadata}
            exec.asset::validate_metadata
        end
        "
    );

    let exec_result = CodeExecutor::with_default_host().run(&code).await;

    match expected_err {
        Some(err) => assert_execution_error!(exec_result, err),
        None => {
            exec_result.expect("validate_metadata should accept valid metadata");
        },
    }

    Ok(())
}

#[rstest::rstest]
#[case::fungible(AssetComposition::Fungible)]
#[case::non_fungible(AssetComposition::None)]
#[tokio::test]
async fn test_id_to_callbacks_and_composition(
    #[case] composition: AssetComposition,
) -> anyhow::Result<()> {
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
    let asset_id = AssetId::new(AssetClass::default(), faucet_id, composition)?;

    let code = format!(
        "
        use miden::tx_kernel_core::asset

        begin
            push.{ASSET_ID}
            exec.asset::id_to_has_callbacks
            # => [has_callbacks, ASSET_ID]
            movdn.4
            # => [ASSET_ID, has_callbacks]

            exec.asset::id_to_composition
            # => [asset_composition, ASSET_ID, has_callbacks]

            # drop the ASSET_ID and one padding element to keep the stack within 16 elements
            movdn.4 dropw swap drop swap drop
            # => [asset_composition, has_callbacks]
        end
        ",
        ASSET_ID = asset_id.to_word(),
    );

    let exec_output = CodeExecutor::with_default_host().run(&code).await?;

    assert_eq!(
        exec_output.get_stack_element(0).as_canonical_u64(),
        composition.as_u8() as u64,
        "MASM asset::id_to_composition returned wrong value for {composition:?}"
    );
    assert_eq!(
        exec_output.get_stack_element(1).as_canonical_u64(),
        asset_id.faucet_id().asset_callback_flag().as_u8() as u64,
        "MASM asset::id_to_has_callbacks returned wrong value for {:?}",
        asset_id.faucet_id().asset_callback_flag()
    );

    Ok(())
}
