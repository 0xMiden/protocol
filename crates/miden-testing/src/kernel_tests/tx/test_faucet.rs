use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{
    Asset,
    AssetClass,
    AssetComposition,
    AssetId,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::errors::tx_kernel::{
    ERR_FAUCET_IS_NOT_ASSET_ORIGIN,
    ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_AMOUNT,
    ERR_VAULT_ASSET_METADATA_NON_ZERO_RESERVED_BITS,
    ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW,
    ERR_VAULT_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND,
};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_WITH_CALLBACKS,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::testing::constants::{CONSUMED_ASSET_1_AMOUNT, FUNGIBLE_ASSET_AMOUNT};
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::memory::INPUT_VAULT_ROOT_PTR;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::{MockAccountComponent, MockFaucetComponent};
use rstest::rstest;

use crate::{
    AccountState,
    Auth,
    MockChain,
    TestTransactionBuilder,
    assert_execution_error,
    assert_transaction_executor_error,
};

// FUNGIBLE FAUCET MINT TESTS
// ================================================================================================

/// Tests that minting a fungible asset on a non-faucet account fails.
#[tokio::test]
async fn mint_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;
    let asset = FungibleAsset::mock(50);

    let code = format!(
        "
      use mock::faucet

      @transaction_script
      pub proc main
          push.{ASSET_VALUE}
          push.{ASSET_ID}
          call.faucet::mint
      end
      ",
        ASSET_ID = asset.to_id_word(),
        ASSET_VALUE = asset.to_value_word(),
    );
    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(code)?;

    let result = TestTransactionBuilder::new(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_FAUCET_IS_NOT_ASSET_ORIGIN);

    Ok(())
}

#[tokio::test]
async fn test_mint_fungible_asset_inconsistent_faucet_id() -> anyhow::Result<()> {
    let mock_tx = TestTransactionBuilder::with_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)
        .build()?;

    let asset = FungibleAsset::mock(5);
    let code = format!(
        "
        use miden::tx_kernel_core::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            call.faucet::mint
        end
        ",
        ASSET_ID = asset.to_id_word(),
        ASSET_VALUE = asset.to_value_word(),
    );

    let exec_output = mock_tx.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_FAUCET_IS_NOT_ASSET_ORIGIN);
    Ok(())
}

/// Tests that minting a fungible asset on a non-faucet account fails when the key has its asset
/// metadata (lower 8 bits) set to u8::MAX.
#[tokio::test]
async fn mint_fungible_asset_fails_on_invalid_asset_metadata() -> anyhow::Result<()> {
    let asset = FungibleAsset::mock(50);

    let mut asset_id_word = asset.to_id_word();
    asset_id_word[2] = Felt::try_from(asset_id_word[2].as_canonical_u64() | 1 << 7)?;

    let code = format!(
        "
      use miden::tx_kernel_core::prologue
      use mock::faucet

      begin
          exec.prologue::prepare_transaction
          push.{ASSET_VALUE}
          push.{ASSET_ID}
          call.faucet::mint
          dropw dropw
      end
      ",
        ASSET_ID = asset_id_word,
        ASSET_VALUE = asset.to_value_word(),
    );

    let result = TestTransactionBuilder::with_fungible_faucet(asset.faucet_id().into())
        .build()?
        .execute_code(&code)
        .await;
    assert_execution_error!(result, ERR_VAULT_ASSET_METADATA_NON_ZERO_RESERVED_BITS);

    Ok(())
}

/// Tests that minting a fungible asset with [`FungibleAsset::MAX_AMOUNT`] + 1 fails.
#[tokio::test]
async fn test_mint_fungible_asset_fails_when_amount_exceeds_max_representable_amount()
-> anyhow::Result<()> {
    let code = format!(
        "
        use mock::faucet

        @transaction_script
        pub proc main
            push.0
            push.0
            push.0
            push.{max_amount_plus_1}
            # => [ASSET_VALUE]

            push.{ASSET_ID}
            # => [ASSET_ID, ASSET_VALUE]

            call.faucet::mint
            dropw dropw
        end
    ",
        ASSET_ID = FungibleAsset::mock(0).to_id_word(),
        max_amount_plus_1 = FungibleAsset::MAX_AMOUNT.as_u64() + 1,
    );
    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(code)?;

    let result = TestTransactionBuilder::with_fungible_faucet(FungibleAsset::mock_issuer().into())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_AMOUNT);
    Ok(())
}

// NON-FUNGIBLE FAUCET MINT TESTS
// ================================================================================================

/// Tests minting succeeds in the tx kernel memory context (to assert input vault conditions).
#[rstest]
#[tokio::test]
async fn test_mint_asset_succeeds_in_tx_kernel(
    // The 2nd case has an unrelated asset in the initial vault.
    #[values(vec![], vec![FungibleAsset::mock(345)])] initial_assets: Vec<Asset>,
    #[values(
      |id| NonFungibleAsset::new(&NonFungibleAssetDetails::new(id, vec![42])).into(),
      |id| FungibleAsset::new(id, 42).unwrap().into(),
    )]
    make_asset: impl FnOnce(AccountId) -> Asset,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account_builder = AccountBuilder::new([1; 32])
        .with_component(MockFaucetComponent)
        .with_assets(initial_assets);
    let faucet =
        builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)?;
    let asset = make_asset(faucet.id());
    let chain = builder.build()?;

    let code = format!(
        r#"
        use miden::tx_kernel_core::asset_vault
        use miden::tx_kernel_core::prologue
        use mock::faucet as mock_faucet

        begin
            # mint asset
            exec.prologue::prepare_transaction
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            call.mock_faucet::mint
            # => []

            # assert the input vault has been updated.
            push.{INPUT_VAULT_ROOT_PTR}
            push.{ASSET_ID}
            exec.asset_vault::get_asset
            push.{ASSET_VALUE}
            assert_eqw.err="vault should contain asset"
            # => []

            # truncate the stack
            dropw dropw
        end
        "#,
        ASSET_ID = asset.to_id_word(),
        ASSET_VALUE = asset.to_value_word(),
    );

    chain.build_transaction(faucet).build()?.execute_code(&code).await?;

    Ok(())
}

/// Tests minting succeeds in a real transaction.
#[rstest]
#[tokio::test]
async fn test_mint_asset_succeeds(
    // The 2nd case has an unrelated asset in the initial vault.
    #[values(vec![], vec![FungibleAsset::mock(345)])] initial_assets: Vec<Asset>,
    #[values(
      |id| NonFungibleAsset::new(&NonFungibleAssetDetails::new(id, vec![42])).into(),
      |id| FungibleAsset::new(id, 42).unwrap().into(),
    )]
    make_asset: impl FnOnce(AccountId) -> Asset,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account_builder = AccountBuilder::new([1; 32])
        .with_component(MockFaucetComponent)
        .with_component(MockAccountComponent::with_empty_slots())
        .with_assets(initial_assets);
    let faucet =
        builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)?;
    let asset = make_asset(faucet.id());
    let chain = builder.build()?;

    let tx_script = format!(
        r#"
        use mock::faucet as mock_faucet
        use mock::account as mock_account

        @transaction_script
        pub proc main
            # mint asset
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            call.mock_faucet::mint
            # => []

            # add the asset to the account vault for asset preservation AFTER the mint to ensure
            # mint requests the asset witness
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            call.mock_account::add_asset
            # => []

            # truncate the stack
            dropw dropw dropw dropw
        end
        "#,
        ASSET_ID = asset.to_id_word(),
        ASSET_VALUE = asset.to_value_word(),
    );

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(tx_script)?;
    chain.build_transaction(faucet).tx_script(tx_script).build()?.execute().await?;

    Ok(())
}

#[tokio::test]
async fn test_mint_non_fungible_asset_fails_inconsistent_faucet_id() -> anyhow::Result<()> {
    let mock_tx =
        TestTransactionBuilder::with_non_fungible_faucet(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1)
            .build()?;
    let non_fungible_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let code = format!(
        "
        use miden::tx_kernel_core::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{asset_value}
            push.{asset_id}
            call.faucet::mint
        end
        ",
        asset_id = non_fungible_asset.to_id_word(),
        asset_value = non_fungible_asset.to_value_word(),
    );

    let exec_output = mock_tx.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_FAUCET_IS_NOT_ASSET_ORIGIN);
    Ok(())
}

/// Tests that minting a non-fungible asset on a non-faucet account fails.
#[tokio::test]
async fn mint_non_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;
    let asset = FungibleAsset::mock(50);

    let code = format!(
        "
      use mock::faucet

      @transaction_script
      pub proc main
          push.{ASSET_VALUE}
          push.{ASSET_ID}
          call.faucet::mint
      end
      ",
        ASSET_ID = asset.to_id_word(),
        ASSET_VALUE = asset.to_value_word(),
    );
    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(code)?;

    let result = TestTransactionBuilder::new(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_FAUCET_IS_NOT_ASSET_ORIGIN);

    Ok(())
}

/// Tests minting a fungible asset with callbacks enabled.
#[tokio::test]
async fn test_mint_fungible_asset_with_callbacks_enabled() -> anyhow::Result<()> {
    // Use a faucet ID with callbacks enabled.
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_WITH_CALLBACKS).unwrap();
    let asset = FungibleAsset::new(faucet_id, FUNGIBLE_ASSET_AMOUNT)?;
    let asset_id = AssetId::new(AssetClass::default(), faucet_id, AssetComposition::Fungible)?;

    let code = format!(
        r#"
        use mock::faucet as mock_faucet
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction

            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_ID}
            call.mock_faucet::mint

            dropw dropw
        end
        "#,
        FUNGIBLE_ASSET_ID = asset_id.to_word(),
        FUNGIBLE_ASSET_VALUE = asset.to_value_word(),
    );

    TestTransactionBuilder::with_fungible_faucet(faucet_id.into())
        .build()?
        .execute_code(&code)
        .await?;

    Ok(())
}

// FUNGIBLE FAUCET BURN TESTS
// ================================================================================================

/// Tests that burning a fungible asset on a non-faucet account fails.
#[tokio::test]
async fn burn_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;
    let asset = FungibleAsset::mock(50);

    let code = format!(
        "
      use mock::faucet

      @transaction_script
      pub proc main
          push.{FUNGIBLE_ASSET_VALUE}
          push.{FUNGIBLE_ASSET_ID}
          call.faucet::burn
      end
      ",
        FUNGIBLE_ASSET_VALUE = asset.to_value_word(),
        FUNGIBLE_ASSET_ID = asset.to_id_word(),
    );
    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(code)?;

    let result = TestTransactionBuilder::new(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_FAUCET_IS_NOT_ASSET_ORIGIN);

    Ok(())
}

#[tokio::test]
async fn test_burn_fungible_asset_inconsistent_faucet_id() -> anyhow::Result<()> {
    let mock_tx =
        TestTransactionBuilder::with_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).build()?;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();
    let fungible_asset = FungibleAsset::new(faucet_id, FUNGIBLE_ASSET_AMOUNT)?;

    let code = format!(
        "
        use miden::tx_kernel_core::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_ID}
            call.faucet::burn
        end
        ",
        FUNGIBLE_ASSET_VALUE = fungible_asset.to_value_word(),
        FUNGIBLE_ASSET_ID = fungible_asset.to_id_word(),
    );

    let exec_output = mock_tx.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_FAUCET_IS_NOT_ASSET_ORIGIN);
    Ok(())
}

#[tokio::test]
async fn test_burn_fungible_asset_insufficient_input_amount() -> anyhow::Result<()> {
    let mock_tx = TestTransactionBuilder::with_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)
        .build()?;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();
    let fungible_asset = FungibleAsset::new(faucet_id, CONSUMED_ASSET_1_AMOUNT + 1)?;

    let code = format!(
        "
        use miden::tx_kernel_core::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_ID}
            call.faucet::burn
        end
        ",
        FUNGIBLE_ASSET_VALUE = fungible_asset.to_value_word(),
        FUNGIBLE_ASSET_ID = fungible_asset.to_id_word(),
    );

    let exec_output = mock_tx.execute_code(&code).await;

    assert_execution_error!(
        exec_output,
        ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW
    );
    Ok(())
}

// NON-FUNGIBLE FAUCET BURN TESTS
// ================================================================================================

/// Tests burning succeeds in the tx kernel memory context (to assert input vault conditions).
#[rstest]
#[tokio::test]
async fn test_burn_asset_succeeds_in_tx_kernel(
    #[values(BurnAssetType::Fungible, BurnAssetType::NonFungible)] asset_type: BurnAssetType,
    #[values(BurnAssetSource::InputNote, BurnAssetSource::FaucetVault)]
    asset_source: BurnAssetSource,
) -> anyhow::Result<()> {
    let (chain, faucet, asset, note) = setup_burn_chain(asset_type, asset_source)?;

    let code = format!(
        r#"
        use miden::tx_kernel_core::asset_vault
        use miden::tx_kernel_core::prologue
        use mock::faucet as mock_faucet

        begin
            exec.prologue::prepare_transaction

            # burn the non-fungible asset
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            call.mock_faucet::burn
            dropw

            # assert the input vault has been updated and does not have the burnt asset
            push.{INPUT_VAULT_ROOT_PTR}
            push.{ASSET_ID}
            exec.asset_vault::get_asset
            # the returned word should be empty, indicating the asset is absent
            padw assert_eqw.err="input vault should not contain burned asset"

            dropw
        end
        "#,
        ASSET_ID = asset.to_id_word(),
        ASSET_VALUE = asset.to_value_word(),
    );

    chain
        .build_transaction(faucet)
        .authenticated_input_notes(note.map(|note| note.id()))
        .build()?
        .execute_code(&code)
        .await?;

    Ok(())
}

/// Tests burning succeeds in a real transaction.
#[rstest]
#[tokio::test]
async fn test_burn_asset_succeeds(
    #[values(BurnAssetType::Fungible, BurnAssetType::NonFungible)] asset_type: BurnAssetType,
    #[values(BurnAssetSource::InputNote, BurnAssetSource::FaucetVault)]
    asset_source: BurnAssetSource,
) -> anyhow::Result<()> {
    let (chain, faucet, asset, note) = setup_burn_chain(asset_type, asset_source)?;

    let tx_script = format!(
        r#"
        use mock::faucet as mock_faucet
        use mock::account as mock_account

        @transaction_script
        pub proc main
            # burn the non-fungible asset
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            call.mock_faucet::burn
            dropw
            # => []

            # remove the asset from the account vault AFTER the burn to ensure burn requests the
            # asset witness
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            call.mock_account::remove_asset
            # => []

            # the final asset value should be empty indicating the asset was fully removed
            padw assert_eqw.err="input vault should not contain burned asset"
            # => []

            dropw dropw
        end
        "#,
        ASSET_ID = asset.to_id_word(),
        ASSET_VALUE = asset.to_value_word(),
    );

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(tx_script)?;

    chain
        .build_transaction(faucet)
        .authenticated_input_notes(note.map(|note| note.id()))
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_burn_non_fungible_asset_fails_does_not_exist() -> anyhow::Result<()> {
    let mock_tx =
        TestTransactionBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;

    let non_fungible_asset_burnt = NonFungibleAsset::mock(&[1, 2, 3]);

    let code = format!(
        "
        use miden::tx_kernel_core::prologue
        use mock::faucet

        begin
            # burn asset
            exec.prologue::prepare_transaction
            push.{NON_FUNGIBLE_ASSET_VALUE}
            push.{NON_FUNGIBLE_ASSET_ID}
            call.faucet::burn
        end
        ",
        NON_FUNGIBLE_ASSET_VALUE = non_fungible_asset_burnt.to_value_word(),
        NON_FUNGIBLE_ASSET_ID = non_fungible_asset_burnt.to_id_word(),
    );

    let exec_output = mock_tx.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_VAULT_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND);
    Ok(())
}

/// Tests that burning a non-fungible asset on a non-faucet account fails.
#[tokio::test]
async fn burn_non_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;
    let asset = FungibleAsset::mock(50);

    let code = format!(
        "
      use mock::faucet

      @transaction_script
      pub proc main
          push.{ASSET_VALUE}
          push.{ASSET_ID}
          call.faucet::burn
      end
      ",
        ASSET_VALUE = asset.to_value_word(),
        ASSET_ID = asset.to_id_word(),
    );
    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(code)?;

    let result = TestTransactionBuilder::new(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_FAUCET_IS_NOT_ASSET_ORIGIN);

    Ok(())
}

#[tokio::test]
async fn test_burn_non_fungible_asset_fails_inconsistent_faucet_id() -> anyhow::Result<()> {
    let non_fungible_asset_burnt = NonFungibleAsset::mock(&[1, 2, 3]);

    // Run code from a different non-fungible asset issuer
    let mock_tx =
        TestTransactionBuilder::with_non_fungible_faucet(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1)
            .build()?;

    let code = format!(
        "
        use miden::tx_kernel_core::prologue
        use mock::faucet

        begin
            # burn asset
            exec.prologue::prepare_transaction
            push.{NON_FUNGIBLE_ASSET_VALUE}
            push.{NON_FUNGIBLE_ASSET_ID}
            call.faucet::burn
        end
        ",
        NON_FUNGIBLE_ASSET_VALUE = non_fungible_asset_burnt.to_value_word(),
        NON_FUNGIBLE_ASSET_ID = non_fungible_asset_burnt.to_id_word(),
    );

    let exec_output = mock_tx.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_FAUCET_IS_NOT_ASSET_ORIGIN);
    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// The type of the asset to be burned.
#[derive(Debug, Clone, Copy)]
enum BurnAssetType {
    Fungible,
    NonFungible,
}

impl BurnAssetType {
    /// Returns an asset of this type issued by the given faucet.
    fn asset(self, faucet_id: AccountId) -> anyhow::Result<Asset> {
        match self {
            BurnAssetType::Fungible => {
                Ok(FungibleAsset::new(faucet_id, FUNGIBLE_ASSET_AMOUNT)?.into())
            },
            BurnAssetType::NonFungible => {
                Ok(NonFungibleAsset::new(&NonFungibleAssetDetails::new(faucet_id, vec![42])).into())
            },
        }
    }
}

/// The way in which the asset to be burned is made available to the transaction.
///
/// An asset can only be burned if it exists, so it must either be carried by an input note or be
/// held in the faucet's vault.
#[derive(Debug, Clone, Copy)]
enum BurnAssetSource {
    InputNote,
    FaucetVault,
}

/// The authentication method of the mock faucet used in the burn tests.
const BURN_FAUCET_AUTH: Auth = Auth::IncrNonce;

/// Returns a builder for the mock faucet used in the burn tests.
fn mock_faucet_builder() -> AccountBuilder {
    AccountBuilder::new([1; 32])
        .with_component(MockFaucetComponent)
        .with_component(MockAccountComponent::with_empty_slots())
}

/// Builds a chain containing the mock faucet with an asset of the given type made available to a
/// transaction against that faucet through the given source, so it can be burned.
///
/// Returns the chain, the faucet account, the asset and, if the asset comes from an input note,
/// that note.
fn setup_burn_chain(
    asset_type: BurnAssetType,
    asset_source: BurnAssetSource,
) -> anyhow::Result<(MockChain, Account, Asset, Option<Note>)> {
    let (auth_components, _) = BURN_FAUCET_AUTH.build_components();

    // The asset names the faucet as its origin, but the faucet may have to hold that asset in its
    // vault. Since the ID of an existing account does not depend on its vault, it can be taken from
    // an asset-less build of the same faucet.
    let faucet_id = mock_faucet_builder().with_components(auth_components).build_existing()?.id();
    let asset = asset_type.asset(faucet_id)?;

    let mut chain_builder = MockChain::builder();
    let mut faucet_builder = mock_faucet_builder();
    let mut note = None;

    match asset_source {
        BurnAssetSource::InputNote => {
            note = Some(chain_builder.add_p2any_note(
                AccountId::try_from(ACCOUNT_ID_SENDER)?,
                NoteType::Public,
                [asset],
            )?);
        },
        BurnAssetSource::FaucetVault => {
            faucet_builder = faucet_builder.with_assets([asset]);
        },
    }

    let faucet = chain_builder.add_account_from_builder(
        BURN_FAUCET_AUTH,
        faucet_builder,
        AccountState::Exists,
    )?;

    Ok((chain_builder.build()?, faucet, asset, note))
}

/// Creates a regular account that exposes the faucet mint and burn procedures.
///
/// This is used to test that calling these procedures fails as expected.
fn setup_non_faucet_account() -> anyhow::Result<Account> {
    use miden_protocol::account::component::AccountComponentMetadata;

    // Build a custom non-faucet account that (invalidly) exposes faucet procedures.
    let faucet_code = CodeBuilder::with_mock_packages_with_source_manager(Arc::new(
        DefaultSourceManager::default(),
    ))
    .compile_component_code(
        "test::non_faucet_component",
        "use miden::protocol::faucet

         @account_procedure
         pub proc mint
             exec.faucet::mint
         end

         @account_procedure
         pub proc burn
             exec.faucet::burn
         end",
    )?;
    let metadata = AccountComponentMetadata::new("test::non_faucet_component");
    let faucet_component = AccountComponent::new(faucet_code, vec![], metadata)?;
    Ok(AccountBuilder::new([4; 32])
        .with_component(NoopAuthComponent)
        .with_component(faucet_component)
        .build_existing()?)
}
