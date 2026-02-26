//! Integration tests for the Metadata Extension component.

extern crate alloc;

use alloc::sync::Arc;

use miden_processor::crypto::RpoRandomCoin;
use miden_protocol::account::{
    AccountBuilder,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::NoAuth;
use miden_standards::account::faucets::TokenName;
use miden_standards::account::metadata::{
    DESCRIPTION_DATA_KEY,
    FieldBytesError,
    Info,
    NAME_UTF8_MAX_BYTES,
    config_slot,
    field_from_bytes,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_DESCRIPTION_NOT_MUTABLE,
    ERR_MAX_SUPPLY_IMMUTABLE,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, TransactionContextBuilder, assert_transaction_executor_error};

/// Tests that the metadata extension can store and retrieve name via MASM.
#[tokio::test]
async fn metadata_info_get_name_from_masm() -> anyhow::Result<()> {
    let name = [Word::from([1u32, 2, 3, 4]), Word::from([5u32, 6, 7, 8])];

    let extension = Info::new().with_name(name);

    let account = AccountBuilder::new([1u8; 32])
        .with_auth_component(NoAuth)
        .with_component(extension)
        .build()?;

    // MASM script to read name and verify values
    let tx_script = format!(
        r#"
        begin
            # Get name (returns [NAME_CHUNK_0, NAME_CHUNK_1, pad(8)])
            call.::miden::standards::metadata::fungible::get_name
            # => [NAME_CHUNK_0, NAME_CHUNK_1, pad(8)]

            # Verify chunk 0 (on top)
            push.{expected_name_0}
            assert_eqw.err="name chunk 0 does not match"
            # => [NAME_CHUNK_1, pad(12)]

            # Verify chunk 1
            push.{expected_name_1}
            assert_eqw.err="name chunk 1 does not match"
            # => [pad(16)]
        end
        "#,
        expected_name_0 = name[0],
        expected_name_1 = name[1],
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Tests that reading zero-valued name returns empty words.
#[tokio::test]
async fn metadata_info_get_name_zeros_returns_empty() -> anyhow::Result<()> {
    // Create extension with zero-valued name (slots exist, but contain zeros)
    let name = [Word::default(), Word::default()];
    let extension = Info::new().with_name(name);

    let account = AccountBuilder::new([1u8; 32])
        .with_auth_component(NoAuth)
        .with_component(extension)
        .build()?;

    let tx_script = r#"
        begin
            call.::miden::standards::metadata::fungible::get_name
            # => [NAME_CHUNK_0, NAME_CHUNK_1, pad(8)]
            padw assert_eqw.err="name chunk 0 should be empty"
            padw assert_eqw.err="name chunk 1 should be empty"
        end
        "#
    .to_string();

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Tests that get_description (first word of 6) can be read via MASM.
#[tokio::test]
async fn metadata_info_get_description_from_masm() -> anyhow::Result<()> {
    let description = [
        Word::from([10u32, 11, 12, 13]),
        Word::from([14u32, 15, 16, 17]),
        Word::from([18u32, 19, 20, 21]),
        Word::from([22u32, 23, 24, 25]),
        Word::from([26u32, 27, 28, 29]),
        Word::from([30u32, 31, 32, 33]),
    ];

    let extension = Info::new().with_description(description, 1);

    let account = AccountBuilder::new([1u8; 32])
        .with_auth_component(NoAuth)
        .with_component(extension)
        .build()?;

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_description
            # => [DESCRIPTION_0, pad(12)]

            push.{expected_0}
            assert_eqw.err="description_0 does not match"
        end
        "#,
        expected_0 = description[0],
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Tests that the metadata extension works alongside a fungible faucet.
#[test]
fn metadata_info_with_faucet_storage() {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let name = [Word::from([111u32, 222, 333, 444]), Word::from([555u32, 666, 777, 888])];
    let description = [
        Word::from([10u32, 20, 30, 40]),
        Word::from([50u32, 60, 70, 80]),
        Word::from([90u32, 100, 110, 120]),
        Word::from([130u32, 140, 150, 160]),
        Word::from([170u32, 180, 190, 200]),
        Word::from([210u32, 220, 230, 240]),
    ];

    let faucet = BasicFungibleFaucet::new(
        "TST".try_into().unwrap(),
        8,                    // decimals
        Felt::new(1_000_000), // max_supply
        TokenName::try_from("TST").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();

    let extension = Info::new().with_name(name).with_description(description, 1);

    let account = AccountBuilder::new([1u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .with_component(extension)
        .build()
        .unwrap();

    // Verify faucet metadata is intact (Word layout: [token_supply, max_supply, decimals, symbol])
    let faucet_metadata = account.storage().get_item(BasicFungibleFaucet::metadata_slot()).unwrap();
    assert_eq!(faucet_metadata[0], Felt::new(0)); // token_supply
    assert_eq!(faucet_metadata[1], Felt::new(1_000_000)); // max_supply
    assert_eq!(faucet_metadata[2], Felt::new(8)); // decimals

    // Verify name
    let name_0 = account.storage().get_item(Info::name_chunk_0_slot()).unwrap();
    let name_1 = account.storage().get_item(Info::name_chunk_1_slot()).unwrap();
    assert_eq!(name_0, name[0]);
    assert_eq!(name_1, name[1]);

    // Verify description
    for (i, expected) in description.iter().enumerate() {
        let chunk = account.storage().get_item(Info::description_slot(i)).unwrap();
        assert_eq!(chunk, *expected);
    }
}

/// Tests that a name at the maximum allowed length (32 bytes, 2 slots) is accepted.
#[test]
fn name_32_bytes_accepted() {
    let max_name = "a".repeat(NAME_UTF8_MAX_BYTES);
    let extension = Info::new().with_name_utf8(&max_name).unwrap();
    let account = AccountBuilder::new([1u8; 32])
        .with_auth_component(NoAuth)
        .with_component(extension)
        .build()
        .unwrap();
    let name_0 = account.storage().get_item(Info::name_chunk_0_slot()).unwrap();
    let name_1 = account.storage().get_item(Info::name_chunk_1_slot()).unwrap();
    let decoded = miden_standards::account::metadata::name_to_utf8(&[name_0, name_1]).unwrap();
    assert_eq!(decoded, max_name);
}

/// Tests that a name longer than the maximum (33 bytes) is rejected.
#[test]
fn name_33_bytes_rejected() {
    let too_long = "a".repeat(33);
    let result = Info::new().with_name_utf8(&too_long);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(miden_standards::account::metadata::NameUtf8Error::TooLong(33))
    ));
}

/// Tests that description at full capacity (6 Words) is supported.
#[test]
fn description_6_words_full_capacity() {
    let description = [
        Word::from([1u32, 2, 3, 4]),
        Word::from([5u32, 6, 7, 8]),
        Word::from([9u32, 10, 11, 12]),
        Word::from([13u32, 14, 15, 16]),
        Word::from([17u32, 18, 19, 20]),
        Word::from([21u32, 22, 23, 24]),
    ];
    let extension = Info::new().with_description(description, 1);
    let account = AccountBuilder::new([1u8; 32])
        .with_auth_component(NoAuth)
        .with_component(extension)
        .build()
        .unwrap();
    for (i, expected) in description.iter().enumerate() {
        let chunk = account.storage().get_item(Info::description_slot(i)).unwrap();
        assert_eq!(chunk, *expected);
    }
}

/// Tests that field longer than 192 bytes (193 bytes) is rejected.
#[test]
fn field_193_bytes_rejected() {
    let result = field_from_bytes(&[0u8; 193]);
    assert!(result.is_err());
    assert!(matches!(result, Err(FieldBytesError::TooLong(193))));
}

/// Tests that BasicFungibleFaucet with Info component (name/description) works correctly.
#[test]
fn faucet_with_integrated_metadata() {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let name = [Word::from([11u32, 22, 33, 44]), Word::from([55u32, 66, 77, 88])];
    let description = [
        Word::from([1u32, 2, 3, 4]),
        Word::from([5u32, 6, 7, 8]),
        Word::from([9u32, 10, 11, 12]),
        Word::from([13u32, 14, 15, 16]),
        Word::from([17u32, 18, 19, 20]),
        Word::from([21u32, 22, 23, 24]),
    ];

    let faucet = BasicFungibleFaucet::new(
        "INT".try_into().unwrap(),
        6,                  // decimals
        Felt::new(500_000), // max_supply
        TokenName::try_from("INT").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();
    let extension = Info::new().with_name(name).with_description(description, 1);

    let account = AccountBuilder::new([2u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .with_component(extension)
        .build()
        .unwrap();

    // Verify faucet metadata is intact (Word layout: [token_supply, max_supply, decimals, symbol])
    let faucet_metadata = account.storage().get_item(BasicFungibleFaucet::metadata_slot()).unwrap();
    assert_eq!(faucet_metadata[0], Felt::new(0)); // token_supply
    assert_eq!(faucet_metadata[1], Felt::new(500_000)); // max_supply
    assert_eq!(faucet_metadata[2], Felt::new(6)); // decimals

    // Verify name
    let name_0 = account.storage().get_item(Info::name_chunk_0_slot()).unwrap();
    let name_1 = account.storage().get_item(Info::name_chunk_1_slot()).unwrap();
    assert_eq!(name_0, name[0]);
    assert_eq!(name_1, name[1]);

    // Verify description
    for (i, expected) in description.iter().enumerate() {
        let chunk = account.storage().get_item(Info::description_slot(i)).unwrap();
        assert_eq!(chunk, *expected);
    }

    // Verify the faucet can be recovered from the account (metadata only; name/desc are in Info)
    let recovered_faucet = BasicFungibleFaucet::try_from(&account).unwrap();
    assert_eq!(recovered_faucet.max_supply(), Felt::new(500_000));
    assert_eq!(recovered_faucet.decimals(), 6);
}

/// Tests initializing a fungible faucet with maximum-length name and full description.
#[test]
fn faucet_initialized_with_max_name_and_full_description() {
    use miden_protocol::account::AccountStorageMode;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let max_name = "0".repeat(NAME_UTF8_MAX_BYTES);
    let description = [
        Word::from([101u32, 102, 103, 104]),
        Word::from([105u32, 106, 107, 108]),
        Word::from([109u32, 110, 111, 112]),
        Word::from([113u32, 114, 115, 116]),
        Word::from([117u32, 118, 119, 120]),
        Word::from([121u32, 122, 123, 124]),
    ];

    let faucet = BasicFungibleFaucet::new(
        "MAX".try_into().unwrap(),
        6,
        Felt::new(1_000_000),
        TokenName::try_from("MAX").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();
    let extension =
        Info::new().with_name_utf8(&max_name).unwrap().with_description(description, 1);

    let account = AccountBuilder::new([5u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .with_component(extension)
        .build()
        .unwrap();

    let name_words = miden_standards::account::metadata::name_from_utf8(&max_name).unwrap();
    let name_0 = account.storage().get_item(Info::name_chunk_0_slot()).unwrap();
    let name_1 = account.storage().get_item(Info::name_chunk_1_slot()).unwrap();
    assert_eq!(name_0, name_words[0]);
    assert_eq!(name_1, name_words[1]);
    for (i, expected) in description.iter().enumerate() {
        let chunk = account.storage().get_item(Info::description_slot(i)).unwrap();
        assert_eq!(chunk, *expected);
    }
    let faucet_metadata = account.storage().get_item(BasicFungibleFaucet::metadata_slot()).unwrap();
    assert_eq!(faucet_metadata[1], Felt::new(1_000_000));
}

/// Tests initializing a network fungible faucet with max name and full description.
#[test]
fn network_faucet_initialized_with_max_name_and_full_description() {
    use miden_protocol::account::AccountStorageMode;
    use miden_standards::account::faucets::NetworkFungibleFaucet;

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let max_name = "a".repeat(NAME_UTF8_MAX_BYTES);
    let description = [
        Word::from([201u32, 202, 203, 204]),
        Word::from([205u32, 206, 207, 208]),
        Word::from([209u32, 210, 211, 212]),
        Word::from([213u32, 214, 215, 216]),
        Word::from([217u32, 218, 219, 220]),
        Word::from([221u32, 222, 223, 224]),
    ];

    let network_faucet = NetworkFungibleFaucet::new(
        "NET".try_into().unwrap(),
        6,
        Felt::new(2_000_000),
        owner_account_id,
        TokenName::try_from("NET").unwrap(),
        None,
        None,
        None,
    )
    .unwrap()
    .with_token_supply(Felt::new(0))
    .unwrap();

    let extension =
        Info::new().with_name_utf8(&max_name).unwrap().with_description(description, 1);

    let account = AccountBuilder::new([6u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Network)
        .with_auth_component(NoAuth)
        .with_component(network_faucet)
        .with_component(extension)
        .build()
        .unwrap();

    let name_words = miden_standards::account::metadata::name_from_utf8(&max_name).unwrap();
    let name_0 = account.storage().get_item(Info::name_chunk_0_slot()).unwrap();
    let name_1 = account.storage().get_item(Info::name_chunk_1_slot()).unwrap();
    assert_eq!(name_0, name_words[0]);
    assert_eq!(name_1, name_words[1]);
    for (i, expected) in description.iter().enumerate() {
        let chunk = account.storage().get_item(Info::description_slot(i)).unwrap();
        assert_eq!(chunk, *expected);
    }
    let faucet_metadata =
        account.storage().get_item(NetworkFungibleFaucet::metadata_slot()).unwrap();
    assert_eq!(faucet_metadata[1], Felt::new(2_000_000));
}

/// Tests that a network fungible faucet with description can be read from MASM.
#[tokio::test]
async fn network_faucet_get_name_and_description_from_masm() -> anyhow::Result<()> {
    use miden_protocol::account::AccountStorageMode;
    use miden_standards::account::faucets::NetworkFungibleFaucet;

    let owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let max_name = "b".repeat(NAME_UTF8_MAX_BYTES);
    let name_words = miden_standards::account::metadata::name_from_utf8(&max_name).unwrap();
    let description = [
        Word::from([301u32, 302, 303, 304]),
        Word::from([305u32, 306, 307, 308]),
        Word::from([309u32, 310, 311, 312]),
        Word::from([313u32, 314, 315, 316]),
        Word::from([317u32, 318, 319, 320]),
        Word::from([321u32, 322, 323, 324]),
    ];

    let network_faucet = NetworkFungibleFaucet::new(
        "MAS".try_into().unwrap(),
        6,
        Felt::new(1_000_000),
        owner_account_id,
        TokenName::try_from("MAS").unwrap(),
        None,
        None,
        None,
    )
    .unwrap()
    .with_token_supply(Felt::new(0))
    .unwrap();

    let extension =
        Info::new().with_name_utf8(&max_name).unwrap().with_description(description, 1);

    let account = AccountBuilder::new([7u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Network)
        .with_auth_component(NoAuth)
        .with_component(network_faucet)
        .with_component(extension)
        .build()?;

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_name
            push.{expected_name_0}
            assert_eqw.err="network faucet name chunk 0 does not match"
            push.{expected_name_1}
            assert_eqw.err="network faucet name chunk 1 does not match"

            call.::miden::standards::metadata::fungible::get_description
            # => [DESCRIPTION_0, pad(12)]
            push.{expected_desc_0}
            assert_eqw.err="network faucet description_0 does not match"
        end
        "#,
        expected_name_0 = name_words[0],
        expected_name_1 = name_words[1],
        expected_desc_0 = description[0],
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Isolated test: only get_decimals.
#[tokio::test]
async fn faucet_get_decimals_only() -> anyhow::Result<()> {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_protocol::asset::TokenSymbol;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let token_symbol = TokenSymbol::new("POL").unwrap();
    let decimals: u8 = 8;
    let max_supply = Felt::new(1_000_000);

    let faucet = BasicFungibleFaucet::new(
        token_symbol,
        decimals,
        max_supply,
        TokenName::try_from("POL").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();

    let account = AccountBuilder::new([4u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .build()?;

    let expected_decimals = Felt::from(decimals).as_int();

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_decimals
            push.{expected_decimals}
            assert_eq.err="decimals does not match"
            push.0
            assert_eq.err="clean stack: pad must be 0"
        end
        "#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Isolated test: only get_token_symbol.
#[tokio::test]
async fn faucet_get_token_symbol_only() -> anyhow::Result<()> {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_protocol::asset::TokenSymbol;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let token_symbol = TokenSymbol::new("POL").unwrap();
    let decimals: u8 = 8;
    let max_supply = Felt::new(1_000_000);

    let faucet = BasicFungibleFaucet::new(
        token_symbol,
        decimals,
        max_supply,
        TokenName::try_from("POL").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();

    let account = AccountBuilder::new([4u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .build()?;

    let expected_symbol = Felt::from(token_symbol).as_int();

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_token_symbol
            push.{expected_symbol}
            assert_eq.err="token_symbol does not match"
            push.0
            assert_eq.err="clean stack: pad must be 0"
        end
        "#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Isolated test: only get_token_supply.
#[tokio::test]
async fn faucet_get_token_supply_only() -> anyhow::Result<()> {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_protocol::asset::TokenSymbol;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let token_symbol = TokenSymbol::new("POL").unwrap();
    let decimals: u8 = 8;
    let max_supply = Felt::new(1_000_000);
    let token_supply = Felt::new(0); // initial supply

    let faucet = BasicFungibleFaucet::new(
        token_symbol,
        decimals,
        max_supply,
        TokenName::try_from("POL").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();

    let account = AccountBuilder::new([4u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .build()?;

    let expected_token_supply = token_supply.as_int();

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_token_supply
            push.{expected_token_supply}
            assert_eq.err="token_supply does not match"
            push.0
            assert_eq.err="clean stack: pad must be 0"
        end
        "#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Isolated test: only get_token_metadata (full word).
#[tokio::test]
async fn faucet_get_token_metadata_only() -> anyhow::Result<()> {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_protocol::asset::TokenSymbol;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let token_symbol = TokenSymbol::new("POL").unwrap();
    let decimals: u8 = 8;
    let max_supply = Felt::new(1_000_000);

    let faucet = BasicFungibleFaucet::new(
        token_symbol,
        decimals,
        max_supply,
        TokenName::try_from("POL").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();

    let account = AccountBuilder::new([4u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .build()?;

    let expected_symbol = Felt::from(token_symbol).as_int();
    let expected_decimals = Felt::from(decimals).as_int();
    let expected_max_supply = max_supply.as_int();
    let expected_token_supply = 0u64;

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_token_metadata
            # => [token_symbol, decimals, max_supply, token_supply, pad(12)]
            push.{expected_symbol} assert_eq.err="token_symbol does not match"
            push.{expected_decimals} assert_eq.err="decimals does not match"
            push.{expected_max_supply} assert_eq.err="max_supply does not match"
            push.{expected_token_supply} assert_eq.err="token_supply does not match"
        end
        "#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Isolated test: only get_name.
#[tokio::test]
async fn metadata_get_name_only() -> anyhow::Result<()> {
    let name = [Word::from([1u32, 2, 3, 4]), Word::from([5u32, 6, 7, 8])];
    let extension = Info::new().with_name(name);

    let account = AccountBuilder::new([1u8; 32])
        .with_auth_component(NoAuth)
        .with_component(extension)
        .build()?;

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_name
            push.{expected_name_0}
            assert_eqw.err="name chunk 0 does not match"
            push.{expected_name_1}
            assert_eqw.err="name chunk 1 does not match"
        end
        "#,
        expected_name_0 = name[0],
        expected_name_1 = name[1],
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Isolated test: only get_description.
#[tokio::test]
async fn metadata_get_description_only() -> anyhow::Result<()> {
    let description = [
        Word::from([10u32, 11, 12, 13]),
        Word::from([14u32, 15, 16, 17]),
        Word::from([18u32, 19, 20, 21]),
        Word::from([22u32, 23, 24, 25]),
        Word::from([26u32, 27, 28, 29]),
        Word::from([30u32, 31, 32, 33]),
    ];
    let extension = Info::new().with_description(description, 1);

    let account = AccountBuilder::new([1u8; 32])
        .with_auth_component(NoAuth)
        .with_component(extension)
        .build()?;

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_description
            # => [DESCRIPTION_0, pad(12)]
            push.{expected_0}
            assert_eqw.err="description_0 does not match"
        end
        "#,
        expected_0 = description[0],
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Isolated test: only get_config.
#[tokio::test]
async fn metadata_get_config_only() -> anyhow::Result<()> {
    let extension = Info::new()
        .with_description([Word::default(); 6], 2) // desc_flag=2 (mutable)
        .with_max_supply_mutable(true);

    let account = AccountBuilder::new([1u8; 32])
        .with_auth_component(NoAuth)
        .with_component(extension)
        .build()?;

    let tx_script = r#"
        begin
            call.::miden::standards::metadata::fungible::get_config
            # => [max_supply_mutable, extlink_flag, logo_flag, desc_flag, pad(12)]
            push.1
            assert_eq.err="max_supply_mutable should be 1"
            push.0
            assert_eq.err="extlink_flag should be 0"
            push.0
            assert_eq.err="logo_flag should be 0"
            push.2
            assert_eq.err="desc_flag should be 2"
        end
        "#;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Isolated test: only get_owner (account must have ownable, e.g. NetworkFungibleFaucet).
#[tokio::test]
async fn metadata_get_owner_only() -> anyhow::Result<()> {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_protocol::asset::TokenSymbol;
    use miden_standards::account::faucets::NetworkFungibleFaucet;

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        miden_protocol::account::AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );
    let token_symbol = TokenSymbol::new("POL").unwrap();
    let decimals: u8 = 8;
    let max_supply = Felt::new(1_000_000);

    let faucet = NetworkFungibleFaucet::new(
        token_symbol,
        decimals,
        max_supply,
        owner_account_id,
        TokenName::try_from("POL").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();

    let account = AccountBuilder::new([4u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .build()?;

    let expected_prefix = owner_account_id.prefix().as_felt().as_int();
    let expected_suffix = owner_account_id.suffix().as_int();

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_owner
            # => [owner_prefix, owner_suffix, pad(14)]
            push.{expected_prefix}
            assert_eq.err="owner prefix does not match"
            push.{expected_suffix}
            assert_eq.err="owner suffix does not match"
            push.0
            assert_eq.err="clean stack: pad must be 0"
        end
        "#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Isolated test: only get_max_supply.
#[tokio::test]
async fn faucet_get_max_supply_only() -> anyhow::Result<()> {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_protocol::asset::TokenSymbol;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let token_symbol = TokenSymbol::new("POL").unwrap();
    let decimals: u8 = 8;
    let max_supply = Felt::new(1_000_000);

    let faucet = BasicFungibleFaucet::new(
        token_symbol,
        decimals,
        max_supply,
        TokenName::try_from("POL").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();

    let account = AccountBuilder::new([4u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .build()?;

    let expected_max_supply = max_supply.as_int();

    let tx_script = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible::get_max_supply
            push.{expected_max_supply}
            assert_eq.err="max_supply does not match"
            push.0
            assert_eq.err="clean stack: pad must be 0"
        end
        "#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Tests that get_decimals and get_token_symbol return the correct individual values from MASM.
#[tokio::test]
async fn faucet_get_decimals_and_symbol_from_masm() -> anyhow::Result<()> {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_protocol::asset::TokenSymbol;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let token_symbol = TokenSymbol::new("POL").unwrap();
    let decimals: u8 = 8;
    let max_supply = Felt::new(1_000_000);

    let faucet = BasicFungibleFaucet::new(
        token_symbol,
        decimals,
        max_supply,
        TokenName::try_from("POL").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();

    let account = AccountBuilder::new([4u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .build()?;

    // Compute expected felt values
    let expected_decimals = Felt::from(decimals).as_int();
    let expected_symbol = Felt::from(token_symbol).as_int();
    let expected_max_supply = max_supply.as_int();

    let tx_script = format!(
        r#"
        begin
            # Test get_decimals
            call.::miden::standards::metadata::fungible::get_decimals
            # => [decimals, pad(15)]
            push.{expected_decimals}
            assert_eq.err="decimals does not match"
            # => [pad(15)]; pad to 16 before next call
            push.0

            # Test get_token_symbol
            call.::miden::standards::metadata::fungible::get_token_symbol
            # => [token_symbol, pad(15)]
            push.{expected_symbol}
            assert_eq.err="token_symbol does not match"
            # => [pad(15)]; pad to 16 before next call
            push.0

            # Test get_max_supply (sanity check)
            call.::miden::standards::metadata::fungible::get_max_supply
            # => [max_supply, pad(15)]
            push.{expected_max_supply}
            assert_eq.err="max_supply does not match"
        end
        "#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Tests that BasicFungibleFaucet metadata can be read from MASM using the faucet's procedures.
#[tokio::test]
async fn faucet_metadata_readable_from_masm() -> anyhow::Result<()> {
    use miden_protocol::Felt;
    use miden_protocol::account::AccountStorageMode;
    use miden_standards::account::faucets::BasicFungibleFaucet;

    let name = [Word::from([100u32, 200, 300, 400]), Word::from([500u32, 600, 700, 800])];
    let description = [
        Word::from([1u32, 2, 3, 4]),
        Word::from([5u32, 6, 7, 8]),
        Word::from([9u32, 10, 11, 12]),
        Word::from([13u32, 14, 15, 16]),
        Word::from([17u32, 18, 19, 20]),
        Word::from([21u32, 22, 23, 24]),
    ];

    let faucet = BasicFungibleFaucet::new(
        "MAS".try_into().unwrap(),
        10,                 // decimals
        Felt::new(999_999), // max_supply
        TokenName::try_from("MAS").unwrap(),
        None,
        None,
        None,
    )
    .unwrap();
    let extension = Info::new().with_name(name).with_description(description, 1);

    let account = AccountBuilder::new([3u8; 32])
        .account_type(miden_protocol::account::AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(faucet)
        .with_component(extension)
        .build()?;

    // MASM script to read name and description via the metadata procedures and verify
    let tx_script = format!(
        r#"
        begin
            # Get name and verify
            call.::miden::standards::metadata::fungible::get_name
            # => [NAME_CHUNK_0, NAME_CHUNK_1, pad(8)]
            push.{expected_name_0}
            assert_eqw.err="faucet name chunk 0 does not match"
            push.{expected_name_1}
            assert_eqw.err="faucet name chunk 1 does not match"

            # Get description and verify first chunk
            call.::miden::standards::metadata::fungible::get_description
            # => [DESCRIPTION_0, pad(12)]
            push.{expected_desc_0}
            assert_eqw.err="faucet description_0 does not match"
        end
        "#,
        expected_name_0 = name[0],
        expected_name_1 = name[1],
        expected_desc_0 = description[0],
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

// =================================================================================================
// optional_set_description: mutable flag and verify_owner
// =================================================================================================

/// Builds the advice map value for field setters.
fn field_advice_map_value(field: &[Word; 6]) -> Vec<Felt> {
    let mut value = Vec::with_capacity(24);
    for word in field.iter() {
        value.extend(word.iter());
    }
    value
}

/// When description flag is 1 (immutable), optional_set_description panics.
#[tokio::test]
async fn optional_set_description_immutable_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );
    let description = [
        Word::from([1u32, 2, 3, 4]),
        Word::from([5u32, 6, 7, 8]),
        Word::from([9u32, 10, 11, 12]),
        Word::from([13u32, 14, 15, 16]),
        Word::from([17u32, 18, 19, 20]),
        Word::from([21u32, 22, 23, 24]),
    ];
    let faucet = builder.add_existing_network_faucet_with_metadata_info(
        "DSC",
        1000,
        owner_account_id,
        Some(0),
        false,
        Some((description, 1)), // flag=1 → immutable
        None,
        None,
    )?;
    let mock_chain = builder.build()?;

    let new_desc = [
        Word::from([100u32, 101, 102, 103]),
        Word::from([104u32, 105, 106, 107]),
        Word::from([108u32, 109, 110, 111]),
        Word::from([112u32, 113, 114, 115]),
        Word::from([116u32, 117, 118, 119]),
        Word::from([120u32, 121, 122, 123]),
    ];

    let tx_script = r#"
        begin
            call.::miden::standards::metadata::fungible::optional_set_description
        end
    "#;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .extend_advice_map([(DESCRIPTION_DATA_KEY, field_advice_map_value(&new_desc))])
        .with_source_manager(source_manager)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, ERR_DESCRIPTION_NOT_MUTABLE);

    Ok(())
}

/// When description flag is 2 and note sender is the owner, optional_set_description succeeds.
#[tokio::test]
async fn optional_set_description_mutable_owner_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let initial_desc = [
        Word::from([1u32, 2, 3, 4]),
        Word::from([5u32, 6, 7, 8]),
        Word::from([9u32, 10, 11, 12]),
        Word::from([13u32, 14, 15, 16]),
        Word::from([17u32, 18, 19, 20]),
        Word::from([21u32, 22, 23, 24]),
    ];
    let new_desc = [
        Word::from([100u32, 101, 102, 103]),
        Word::from([104u32, 105, 106, 107]),
        Word::from([108u32, 109, 110, 111]),
        Word::from([112u32, 113, 114, 115]),
        Word::from([116u32, 117, 118, 119]),
        Word::from([120u32, 121, 122, 123]),
    ];

    let faucet = builder.add_existing_network_faucet_with_metadata_info(
        "DSC",
        1000,
        owner_account_id,
        Some(0),
        false,
        Some((initial_desc, 2)), // flag=2 → mutable
        None,
        None,
    )?;
    let mock_chain = builder.build()?;

    let committed = mock_chain.committed_account(faucet.id())?;
    let config_word = committed.storage().get_item(config_slot())?;
    assert_eq!(
        config_word[0],
        Felt::from(2u32),
        "committed account must have desc_flag = 2"
    );

    let set_desc_note_script_code = r#"
        begin
            call.::miden::standards::metadata::fungible::optional_set_description
        end
    "#;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let set_desc_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(set_desc_note_script_code)?;

    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let set_desc_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([7, 8, 9, 10u32]))
        .code(set_desc_note_script_code)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[set_desc_note])?
        .add_note_script(set_desc_note_script)
        .extend_advice_map([(DESCRIPTION_DATA_KEY, field_advice_map_value(&new_desc))])
        .with_source_manager(source_manager)
        .build()?;

    let executed = tx_context.execute().await?;
    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_delta(executed.account_delta())?;

    for (i, expected) in new_desc.iter().enumerate() {
        let chunk = updated_faucet.storage().get_item(Info::description_slot(i))?;
        assert_eq!(chunk, *expected, "description_{i} should be updated");
    }

    Ok(())
}

/// When description flag is 2 but note sender is not the owner, optional_set_description panics.
#[tokio::test]
async fn optional_set_description_mutable_non_owner_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );
    let non_owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let initial_desc = [
        Word::from([1u32, 2, 3, 4]),
        Word::from([5u32, 6, 7, 8]),
        Word::from([9u32, 10, 11, 12]),
        Word::from([13u32, 14, 15, 16]),
        Word::from([17u32, 18, 19, 20]),
        Word::from([21u32, 22, 23, 24]),
    ];
    let new_desc = [
        Word::from([100u32, 101, 102, 103]),
        Word::from([104u32, 105, 106, 107]),
        Word::from([108u32, 109, 110, 111]),
        Word::from([112u32, 113, 114, 115]),
        Word::from([116u32, 117, 118, 119]),
        Word::from([120u32, 121, 122, 123]),
    ];

    let faucet = builder.add_existing_network_faucet_with_metadata_info(
        "DSC",
        1000,
        owner_account_id,
        Some(0),
        false,
        Some((initial_desc, 2)),
        None,
        None,
    )?;
    let mock_chain = builder.build()?;

    let set_desc_note_script_code = r#"
        begin
            call.::miden::standards::metadata::fungible::optional_set_description
        end
    "#;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let set_desc_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(set_desc_note_script_code)?;

    let mut rng = RpoRandomCoin::new([Felt::from(99u32); 4].into());
    let set_desc_note = NoteBuilder::new(non_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([11, 12, 13, 14u32]))
        .code(set_desc_note_script_code)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[set_desc_note])?
        .add_note_script(set_desc_note_script)
        .extend_advice_map([(DESCRIPTION_DATA_KEY, field_advice_map_value(&new_desc))])
        .with_source_manager(source_manager)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

// =================================================================================================
// optional_set_max_supply: mutable flag and verify_owner
// =================================================================================================

/// When max_supply_mutable is 0 (immutable), optional_set_max_supply panics.
#[tokio::test]
async fn optional_set_max_supply_immutable_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet_with_metadata_info(
        "MSM",
        1000,
        owner_account_id,
        Some(0),
        false, // max_supply_mutable = false
        None,
        None,
        None,
    )?;
    let mock_chain = builder.build()?;

    let new_max_supply: u64 = 2000;
    let tx_script = format!(
        r#"
        begin
            push.{new_max_supply}
            call.::miden::standards::metadata::fungible::optional_set_max_supply
        end
    "#
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(tx_script)?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, ERR_MAX_SUPPLY_IMMUTABLE);

    Ok(())
}

/// When max_supply_mutable is 1 and note sender is the owner, optional_set_max_supply succeeds.
#[tokio::test]
async fn optional_set_max_supply_mutable_owner_succeeds() -> anyhow::Result<()> {
    use miden_standards::account::faucets::NetworkFungibleFaucet;

    let mut builder = MockChain::builder();
    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let initial_max_supply: u64 = 1000;
    let new_max_supply: u64 = 2000;

    let faucet = builder.add_existing_network_faucet_with_metadata_info(
        "MSM",
        initial_max_supply,
        owner_account_id,
        Some(0),
        true, // max_supply_mutable = true
        None,
        None,
        None,
    )?;
    let mock_chain = builder.build()?;

    let set_max_supply_note_script_code = format!(
        r#"
        begin
            push.{new_max_supply}
            swap drop
            call.::miden::standards::metadata::fungible::optional_set_max_supply
        end
    "#
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let set_max_supply_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(&set_max_supply_note_script_code)?;

    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let set_max_supply_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([20, 21, 22, 23u32]))
        .code(&set_max_supply_note_script_code)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[set_max_supply_note])?
        .add_note_script(set_max_supply_note_script)
        .with_source_manager(source_manager)
        .build()?;

    let executed = tx_context.execute().await?;
    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_delta(executed.account_delta())?;

    // Verify the metadata word: [token_supply, max_supply, decimals, symbol]
    let metadata_word = updated_faucet.storage().get_item(NetworkFungibleFaucet::metadata_slot())?;
    assert_eq!(
        metadata_word[1],
        Felt::new(new_max_supply),
        "max_supply should be updated to {new_max_supply}"
    );
    // token_supply should remain 0
    assert_eq!(metadata_word[0], Felt::new(0), "token_supply should remain unchanged");

    Ok(())
}

/// When max_supply_mutable is 1 but note sender is not the owner, optional_set_max_supply panics.
#[tokio::test]
async fn optional_set_max_supply_mutable_non_owner_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );
    let non_owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet_with_metadata_info(
        "MSM",
        1000,
        owner_account_id,
        Some(0),
        true, // max_supply_mutable = true
        None,
        None,
        None,
    )?;
    let mock_chain = builder.build()?;

    let new_max_supply: u64 = 2000;
    let set_max_supply_note_script_code = format!(
        r#"
        begin
            push.{new_max_supply}
            swap drop
            call.::miden::standards::metadata::fungible::optional_set_max_supply
        end
    "#
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let set_max_supply_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(&set_max_supply_note_script_code)?;

    let mut rng = RpoRandomCoin::new([Felt::from(99u32); 4].into());
    let set_max_supply_note = NoteBuilder::new(non_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([30, 31, 32, 33u32]))
        .code(&set_max_supply_note_script_code)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[set_max_supply_note])?
        .add_note_script(set_max_supply_note_script)
        .with_source_manager(source_manager)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

// =================================================================================================
// is_max_supply_mutable: getter test
// =================================================================================================

/// Tests that all is_*_mutable procedures correctly read the config flags.
/// Each field is tested with flag=2 (mutable, expects 1) and flag=1 (immutable, expects 0).
/// Also tests is_max_supply_mutable with true (expects 1).
#[tokio::test]
async fn metadata_is_field_mutable_checks() -> anyhow::Result<()> {
    let data = field_from_bytes(b"test").unwrap();

    let cases: Vec<(Info, &str, u8)> = vec![
        (Info::new().with_max_supply_mutable(true), "is_max_supply_mutable", 1),
        (Info::new().with_description(data, 2), "is_description_mutable", 1),
        (Info::new().with_description(data, 1), "is_description_mutable", 0),
        (Info::new().with_logo_uri(data, 2), "is_logo_uri_mutable", 1),
        (Info::new().with_logo_uri(data, 1), "is_logo_uri_mutable", 0),
        (Info::new().with_external_link(data, 2), "is_external_link_mutable", 1),
        (Info::new().with_external_link(data, 1), "is_external_link_mutable", 0),
    ];

    for (info, proc_name, expected) in cases {
        let account = AccountBuilder::new([1u8; 32])
            .with_auth_component(NoAuth)
            .with_component(info)
            .build()?;

        let tx_script = format!(
            "begin
                call.::miden::standards::metadata::fungible::{proc_name}
                push.{expected}
                assert_eq.err=\"{proc_name} returned unexpected value\"
            end"
        );

        let source_manager = Arc::new(DefaultSourceManager::default());
        let tx_script =
            CodeBuilder::with_source_manager(source_manager.clone())
                .compile_tx_script(&tx_script)?;

        let tx_context = TransactionContextBuilder::new(account)
            .tx_script(tx_script)
            .with_source_manager(source_manager)
            .build()?;

        tx_context.execute().await?;
    }

    Ok(())
}
