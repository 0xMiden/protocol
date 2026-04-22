//! Integration tests for the Token Metadata standard (`FungibleTokenMetadata`).

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_crypto::hash::poseidon2::Poseidon2;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
    StorageSlotName,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::TokenSymbol;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Ownable2Step;
use miden_standards::account::auth::NoAuth;
use miden_standards::account::faucets::{BasicFungibleFaucet, NetworkFungibleFaucet};
use miden_standards::account::metadata::{
    Description,
    ExternalLink,
    FungibleTokenMetadata,
    FungibleTokenMetadataBuilder,
    LogoURI,
    TokenMetadata,
    TokenName,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_DESCRIPTION_NOT_MUTABLE,
    ERR_EXTERNAL_LINK_NOT_MUTABLE,
    ERR_LOGO_URI_NOT_MUTABLE,
    ERR_MAX_SUPPLY_NOT_MUTABLE,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::testing::note::NoteBuilder;

use crate::{MockChain, TransactionContextBuilder, assert_transaction_executor_error};

// SHARED HELPERS
// ================================================================================================

/// Builds [`FungibleTokenMetadata`] for tests that use raw word arrays + mutability flags
/// (e.g. from [`description_config`] / [`logo_uri_config`] / [`external_link_config`]).
fn network_faucet_metadata(
    token_symbol: &str,
    max_supply: u64,
    token_supply: Option<u64>,
    max_supply_mutable: bool,
    description: Option<([Word; 7], bool)>,
    logo_uri: Option<([Word; 7], bool)>,
    external_link: Option<([Word; 7], bool)>,
) -> anyhow::Result<FungibleTokenMetadata> {
    let token_supply = token_supply.unwrap_or(0);
    let name = TokenName::new(token_symbol)?;
    let token_symbol = TokenSymbol::new(token_symbol)?;

    let mut builder = FungibleTokenMetadataBuilder::new(name, token_symbol, 10, max_supply)
        .token_supply(token_supply)
        .is_max_supply_mutable(max_supply_mutable);
    if let Some((words, mutable)) = description {
        builder = builder
            .description(Description::try_from_words(&words).expect("valid description words"))
            .is_description_mutable(mutable);
    }
    if let Some((words, mutable)) = logo_uri {
        builder = builder
            .logo_uri(LogoURI::try_from_words(&words).expect("valid logo_uri words"))
            .is_logo_uri_mutable(mutable);
    }
    if let Some((words, mutable)) = external_link {
        builder = builder
            .external_link(ExternalLink::try_from_words(&words).expect("valid external_link words"))
            .is_external_link_mutable(mutable);
    }

    Ok(builder.build()?)
}

fn initial_field_data() -> [Word; 7] {
    [
        Word::from([1u32, 2, 3, 4]),
        Word::from([5u32, 6, 7, 8]),
        Word::from([9u32, 10, 11, 12]),
        Word::from([13u32, 14, 15, 16]),
        Word::from([17u32, 18, 19, 20]),
        Word::from([21u32, 22, 23, 24]),
        Word::from([25u32, 26, 27, 28]),
    ]
}

fn new_field_data() -> [Word; 7] {
    [
        Word::from([100u32, 101, 102, 103]),
        Word::from([104u32, 105, 106, 107]),
        Word::from([108u32, 109, 110, 111]),
        Word::from([112u32, 113, 114, 115]),
        Word::from([116u32, 117, 118, 119]),
        Word::from([120u32, 121, 122, 123]),
        Word::from([124u32, 125, 126, 127]),
    ]
}

fn owner_account_id() -> AccountId {
    AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    )
}

fn non_owner_account_id() -> AccountId {
    AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    )
}

/// Build a minimal faucet metadata (no optional fields).
fn build_faucet_metadata() -> FungibleTokenMetadata {
    FungibleTokenMetadataBuilder::new(
        TokenName::new("T").unwrap(),
        "TST".try_into().unwrap(),
        2,
        1_000u64,
    )
    .build()
    .unwrap()
}

/// Build a standard POL faucet metadata (used by scalar getter tests).
/// Uses "Polygon Token" (13 bytes) so both name word chunks are non-zero.
fn build_pol_faucet_metadata() -> FungibleTokenMetadata {
    FungibleTokenMetadataBuilder::new(
        TokenName::new("Polygon Token").unwrap(),
        TokenSymbol::new("POL").unwrap(),
        8,
        1_000_000u64,
    )
    .build()
    .unwrap()
}

/// Build a basic faucet account with POL metadata.
fn build_pol_faucet_account() -> Account {
    AccountBuilder::new([4u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(build_pol_faucet_metadata())
        .with_component(BasicFungibleFaucet)
        .build()
        .unwrap()
}

/// Flatten `[Word; 7]` into `Vec<Felt>` for advice map values.
fn field_advice_map_value(field: &[Word; 7]) -> Vec<Felt> {
    let mut value = Vec::with_capacity(28);
    for word in field.iter() {
        value.extend(word.iter());
    }
    value
}

/// Compute the Poseidon2 hash of the field data (used as the advice map key).
fn compute_field_hash(data: &[Word; 7]) -> Word {
    let felts = field_advice_map_value(data);
    Poseidon2::hash_elements(&felts)
}

/// Execute a tx script against the given account and assert success.
async fn execute_tx_script(
    account: Account,
    tx_script_code: impl AsRef<str>,
) -> anyhow::Result<()> {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_tx_script(tx_script_code.as_ref())?;
    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;
    tx_context.execute().await?;
    Ok(())
}

// =================================================================================================
// GETTER TESTS – name
// =================================================================================================

#[tokio::test]
async fn get_name_from_masm() -> anyhow::Result<()> {
    let token_name = TokenName::new("test name").unwrap();
    let name = token_name.to_words();

    let metadata =
        FungibleTokenMetadataBuilder::new(token_name, "TST".try_into().unwrap(), 2, 1_000u64)
            .build()
            .unwrap();

    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoAuth)
        .with_component(metadata)
        .with_component(BasicFungibleFaucet)
        .build()?;

    execute_tx_script(
        account,
        format!(
            r#"
            begin
                call.::miden::standards::metadata::fungible_faucet::get_name
                push.{n0}
                assert_eqw.err="name chunk 0 does not match"
                push.{n1}
                assert_eqw.err="name chunk 1 does not match"
            end
            "#,
            n0 = name[0],
            n1 = name[1],
        ),
    )
    .await
}

#[tokio::test]
async fn get_name_zeros_returns_empty() -> anyhow::Result<()> {
    // Build a faucet with an empty name to verify get_name returns zero words.
    let metadata = FungibleTokenMetadataBuilder::new(
        TokenName::new("").expect("empty string is a valid token name"),
        "TST".try_into().unwrap(),
        2,
        1_000u64,
    )
    .build()
    .unwrap();

    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoAuth)
        .with_component(metadata)
        .with_component(BasicFungibleFaucet)
        .build()?;

    execute_tx_script(
        account,
        r#"
        begin
            call.::miden::standards::metadata::fungible_faucet::get_name
            padw assert_eqw.err="name chunk 0 should be empty"
            padw assert_eqw.err="name chunk 1 should be empty"
        end
        "#,
    )
    .await
}

// =================================================================================================
// GETTER TESTS – scalar fields
// =================================================================================================

#[tokio::test]
async fn faucet_get_decimals() -> anyhow::Result<()> {
    let expected = Felt::from(8u8).as_canonical_u64();
    execute_tx_script(
        build_pol_faucet_account(),
        format!(
            r#"
            begin
                call.::miden::standards::metadata::fungible_faucet::get_decimals
                push.{expected} assert_eq.err="decimals does not match"
                push.0 assert_eq.err="clean stack: pad must be 0"
            end
            "#
        ),
    )
    .await
}

#[tokio::test]
async fn faucet_get_token_symbol() -> anyhow::Result<()> {
    let expected = Felt::from(TokenSymbol::new("POL").unwrap()).as_canonical_u64();
    execute_tx_script(
        build_pol_faucet_account(),
        format!(
            r#"
            begin
                call.::miden::standards::metadata::fungible_faucet::get_token_symbol
                push.{expected} assert_eq.err="token_symbol does not match"
                push.0 assert_eq.err="clean stack: pad must be 0"
            end
            "#
        ),
    )
    .await
}

#[tokio::test]
async fn faucet_get_token_supply() -> anyhow::Result<()> {
    execute_tx_script(
        build_pol_faucet_account(),
        r#"
        begin
            call.::miden::standards::metadata::fungible_faucet::get_token_supply
            push.0 assert_eq.err="token_supply does not match"
            push.0 assert_eq.err="clean stack: pad must be 0"
        end
        "#,
    )
    .await
}

#[tokio::test]
async fn faucet_get_max_supply() -> anyhow::Result<()> {
    let expected = Felt::new(1_000_000).as_canonical_u64();
    execute_tx_script(
        build_pol_faucet_account(),
        format!(
            r#"
            begin
                call.::miden::standards::metadata::fungible_faucet::get_max_supply
                push.{expected} assert_eq.err="max_supply does not match"
                push.0 assert_eq.err="clean stack: pad must be 0"
            end
            "#
        ),
    )
    .await
}

#[tokio::test]
async fn faucet_get_token_metadata() -> anyhow::Result<()> {
    let symbol = TokenSymbol::new("POL").unwrap();
    let expected_symbol = Felt::from(symbol).as_canonical_u64();
    let expected_decimals = Felt::from(8u8).as_canonical_u64();
    let expected_max_supply = Felt::new(1_000_000).as_canonical_u64();

    execute_tx_script(
        build_pol_faucet_account(),
        format!(
            r#"
            begin
                call.::miden::standards::metadata::fungible_faucet::get_token_metadata
                push.0 assert_eq.err="token_supply does not match"
                push.{expected_max_supply} assert_eq.err="max_supply does not match"
                push.{expected_decimals} assert_eq.err="decimals does not match"
                push.{expected_symbol} assert_eq.err="token_symbol does not match"
            end
            "#
        ),
    )
    .await
}

#[tokio::test]
async fn faucet_get_decimals_symbol_and_max_supply() -> anyhow::Result<()> {
    let symbol = TokenSymbol::new("POL").unwrap();
    let expected_decimals = Felt::from(8u8).as_canonical_u64();
    let expected_symbol = Felt::from(symbol).as_canonical_u64();
    let expected_max_supply = Felt::new(1_000_000).as_canonical_u64();

    execute_tx_script(
        build_pol_faucet_account(),
        format!(
            r#"
            begin
                call.::miden::standards::metadata::fungible_faucet::get_decimals
                push.{expected_decimals} assert_eq.err="decimals does not match"
                call.::miden::standards::metadata::fungible_faucet::get_token_symbol
                push.{expected_symbol} assert_eq.err="token_symbol does not match"
                call.::miden::standards::metadata::fungible_faucet::get_max_supply
                push.{expected_max_supply} assert_eq.err="max_supply does not match"
            end
            "#
        ),
    )
    .await
}

// =================================================================================================
// GETTER TESTS – mutability config
// =================================================================================================

#[tokio::test]
async fn get_mutability_config() -> anyhow::Result<()> {
    let metadata = FungibleTokenMetadataBuilder::new(
        TokenName::new("T").unwrap(),
        "TST".try_into().unwrap(),
        2,
        1_000u64,
    )
    .description(Description::new("test").unwrap())
    .is_description_mutable(true)
    .is_max_supply_mutable(true)
    .build()
    .unwrap();

    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoAuth)
        .with_component(metadata)
        .with_component(BasicFungibleFaucet)
        .build()?;

    execute_tx_script(
        account,
        r#"
        begin
            call.::miden::standards::metadata::fungible_faucet::get_mutability_config
            push.1 assert_eq.err="desc_mutable should be 1"
            push.0 assert_eq.err="logo_mutable should be 0"
            push.0 assert_eq.err="extlink_mutable should be 0"
            push.1 assert_eq.err="max_supply_mutable should be 1"
        end
        "#,
    )
    .await
}

/// Tests all `is_*_mutable` procedures with flag=0 and flag=1.
#[rstest::rstest]
#[case("is_max_supply_mutable",    build_faucet_metadata().with_max_supply_mutable(true),    1)]
#[case("is_description_mutable",   build_faucet_metadata().with_description_mutable(true),   1)]
#[case("is_description_mutable",   build_faucet_metadata().with_description_mutable(false),  0)]
#[case("is_logo_uri_mutable",      build_faucet_metadata().with_logo_uri_mutable(true),      1)]
#[case("is_logo_uri_mutable",      build_faucet_metadata().with_logo_uri_mutable(false),     0)]
#[case("is_external_link_mutable", build_faucet_metadata().with_external_link_mutable(true), 1)]
#[case("is_external_link_mutable", build_faucet_metadata().with_external_link_mutable(false),0)]
#[tokio::test]
async fn is_field_mutable_checks(
    #[case] proc_name: &str,
    #[case] metadata: FungibleTokenMetadata,
    #[case] expected: u8,
) -> anyhow::Result<()> {
    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoAuth)
        .with_component(metadata)
        .with_component(BasicFungibleFaucet)
        .build()?;

    execute_tx_script(
        account,
        format!(
            "begin
                call.::miden::standards::metadata::fungible_faucet::{proc_name}
                push.{expected}
                assert_eq.err=\"{proc_name} returned unexpected value\"
            end"
        ),
    )
    .await
}

// =================================================================================================
// STORAGE LAYOUT TESTS
// =================================================================================================

#[test]
fn faucet_with_metadata_storage_layout() {
    let token_name = TokenName::new("test faucet name").unwrap();
    let desc_text = "faucet description text for testing";
    let description = Description::new(desc_text).unwrap();

    let metadata =
        FungibleTokenMetadataBuilder::new(token_name, "TST".try_into().unwrap(), 8, 1_000_000u64)
            .description(description)
            .build()
            .unwrap();

    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(NoAuth)
        .with_component(metadata)
        .with_component(BasicFungibleFaucet)
        .build()
        .unwrap();

    // Verify roundtrip via try_from
    let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();
    assert_eq!(restored.token_supply(), Felt::ZERO);
    assert_eq!(restored.max_supply().as_canonical_u64(), 1_000_000);
    assert_eq!(restored.decimals(), 8);
    assert_eq!(restored.description().map(|d| d.as_str()), Some(desc_text));
}

// =================================================================================================
// FAUCET INITIALIZATION – basic + network with max name/description
// =================================================================================================

fn verify_faucet_with_max_name_and_description(
    seed: [u8; 32],
    symbol: &str,
    max_supply: u64,
    storage_mode: AccountStorageMode,
    extra_components: Vec<AccountComponent>,
) {
    let max_name = "a".repeat(TokenName::MAX_BYTES);
    let desc_text = "a".repeat(Description::MAX_BYTES);
    let description = Description::new(&desc_text).unwrap();

    let faucet_metadata = FungibleTokenMetadataBuilder::new(
        TokenName::new(&max_name).unwrap(),
        symbol.try_into().unwrap(),
        6,
        max_supply,
    )
    .description(description)
    .build()
    .unwrap();

    let mut builder = AccountBuilder::new(seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(storage_mode)
        .with_auth_component(NoAuth)
        .with_component(faucet_metadata);

    for comp in extra_components {
        builder = builder.with_component(comp);
    }

    let account = builder.build().unwrap();

    // Verify roundtrip via try_from
    let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();
    assert_eq!(restored.name().as_str(), max_name);
    assert_eq!(restored.description().map(|d| d.as_str()), Some(desc_text.as_str()));
    assert_eq!(restored.max_supply().as_canonical_u64(), max_supply);
}

#[test]
fn basic_faucet_with_max_name_and_full_description() {
    verify_faucet_with_max_name_and_description(
        [5u8; 32],
        "MAX",
        1_000_000,
        AccountStorageMode::Public,
        vec![BasicFungibleFaucet.into()],
    );
}

#[test]
fn network_faucet_with_max_name_and_full_description() {
    verify_faucet_with_max_name_and_description(
        [6u8; 32],
        "NET",
        2_000_000,
        AccountStorageMode::Network,
        vec![NetworkFungibleFaucet.into(), Ownable2Step::new(owner_account_id()).into()],
    );
}

// =================================================================================================
// MASM NAME READBACK – basic + network faucets
// =================================================================================================

// =================================================================================================
// SETTER TESTS – set_description, set_logo_uri, set_external_link (parameterised)
// =================================================================================================

struct FieldSetterFaucetArgs {
    description: Option<([Word; 7], bool)>,
    logo_uri: Option<([Word; 7], bool)>,
    external_link: Option<([Word; 7], bool)>,
}

fn description_config(data: [Word; 7], mutable: bool) -> FieldSetterFaucetArgs {
    FieldSetterFaucetArgs {
        description: Some((data, mutable)),
        logo_uri: None,
        external_link: None,
    }
}

fn logo_uri_config(data: [Word; 7], mutable: bool) -> FieldSetterFaucetArgs {
    FieldSetterFaucetArgs {
        description: None,
        logo_uri: Some((data, mutable)),
        external_link: None,
    }
}

fn external_link_config(data: [Word; 7], mutable: bool) -> FieldSetterFaucetArgs {
    FieldSetterFaucetArgs {
        description: None,
        logo_uri: None,
        external_link: Some((data, mutable)),
    }
}

async fn test_field_setter_immutable_fails(
    proc_name: &str,
    immutable_error: MasmError,
    args: FieldSetterFaucetArgs,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = owner_account_id();

    let metadata = network_faucet_metadata(
        "FLD",
        1000,
        Some(0),
        false,
        args.description,
        args.logo_uri,
        args.external_link,
    )?;
    let faucet = builder.add_existing_network_faucet_with_metadata(owner, metadata)?;
    let mock_chain = builder.build()?;

    let tx_script_code = format!(
        r#"
        begin
            call.::miden::standards::metadata::fungible_faucet::{proc_name}
        end
    "#
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_tx_script(&tx_script_code)?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, immutable_error);

    Ok(())
}

async fn test_field_setter_owner_succeeds(
    proc_name: &str,
    args: FieldSetterFaucetArgs,
    slot_fn: fn(usize) -> &'static StorageSlotName,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = owner_account_id();
    let new_data = new_field_data();

    let metadata = network_faucet_metadata(
        "FLD",
        1000,
        Some(0),
        false,
        args.description,
        args.logo_uri,
        args.external_link,
    )?;
    let faucet = builder.add_existing_network_faucet_with_metadata(owner, metadata)?;
    let mock_chain = builder.build()?;

    let hash = compute_field_hash(&new_data);

    // Push hash as a word so advice map key matches; dropw after call so stack depth is 16
    // (setter leaves 20). Use `debug.stack` in the script and run with --nocapture to trace.
    let note_script_code = format!(
        r#"
    begin
        dropw push.{hash}
        call.::miden::standards::metadata::fungible_faucet::{proc_name}
        dropw
    end
"#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());

    let mut rng = RandomCoin::new([Felt::from(42u32); 4].into());
    let note = NoteBuilder::new(owner, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([7, 8, 9, 10u32]))
        .code(&note_script_code)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[note])?
        .extend_advice_map([(hash, field_advice_map_value(&new_data))])
        .with_source_manager(source_manager)
        .build()?;

    let executed = tx_context.execute().await?;
    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_delta(executed.account_delta())?;

    for (i, expected) in new_data.iter().enumerate() {
        let chunk = updated_faucet.storage().get_item(slot_fn(i))?;
        assert_eq!(chunk, *expected, "field chunk {i} should be updated");
    }

    Ok(())
}

async fn test_field_setter_non_owner_fails(
    proc_name: &str,
    args: FieldSetterFaucetArgs,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = owner_account_id();
    let non_owner = non_owner_account_id();

    let metadata = network_faucet_metadata(
        "FLD",
        1000,
        Some(0),
        false,
        args.description,
        args.logo_uri,
        args.external_link,
    )?;
    let faucet = builder.add_existing_network_faucet_with_metadata(owner, metadata)?;
    let mock_chain = builder.build()?;

    // Auth check fires before data is touched, so no hash push is needed.
    let note_script_code = format!(
        r#"
    begin
        call.::miden::standards::metadata::fungible_faucet::{proc_name}
        dropw
    end
"#,
        proc_name = proc_name,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());

    let mut rng = RandomCoin::new([Felt::from(99u32); 4].into());
    let note = NoteBuilder::new(non_owner, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([11, 12, 13, 14u32]))
        .code(&note_script_code)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[note])?
        .with_source_manager(source_manager)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

// --- set_description ---

#[tokio::test]
async fn set_description_immutable_fails() -> anyhow::Result<()> {
    test_field_setter_immutable_fails(
        "set_description",
        ERR_DESCRIPTION_NOT_MUTABLE,
        description_config(initial_field_data(), false),
    )
    .await
}

#[tokio::test]
async fn set_description_mutable_owner_succeeds() -> anyhow::Result<()> {
    test_field_setter_owner_succeeds(
        "set_description",
        description_config(initial_field_data(), true),
        TokenMetadata::description_slot,
    )
    .await
}

#[tokio::test]
async fn set_description_mutable_non_owner_fails() -> anyhow::Result<()> {
    test_field_setter_non_owner_fails(
        "set_description",
        description_config(initial_field_data(), true),
    )
    .await
}

// --- set_logo_uri ---

#[tokio::test]
async fn set_logo_uri_immutable_fails() -> anyhow::Result<()> {
    test_field_setter_immutable_fails(
        "set_logo_uri",
        ERR_LOGO_URI_NOT_MUTABLE,
        logo_uri_config(initial_field_data(), false),
    )
    .await
}

#[tokio::test]
async fn set_logo_uri_mutable_owner_succeeds() -> anyhow::Result<()> {
    test_field_setter_owner_succeeds(
        "set_logo_uri",
        logo_uri_config(initial_field_data(), true),
        TokenMetadata::logo_uri_slot,
    )
    .await
}

#[tokio::test]
async fn set_logo_uri_mutable_non_owner_fails() -> anyhow::Result<()> {
    test_field_setter_non_owner_fails("set_logo_uri", logo_uri_config(initial_field_data(), true))
        .await
}

// --- set_external_link ---

#[tokio::test]
async fn set_external_link_immutable_fails() -> anyhow::Result<()> {
    test_field_setter_immutable_fails(
        "set_external_link",
        ERR_EXTERNAL_LINK_NOT_MUTABLE,
        external_link_config(initial_field_data(), false),
    )
    .await
}

#[tokio::test]
async fn set_external_link_mutable_owner_succeeds() -> anyhow::Result<()> {
    test_field_setter_owner_succeeds(
        "set_external_link",
        external_link_config(initial_field_data(), true),
        TokenMetadata::external_link_slot,
    )
    .await
}

#[tokio::test]
async fn set_external_link_mutable_non_owner_fails() -> anyhow::Result<()> {
    test_field_setter_non_owner_fails(
        "set_external_link",
        external_link_config(initial_field_data(), true),
    )
    .await
}

// =================================================================================================
// SETTER TESTS – set_max_supply
// =================================================================================================

#[tokio::test]
async fn set_max_supply_immutable_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = owner_account_id();

    let metadata = network_faucet_metadata("MSM", 1000, Some(0), false, None, None, None)?;
    let faucet = builder.add_existing_network_faucet_with_metadata(owner, metadata)?;
    let mock_chain = builder.build()?;

    let tx_script_code = r#"
        begin
            push.2000
            call.::miden::standards::metadata::fungible_faucet::set_max_supply
        end
    "#;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_tx_script(tx_script_code)?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, ERR_MAX_SUPPLY_NOT_MUTABLE);

    Ok(())
}

#[tokio::test]
async fn set_max_supply_mutable_owner_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = owner_account_id();
    let new_max_supply: u64 = 2000;

    let metadata = network_faucet_metadata("MSM", 1000, Some(0), true, None, None, None)?;
    let faucet = builder.add_existing_network_faucet_with_metadata(owner, metadata)?;
    let mock_chain = builder.build()?;

    let note_script_code = format!(
        r#"
        begin
            push.{new_max_supply}
            swap drop
            call.::miden::standards::metadata::fungible_faucet::set_max_supply
        end
    "#
    );

    let source_manager = Arc::new(DefaultSourceManager::default());

    let mut rng = RandomCoin::new([Felt::from(42u32); 4].into());
    let note = NoteBuilder::new(owner, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([20, 21, 22, 23u32]))
        .code(&note_script_code)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[note])?
        .with_source_manager(source_manager)
        .build()?;

    let executed = tx_context.execute().await?;
    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_delta(executed.account_delta())?;

    let restored = FungibleTokenMetadata::try_from(updated_faucet.storage())?;
    assert_eq!(
        restored.max_supply().as_canonical_u64(),
        new_max_supply,
        "max_supply should be updated"
    );
    assert_eq!(restored.token_supply(), Felt::ZERO, "token_supply should remain unchanged");

    Ok(())
}

#[tokio::test]
async fn set_max_supply_mutable_non_owner_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = owner_account_id();
    let non_owner = non_owner_account_id();

    let metadata = network_faucet_metadata("MSM", 1000, Some(0), true, None, None, None)?;
    let faucet = builder.add_existing_network_faucet_with_metadata(owner, metadata)?;
    let mock_chain = builder.build()?;

    // Auth check fires before data is touched, so no arguments needed.
    let note_script_code = "
        begin
            call.::miden::standards::metadata::fungible_faucet::set_max_supply
        end
    ";

    let source_manager = Arc::new(DefaultSourceManager::default());

    let mut rng = RandomCoin::new([Felt::from(99u32); 4].into());
    let note = NoteBuilder::new(non_owner, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([30, 31, 32, 33u32]))
        .code(note_script_code)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[note])?
        .with_source_manager(source_manager)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}
