use assert_matches::assert_matches;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::{AccountBuilder, AccountComponent, AccountType};
use miden_protocol::asset::{FungibleAsset, NonFungibleAsset, TokenSymbol};
use miden_protocol::crypto::rand::{FeltRng, RpoRandomCoin};
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteMetadata,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
};
use miden_protocol::{Felt, Word};

use crate::AuthScheme;
use crate::account::auth::{
    AuthEcdsaK256Keccak,
    AuthFalcon512Rpo,
    AuthFalcon512RpoMultisig,
    AuthFalcon512RpoMultisigConfig,
    NoAuth,
};
use crate::account::faucets::BasicFungibleFaucet;
use crate::account::interface::{
    AccountComponentInterface,
    AccountInterface,
    AccountInterfaceExt,
    NoteAccountCompatibility,
};
use crate::account::wallets::BasicWallet;
use crate::code_builder::CodeBuilder;
use crate::note::{P2idNote, P2ideNote, SwapNote};
use crate::testing::account_interface::get_public_keys_from_account;

// DEFAULT NOTES
// ================================================================================================

#[test]
fn test_basic_wallet_default_notes() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(20)])
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    let mock_seed = Word::from([Felt::new(4), Felt::new(5), Felt::new(6), Felt::new(7)]).as_bytes();
    let faucet_account = AccountBuilder::new(mock_seed)
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(get_mock_auth_component())
        .with_component(
            BasicFungibleFaucet::new(
                TokenSymbol::new("POL").expect("invalid token symbol"),
                10,
                Felt::new(100),
            )
            .expect("failed to create a fungible faucet component"),
        )
        .build_existing()
        .expect("failed to create wallet account");
    let faucet_account_interface = AccountInterface::from_account(&faucet_account);

    let p2id_note = P2idNote::create(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap(),
        vec![FungibleAsset::mock(10)],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    let p2ide_note = P2ideNote::create(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap(),
        vec![FungibleAsset::mock(10)],
        None,
        None,
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    let offered_asset = NonFungibleAsset::mock(&[5, 6, 7, 8]);
    let requested_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let (swap_note, _) = SwapNote::create(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        offered_asset,
        requested_asset,
        NoteType::Public,
        NoteAttachment::default(),
        NoteType::Public,
        NoteAttachment::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    // Basic wallet
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        wallet_account_interface.is_compatible_with(&p2id_note)
    );
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        wallet_account_interface.is_compatible_with(&p2ide_note)
    );
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        wallet_account_interface.is_compatible_with(&swap_note)
    );

    // Basic fungible faucet
    assert_eq!(
        NoteAccountCompatibility::No,
        faucet_account_interface.is_compatible_with(&p2id_note)
    );
    assert_eq!(
        NoteAccountCompatibility::No,
        faucet_account_interface.is_compatible_with(&p2ide_note)
    );
    assert_eq!(
        NoteAccountCompatibility::No,
        faucet_account_interface.is_compatible_with(&swap_note)
    );
}

/// Checks the compatibility of the basic notes (P2ID, P2IDE and SWAP) against an account with a
/// custom interface containing a procedure from the basic wallet.
///
/// In that setup check against P2ID and P2IDE notes should result in `Maybe`, and the check against
/// SWAP should result in `No`.
#[test]
fn test_custom_account_default_note() {
    let account_custom_code_source = "
        use miden::standards::wallets::basic

        pub use basic::receive_asset
    ";

    let account_code = CodeBuilder::default()
        .compile_component_code("test::account_custom", account_custom_code_source)
        .unwrap();
    let account_component =
        AccountComponent::new(account_code, vec![]).unwrap().with_supports_all_types();

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let target_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(account_component.clone())
        .build_existing()
        .unwrap();
    let target_account_interface = AccountInterface::from_account(&target_account);

    let p2id_note = P2idNote::create(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap(),
        vec![FungibleAsset::mock(10)],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    let p2ide_note = P2ideNote::create(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap(),
        vec![FungibleAsset::mock(10)],
        None,
        None,
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    let offered_asset = NonFungibleAsset::mock(&[5, 6, 7, 8]);
    let requested_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let (swap_note, _) = SwapNote::create(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        offered_asset,
        requested_asset,
        NoteType::Public,
        NoteAttachment::default(),
        NoteType::Public,
        NoteAttachment::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .unwrap();

    assert_eq!(
        NoteAccountCompatibility::Maybe,
        target_account_interface.is_compatible_with(&p2id_note)
    );
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        target_account_interface.is_compatible_with(&p2ide_note)
    );
    assert_eq!(
        NoteAccountCompatibility::No,
        target_account_interface.is_compatible_with(&swap_note)
    );
}

/// Checks the function `create_swap_note` should fail if the requested asset is the same as the
/// offered asset.
#[test]
fn test_required_asset_same_as_offered() {
    let offered_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);
    let requested_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let result = SwapNote::create(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        offered_asset,
        requested_asset,
        NoteType::Public,
        NoteAttachment::default(),
        NoteType::Public,
        NoteAttachment::default(),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    );

    assert_matches!(result, Err(NoteError::Other { error_msg, .. }) if error_msg == "requested asset same as offered asset".into());
}

// CUSTOM NOTES
// ================================================================================================

#[test]
fn test_basic_wallet_custom_notes() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(20)])
        .build_existing()
        .expect("failed to create wallet account");
    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    let sender_account_id = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap();
    let serial_num = RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let tag = NoteTag::with_account_target(wallet_account.id());
    let metadata = NoteMetadata::new(sender_account_id, NoteType::Public, tag);
    let vault = NoteAssets::new(vec![FungibleAsset::mock(100)]).unwrap();

    let compatible_source_code = "
        use miden::protocol::tx
        use miden::standards::wallets::basic->wallet
        use miden::standards::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note

                # unsupported procs
                call.fungible_faucet::distribute
                call.fungible_faucet::burn
            else
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script = CodeBuilder::default().compile_note_script(compatible_source_code).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let compatible_custom_note = Note::new(vault.clone(), metadata.clone(), recipient);
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        wallet_account_interface.is_compatible_with(&compatible_custom_note)
    );

    let incompatible_source_code = "
        use miden::standards::wallets::basic->wallet
        use miden::standards::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # unsupported procs
                call.fungible_faucet::distribute
                call.fungible_faucet::burn
            else
                # unsupported proc
                call.fungible_faucet::distribute

                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script = CodeBuilder::default().compile_note_script(incompatible_source_code).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let incompatible_custom_note = Note::new(vault, metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::No,
        wallet_account_interface.is_compatible_with(&incompatible_custom_note)
    );
}

#[test]
fn test_basic_fungible_faucet_custom_notes() {
    let mock_seed = Word::from([Felt::new(4), Felt::new(5), Felt::new(6), Felt::new(7)]).as_bytes();
    let faucet_account = AccountBuilder::new(mock_seed)
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(get_mock_auth_component())
        .with_component(
            BasicFungibleFaucet::new(
                TokenSymbol::new("POL").expect("invalid token symbol"),
                10,
                Felt::new(100),
            )
            .expect("failed to create a fungible faucet component"),
        )
        .build_existing()
        .expect("failed to create wallet account");
    let faucet_account_interface = AccountInterface::from_account(&faucet_account);

    let sender_account_id = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap();
    let serial_num = RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let tag = NoteTag::with_account_target(faucet_account.id());
    let metadata = NoteMetadata::new(sender_account_id, NoteType::Public, tag);
    let vault = NoteAssets::new(vec![FungibleAsset::mock(100)]).unwrap();

    let compatible_source_code = "
        use miden::standards::wallets::basic->wallet
        use miden::standards::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.fungible_faucet::distribute
                call.fungible_faucet::burn
            else
                # supported proc
                call.fungible_faucet::distribute

                # unsupported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script = CodeBuilder::default().compile_note_script(compatible_source_code).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let compatible_custom_note = Note::new(vault.clone(), metadata.clone(), recipient);
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        faucet_account_interface.is_compatible_with(&compatible_custom_note)
    );

    let incompatible_source_code = "
        use miden::standards::wallets::basic->wallet
        use miden::standards::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.fungible_faucet::distribute
                call.fungible_faucet::burn

                # unsupported proc
                call.wallet::receive_asset
            else
                # supported proc
                call.fungible_faucet::burn

                # unsupported procs
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script = CodeBuilder::default().compile_note_script(incompatible_source_code).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let incompatible_custom_note = Note::new(vault, metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::No,
        faucet_account_interface.is_compatible_with(&incompatible_custom_note)
    );
}

/// Checks the compatibility of the note with custom code against an account with one custom
/// interface.
///
/// In that setup the note script should have at least one execution branch with procedures from the
/// account interface for being `Maybe` compatible.
#[test]
fn test_custom_account_custom_notes() {
    let account_custom_code_source = "
        pub proc procedure_1
            push.1.2.3.4 dropw
        end

        pub proc procedure_2
            push.5.6.7.8 dropw
        end
    ";

    let account_code = CodeBuilder::default()
        .compile_component_code("test::account::component_1", account_custom_code_source)
        .unwrap();
    let account_component =
        AccountComponent::new(account_code, vec![]).unwrap().with_supports_all_types();

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let target_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(account_component.clone())
        .build_existing()
        .unwrap();
    let target_account_interface = AccountInterface::from_account(&target_account);

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let sender_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(20)])
        .build_existing()
        .expect("failed to create wallet account");

    let serial_num = RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let tag = NoteTag::with_account_target(target_account.id());
    let metadata = NoteMetadata::new(sender_account.id(), NoteType::Public, tag);
    let vault = NoteAssets::new(vec![FungibleAsset::mock(100)]).unwrap();

    let compatible_source_code = "
        use miden::standards::wallets::basic->wallet
        use test::account::component_1->test_account

        begin
            push.1
            if.true
                # supported proc
                call.test_account::procedure_1

                # unsupported proc
                call.wallet::receive_asset
            else
                # supported procs
                call.test_account::procedure_1
                call.test_account::procedure_2
            end
        end
    ";
    let note_script = CodeBuilder::default()
        .with_dynamically_linked_library(account_component.component_code())
        .unwrap()
        .compile_note_script(compatible_source_code)
        .unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let compatible_custom_note = Note::new(vault.clone(), metadata.clone(), recipient);
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        target_account_interface.is_compatible_with(&compatible_custom_note)
    );

    let incompatible_source_code = "
        use miden::standards::wallets::basic->wallet
        use test::account::component_1->test_account

        begin
            push.1
            if.true
                call.wallet::receive_asset
                call.test_account::procedure_1
            else
                call.test_account::procedure_2
                call.wallet::move_asset_to_note
            end
        end
    ";
    let note_script = CodeBuilder::default()
        .with_dynamically_linked_library(account_component.component_code())
        .unwrap()
        .compile_note_script(incompatible_source_code)
        .unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let incompatible_custom_note = Note::new(vault, metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::No,
        target_account_interface.is_compatible_with(&incompatible_custom_note)
    );
}

/// Checks the compatibility of the note with custom code against an account with many custom
/// interfaces.
///
/// In that setup the note script should have at least one execution branch with procedures from the
/// account interface for being `Maybe` compatible.
#[test]
fn test_custom_account_multiple_components_custom_notes() {
    let account_custom_code_source = "
        pub proc procedure_1
            push.1.2.3.4 dropw
        end

        pub proc procedure_2
            push.5.6.7.8 dropw
        end
    ";

    let custom_code = CodeBuilder::default()
        .compile_component_code("test::account::component_1", account_custom_code_source)
        .unwrap();
    let custom_component =
        AccountComponent::new(custom_code, vec![]).unwrap().with_supports_all_types();

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let target_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(custom_component.clone())
        .with_component(BasicWallet)
        .build_existing()
        .unwrap();
    let target_account_interface = AccountInterface::from_account(&target_account);

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let sender_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(20)])
        .build_existing()
        .expect("failed to create wallet account");

    let serial_num = RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let tag = NoteTag::with_account_target(target_account.id());
    let metadata = NoteMetadata::new(sender_account.id(), NoteType::Public, tag);
    let vault = NoteAssets::new(vec![FungibleAsset::mock(100)]).unwrap();

    let compatible_source_code = "
        use miden::standards::wallets::basic->wallet
        use test::account::component_1->test_account
        use miden::standards::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
                call.test_account::procedure_1
                call.test_account::procedure_2
            else
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
                call.test_account::procedure_1
                call.test_account::procedure_2

                # unsupported proc
                call.fungible_faucet::distribute
            end
        end
    ";
    let note_script = CodeBuilder::default()
        .with_dynamically_linked_library(custom_component.component_code())
        .unwrap()
        .compile_note_script(compatible_source_code)
        .unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let compatible_custom_note = Note::new(vault.clone(), metadata.clone(), recipient);
    assert_eq!(
        NoteAccountCompatibility::Maybe,
        target_account_interface.is_compatible_with(&compatible_custom_note)
    );

    let incompatible_source_code = "
        use miden::standards::wallets::basic->wallet
        use test::account::component_1->test_account
        use miden::standards::faucets::basic_fungible->fungible_faucet

        begin
            push.1
            if.true
                # supported procs
                call.wallet::receive_asset
                call.wallet::move_asset_to_note
                call.test_account::procedure_1
                call.test_account::procedure_2

                # unsupported proc
                call.fungible_faucet::distribute
            else
                # supported procs
                call.test_account::procedure_1
                call.test_account::procedure_2

                # unsupported proc
                call.fungible_faucet::burn
            end
        end
    ";
    let note_script = CodeBuilder::default()
        .with_dynamically_linked_library(custom_component.component_code())
        .unwrap()
        .compile_note_script(incompatible_source_code)
        .unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let incompatible_custom_note = Note::new(vault.clone(), metadata, recipient);
    assert_eq!(
        NoteAccountCompatibility::No,
        target_account_interface.is_compatible_with(&incompatible_custom_note)
    );
}

// HELPERS
// ================================================================================================

/// Helper function to create a mock auth component for testing
fn get_mock_auth_component() -> AuthFalcon512Rpo {
    let mock_word = Word::from([0, 1, 2, 3u32]);
    let mock_public_key = PublicKeyCommitment::from(mock_word);
    AuthFalcon512Rpo::new(mock_public_key)
}

/// Helper function to create a mock Ecdsa auth component for testing
fn get_mock_ecdsa_auth_component() -> AuthEcdsaK256Keccak {
    let mock_word = Word::from([0, 1, 2, 3u32]);
    let mock_public_key = PublicKeyCommitment::from(mock_word);
    AuthEcdsaK256Keccak::new(mock_public_key)
}

// GET AUTH SCHEME TESTS
// ================================================================================================

#[test]
fn test_get_auth_scheme_ecdsa_k256_keccak() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_ecdsa_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    // Find the EcdsaK256Keccak component interface
    let ecdsa_k256_keccak_component = wallet_account_interface
        .components()
        .iter()
        .find(|component| matches!(component, AccountComponentInterface::AuthEcdsaK256Keccak))
        .expect("should have EcdsaK256Keccak component");

    // Test get_auth_schemes method
    let auth_schemes = ecdsa_k256_keccak_component.get_auth_schemes(wallet_account.storage());
    assert_eq!(auth_schemes.len(), 1);
    let auth_scheme = &auth_schemes[0];
    match auth_scheme {
        AuthScheme::EcdsaK256Keccak { pub_key } => {
            assert_eq!(*pub_key, PublicKeyCommitment::from(Word::from([0, 1, 2, 3u32])));
        },
        _ => panic!("Expected EcdsaK256Keccak auth scheme"),
    }
}

#[test]
fn test_get_auth_scheme_falcon512_rpo() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    // Find the Falcon512Rpo component interface
    let rpo_falcon_component = wallet_account_interface
        .components()
        .iter()
        .find(|component| matches!(component, AccountComponentInterface::AuthFalcon512Rpo))
        .expect("should have Falcon512Rpo component");

    // Test get_auth_schemes method
    let auth_schemes = rpo_falcon_component.get_auth_schemes(wallet_account.storage());
    assert_eq!(auth_schemes.len(), 1);
    let auth_scheme = &auth_schemes[0];
    match auth_scheme {
        AuthScheme::Falcon512Rpo { pub_key } => {
            assert_eq!(*pub_key, PublicKeyCommitment::from(Word::from([0, 1, 2, 3u32])));
        },
        _ => panic!("Expected Falcon512Rpo auth scheme"),
    }
}

#[test]
fn test_get_auth_scheme_no_auth() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from_account(&no_auth_account);

    // Find the NoAuth component interface
    let no_auth_component = no_auth_account_interface
        .components()
        .iter()
        .find(|component| matches!(component, AccountComponentInterface::AuthNoAuth))
        .expect("should have NoAuth component");

    // Test get_auth_schemes method
    let auth_schemes = no_auth_component.get_auth_schemes(no_auth_account.storage());
    assert_eq!(auth_schemes.len(), 1);
    let auth_scheme = &auth_schemes[0];
    match auth_scheme {
        AuthScheme::NoAuth => {},
        _ => panic!("Expected NoAuth auth scheme"),
    }
}

/// Test that non-auth components return None
#[test]
fn test_get_auth_scheme_non_auth_component() {
    let basic_wallet_component = AccountComponentInterface::BasicWallet;
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let auth_schemes = basic_wallet_component.get_auth_schemes(wallet_account.storage());
    assert!(auth_schemes.is_empty());
}

/// Test that the From<&Account> implementation correctly uses get_auth_scheme
#[test]
fn test_account_interface_from_account_uses_get_auth_scheme() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    // Should have exactly one auth scheme
    assert_eq!(wallet_account_interface.auth().len(), 1);

    match &wallet_account_interface.auth()[0] {
        AuthScheme::Falcon512Rpo { pub_key } => {
            let expected_pub_key = PublicKeyCommitment::from(Word::from([0, 1, 2, 3u32]));
            assert_eq!(*pub_key, expected_pub_key);
        },
        _ => panic!("Expected Falcon512Rpo auth scheme"),
    }

    // Test with NoAuth
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from_account(&no_auth_account);

    // Should have exactly one auth scheme
    assert_eq!(no_auth_account_interface.auth().len(), 1);

    match &no_auth_account_interface.auth()[0] {
        AuthScheme::NoAuth => {},
        _ => panic!("Expected NoAuth auth scheme"),
    }
}

/// Test AccountInterface.get_auth_scheme() method with Falcon512Rpo and NoAuth
#[test]
fn test_account_interface_get_auth_scheme() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    // Test that auth() method provides the authentication schemes
    assert_eq!(wallet_account_interface.auth().len(), 1);
    match &wallet_account_interface.auth()[0] {
        AuthScheme::Falcon512Rpo { pub_key } => {
            assert_eq!(*pub_key, PublicKeyCommitment::from(Word::from([0, 1, 2, 3u32])));
        },
        _ => panic!("Expected Falcon512Rpo auth scheme"),
    }

    // Test AccountInterface.get_auth_scheme() method with NoAuth
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from_account(&no_auth_account);

    // Test that auth() method provides the authentication schemes
    assert_eq!(no_auth_account_interface.auth().len(), 1);
    match &no_auth_account_interface.auth()[0] {
        AuthScheme::NoAuth => {},
        _ => panic!("Expected NoAuth auth scheme"),
    }

    // Note: We don't test the case where an account has no auth components because
    // accounts are required to have auth components in the current system design
}

#[test]
fn test_public_key_extraction_regular_account() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    // Test public key extraction like miden-client would do
    let pub_keys = get_public_keys_from_account(&wallet_account);

    assert_eq!(pub_keys.len(), 1);
    assert_eq!(pub_keys[0], Word::from([0, 1, 2, 3u32]));
}

#[test]
fn test_public_key_extraction_multisig_account() {
    // Create test public keys
    let pub_key_1 = PublicKeyCommitment::from(Word::from([1u32, 0, 0, 0]));
    let pub_key_2 = PublicKeyCommitment::from(Word::from([2u32, 0, 0, 0]));
    let pub_key_3 = PublicKeyCommitment::from(Word::from([3u32, 0, 0, 0]));
    let approvers = vec![pub_key_1, pub_key_2, pub_key_3];
    let threshold = 2u32;

    // Create multisig component
    let multisig_component = AuthFalcon512RpoMultisig::new(
        AuthFalcon512RpoMultisigConfig::new(approvers.clone(), threshold).unwrap(),
    )
    .expect("multisig component creation failed");

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let multisig_account = AccountBuilder::new(mock_seed)
        .with_auth_component(multisig_component)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create multisig account");

    let pub_keys = get_public_keys_from_account(&multisig_account);

    assert_eq!(pub_keys.len(), 3);
    assert_eq!(pub_keys[0], Word::from([1u32, 0, 0, 0]));
    assert_eq!(pub_keys[1], Word::from([2u32, 0, 0, 0]));
    assert_eq!(pub_keys[2], Word::from([3u32, 0, 0, 0]));
}

#[test]
fn test_public_key_extraction_no_auth_account() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    // Test public key extraction
    let pub_keys = get_public_keys_from_account(&no_auth_account);

    // NoAuth should not contribute any public keys
    assert_eq!(pub_keys.len(), 0);
}
