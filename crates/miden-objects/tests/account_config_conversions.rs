use core::error::Error;

use assert_matches::assert_matches;
use miden_objects::{ConversionError, proto};
use miden_protocol::account::{
    AccountCode,
    AccountId,
    AccountIdVersion,
    AccountStorage,
    AccountStorageHeader,
    AccountType,
    AssetCallbackFlag,
    PartialAccount,
    PartialStorage,
    PartialStorageMap,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotId,
    StorageSlotName,
};
use miden_protocol::asset::{
    Asset,
    AssetId,
    AssetVault,
    FungibleAsset,
    NonFungibleAsset,
    PartialVault,
};
use miden_protocol::crypto::merkle::smt::{PartialSmt, Smt};
use miden_protocol::errors::{
    AccountError,
    AssetError,
    PartialAssetVaultError,
    ProtocolConfigError,
};
use miden_protocol::protocol_config::{
    KernelConfig,
    ProofSecurityPolicy,
    ProofVerificationConfig,
    ProtocolConfig,
};
use miden_protocol::{Felt, Word};
use prost::Message;

fn dummy_account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

fn partial_account() -> PartialAccount {
    PartialAccount::new(
        dummy_account_id(7),
        Felt::ONE,
        AccountCode::mock(),
        PartialStorage::new(AccountStorageHeader::new(vec![]).unwrap(), []).unwrap(),
        PartialVault::new(Word::empty()),
        None,
    )
    .unwrap()
}

fn dummy_protocol_config() -> ProtocolConfig {
    ProtocolConfig::new(
        AssetId::new_fungible(dummy_account_id(8)),
        KernelConfig::new(Word::from([1_u32, 0, 0, 0]), vec![Word::from([2_u32, 0, 0, 0])])
            .unwrap(),
        KernelConfig::new(Word::from([3_u32, 0, 0, 0]), vec![]).unwrap(),
        KernelConfig::new(Word::from([4_u32, 0, 0, 0]), vec![]).unwrap(),
        ProofVerificationConfig::new(
            Word::from([5_u32, 0, 0, 0]),
            Word::from([6_u32, 0, 0, 0]),
            ProofSecurityPolicy::new(Word::from([7_u32, 0, 0, 0]), 96).unwrap(),
        ),
    )
    .unwrap()
}

fn error_source<E: Error + 'static>(error: &ConversionError) -> Option<&E> {
    error.source().and_then(|source| source.downcast_ref::<E>())
}

#[test]
fn storage_slot_id_roundtrips_through_protobuf_bytes() {
    let id = StorageSlotId::new(Felt::from(1_u32), Felt::from(2_u32));

    let encoded = proto::account::StorageSlotId::from(id).encode_to_vec();
    let message = proto::account::StorageSlotId::decode(encoded.as_slice()).unwrap();

    assert_eq!(StorageSlotId::try_from(message).unwrap(), id);
}

#[test]
fn partial_account_roundtrips_through_protobuf_bytes() {
    let account = partial_account();

    let encoded = proto::account::PartialAccount::from(&account).encode_to_vec();
    let message = proto::account::PartialAccount::decode(encoded.as_slice()).unwrap();

    assert_eq!(PartialAccount::try_from(message).unwrap(), account);
}

#[test]
fn partial_account_requires_nested_messages() {
    let mut message = proto::account::PartialAccount::from(partial_account());
    message.account_id = None;

    let error = PartialAccount::try_from(message).unwrap_err();

    assert!(error.to_string().ends_with("::account_id is missing"));
}

#[test]
fn partial_account_preserves_seed_validation_source() {
    let mut message = proto::account::PartialAccount::from(partial_account());
    message.seed = Some(Word::empty().into());

    let error = PartialAccount::try_from(message).unwrap_err();

    assert_matches!(
        error_source::<AccountError>(&error),
        Some(AccountError::ExistingAccountWithSeed)
    );
}

#[test]
fn partial_account_rejects_new_account_without_seed() {
    let mut message = proto::account::PartialAccount::from(partial_account());
    message.nonce = Some(Felt::ZERO.into());

    let error = PartialAccount::try_from(message).unwrap_err();

    assert_matches!(
        error_source::<AccountError>(&error),
        Some(AccountError::NewAccountMissingSeed)
    );
}

#[test]
fn partial_storage_rejects_duplicate_roots_before_collection() {
    let mut message = proto::account::PartialStorage::from(partial_account().storage());
    let map = proto::account::PartialStorageMap {
        smt: Some(PartialSmt::new(Word::from([9_u32, 0, 0, 0])).into()),
        keys: vec![],
    };
    message.maps = vec![map.clone(), map];

    let error = PartialStorage::try_from(message).unwrap_err();

    assert_eq!(error.to_string(), "maps[1]: duplicate partial storage map root");
}

#[test]
fn partial_storage_preserves_root_not_in_header_source() {
    let mut message = proto::account::PartialStorage::from(partial_account().storage());
    message.maps.push(proto::account::PartialStorageMap {
        smt: Some(PartialSmt::new(Word::from([9_u32, 0, 0, 0])).into()),
        keys: vec![],
    });

    let error = PartialStorage::try_from(message).unwrap_err();

    assert_matches!(
        error_source::<AccountError>(&error),
        Some(AccountError::StorageMapRootNotFound(root)) if *root == Word::from([9_u32, 0, 0, 0])
    );
}

#[test]
fn partial_storage_map_rejects_duplicate_raw_keys() {
    let key = StorageMapKey::from_index(1);
    let storage_map = StorageMap::with_entries([(key, Word::from([2_u32, 0, 0, 0]))]).unwrap();
    let mut message: proto::account::PartialStorageMap =
        PartialStorageMap::new_full(storage_map).into();
    message.keys.push(Word::from(key).into());

    let error = PartialStorageMap::try_from(message).unwrap_err();

    assert_matches!(
        error_source::<miden_protocol::crypto::merkle::MerkleError>(&error),
        Some(miden_protocol::crypto::merkle::MerkleError::DuplicateValuesForIndex(_))
    );
}

#[test]
fn partial_storage_map_rejects_untracked_raw_keys() {
    let mut message: proto::account::PartialStorageMap =
        PartialStorageMap::new(Word::empty()).into();
    message.keys = vec![Word::from(StorageMapKey::from_index(1)).into()];

    let error = PartialStorageMap::try_from(message).unwrap_err();

    assert_matches!(
        error_source::<miden_protocol::crypto::merkle::MerkleError>(&error),
        Some(miden_protocol::crypto::merkle::MerkleError::UntrackedKey(_))
    );
}

#[test]
fn partial_vault_rejects_duplicate_asset_ids() {
    let id = AssetId::new_fungible(dummy_account_id(9));
    let asset = Asset::new(id, Word::from([2_u32, 0, 0, 0])).unwrap();
    let mut message: proto::account::PartialVault =
        PartialVault::new_full(AssetVault::new(&[asset]).unwrap()).into();
    message.asset_ids.push(Word::from(id).into());

    let error = PartialVault::try_from(message).unwrap_err();

    assert_matches!(
        error_source::<PartialAssetVaultError>(&error),
        Some(PartialAssetVaultError::DuplicateAssetId(actual)) if *actual == id
    );
}

#[test]
fn partial_vault_preserves_invalid_asset_id_source() {
    let mut message: proto::account::PartialVault = PartialVault::new(Word::empty()).into();
    message.asset_ids = vec![Word::empty().into()];

    let error = PartialVault::try_from(message).unwrap_err();

    assert_matches!(error_source::<AssetError>(&error), Some(AssetError::UnknownAssetIdVersion(0)));
}

#[test]
fn partial_vault_preserves_invalid_asset_value_source() {
    let id = AssetId::new_fungible(dummy_account_id(9));
    let smt = Smt::with_entries([(id.hash().as_word(), Word::from([1_u32, 2, 0, 0]))]).unwrap();
    let message = proto::account::PartialVault {
        smt: Some(PartialSmt::from_proofs([smt.open(&id.hash().as_word())]).unwrap().into()),
        asset_ids: vec![Word::from(id).into()],
    };

    let error = PartialVault::try_from(message).unwrap_err();

    assert_matches!(
        error_source::<PartialAssetVaultError>(&error),
        Some(PartialAssetVaultError::InvalidAssetForId {
            source: AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(_),
            ..
        })
    );
}

#[test]
fn partial_storage_decoding_normalizes_map_order() {
    let storage = AccountStorage::new(vec![
        StorageSlot::with_empty_map(StorageSlotName::mock(1)),
        StorageSlot::with_empty_map(StorageSlotName::mock(2)),
    ])
    .unwrap();
    let partial_storage = PartialStorage::new_full(storage);
    let expected = proto::account::PartialStorage::from(&partial_storage);
    let mut unordered = expected.clone();
    unordered.maps.reverse();

    let decoded = PartialStorage::try_from(unordered).unwrap();

    assert_eq!(proto::account::PartialStorage::from(decoded), expected);
}

#[test]
fn partial_vault_decoding_normalizes_asset_id_order() {
    let vault =
        AssetVault::new(&[FungibleAsset::mock(2), NonFungibleAsset::mock(&[1, 2, 3])]).unwrap();
    let expected: proto::account::PartialVault = PartialVault::new_full(vault).into();
    let mut unordered = expected.clone();
    unordered.asset_ids.reverse();

    let decoded = PartialVault::try_from(unordered).unwrap();

    assert_eq!(proto::account::PartialVault::from(decoded), expected);
}

#[test]
fn partial_account_encoding_canonicalizes_map_like_fields() {
    let key_a = StorageMapKey::from_index(1);
    let key_b = StorageMapKey::from_index(2);
    let storage_map = StorageMap::with_entries([
        (key_a, Word::from([11_u32, 0, 0, 0])),
        (key_b, Word::from([12_u32, 0, 0, 0])),
    ])
    .unwrap();
    let storage =
        AccountStorage::new(vec![StorageSlot::with_map(StorageSlotName::mock(1), storage_map)])
            .unwrap();
    let partial_storage = PartialStorage::new_full(storage);
    let account = PartialAccount::new(
        dummy_account_id(7),
        Felt::ONE,
        AccountCode::mock(),
        partial_storage,
        PartialVault::new(Word::empty()),
        None,
    )
    .unwrap();

    let message = proto::account::PartialAccount::from(account);
    let keys = &message.storage.unwrap().maps[0].keys;

    assert_eq!(keys, &vec![Word::from(key_a).into(), Word::from(key_b).into()]);
}

#[test]
fn protocol_config_roundtrips_through_protobuf_bytes_and_preserves_kernel_order() {
    let config = dummy_protocol_config();

    let encoded = proto::protocol_config::ProtocolConfig::from(&config).encode_to_vec();
    let message = proto::protocol_config::ProtocolConfig::decode(encoded.as_slice()).unwrap();

    assert_eq!(
        message.tx_kernel.as_ref().unwrap().kernel_procs,
        vec![Word::from([2_u32, 0, 0, 0]).into()]
    );
    assert_eq!(ProtocolConfig::try_from(message).unwrap(), config);
}

#[test]
fn protocol_config_requires_all_nested_messages() {
    let mut message = proto::protocol_config::ProtocolConfig::from(dummy_protocol_config());
    message.proof_verification = None;

    let error = ProtocolConfig::try_from(message).unwrap_err();

    assert!(error.to_string().ends_with("::proof_verification is missing"));
}

#[test]
fn protocol_config_preserves_fee_asset_validation_source() {
    let mut message = proto::protocol_config::ProtocolConfig::from(dummy_protocol_config());
    let non_fungible = AssetId::new(
        miden_protocol::asset::AssetClass::default(),
        dummy_account_id(10),
        miden_protocol::asset::AssetComposition::None,
    )
    .unwrap();
    message.fee_asset_id = Some(Word::from(non_fungible).into());

    let error = ProtocolConfig::try_from(message).unwrap_err();

    assert_matches!(
        error_source::<ProtocolConfigError>(&error),
        Some(ProtocolConfigError::FeeAssetMustBeFungible(_))
    );
}

#[test]
fn kernel_config_rejects_oversized_procedure_list() {
    let error = KernelConfig::try_from(proto::protocol_config::KernelConfig {
        main_proc: Some(Word::empty().into()),
        kernel_procs: vec![Word::empty().into(); KernelConfig::MAX_NUM_KERNEL_PROCEDURES + 1],
    })
    .unwrap_err();

    assert_matches!(
        error_source::<ProtocolConfigError>(&error),
        Some(ProtocolConfigError::TooManyKernelProcedures { count })
            if *count == KernelConfig::MAX_NUM_KERNEL_PROCEDURES + 1
    );
}

#[test]
fn protocol_config_reports_the_full_nested_repeated_field_path() {
    let mut message = proto::protocol_config::ProtocolConfig::from(dummy_protocol_config());
    message
        .tx_kernel
        .as_mut()
        .unwrap()
        .kernel_procs
        .push(proto::primitives::Word { encoded: vec![0_u8; 31] });

    let error = ProtocolConfig::try_from(message).unwrap_err();

    assert!(
        error.to_string().starts_with("tx_kernel.kernel_procs[1].word.encoded:"),
        "unexpected error path: {error}"
    );
}

#[test]
fn proof_security_policy_rejects_out_of_range_minimum_bits() {
    let error = ProofSecurityPolicy::try_from(proto::protocol_config::ProofSecurityPolicy {
        security_estimator_root: Some(Word::empty().into()),
        minimum_bits: u32::from(u8::MAX) + 1,
    })
    .unwrap_err();

    assert_matches!(error_source::<core::num::TryFromIntError>(&error), Some(_));
}

#[test]
fn proof_security_policy_preserves_zero_bits_validation_source() {
    let error = ProofSecurityPolicy::try_from(proto::protocol_config::ProofSecurityPolicy {
        security_estimator_root: Some(Word::empty().into()),
        minimum_bits: 0,
    })
    .unwrap_err();

    assert_matches!(
        error_source::<ProtocolConfigError>(&error),
        Some(ProtocolConfigError::MinimumSecurityBitsMustBeNonZero)
    );
}
