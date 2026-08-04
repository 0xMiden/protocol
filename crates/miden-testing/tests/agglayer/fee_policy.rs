use miden_agglayer::testing::{
    bridge_admin_account_id,
    create_existing_bridge_account_with_roles_and_fee_policy,
};
use miden_agglayer::{
    AggLayerBridge,
    AggLayerFaucet,
    create_existing_agglayer_faucet_with_fee_policy,
};
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId, StorageMapKey};
use miden_protocol::asset::AssetId;
use miden_protocol::block::FeeParameters;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_tx::NetworkNotePricer;

const VERIFICATION_BASE_FEE: u32 = 500;
const MIDEN_NETWORK_ID: u32 = 77;

fn fee_faucet_id() -> AccountId {
    AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
        .expect("testing fee faucet ID should be valid")
}

fn pricer() -> NetworkNotePricer {
    NetworkNotePricer::builder()
        .fee_parameters(FeeParameters::new(fee_faucet_id(), VERIFICATION_BASE_FEE))
        .build()
}

fn assert_priced_account(
    account: &Account,
    roots: impl IntoIterator<Item = miden_protocol::note::NoteScriptRoot>,
) -> anyhow::Result<()> {
    let pricer = pricer();
    assert_eq!(
        account.storage().get_item(FeePolicyManager::active_fee_policy_slot())?,
        BasicConstantFeePolicy::root().as_word()
    );
    assert_eq!(
        account.storage().get_item(FeePolicyManager::fee_asset_id_slot())?,
        AssetId::new_fungible(fee_faucet_id()).to_word()
    );

    for root in roots {
        let entry = account.storage().get_map_item(
            BasicConstantFeePolicy::fee_schedule_slot_name(),
            StorageMapKey::new(root.as_word()),
        )?;
        assert_eq!(entry[0].as_canonical_u64(), pricer.price(root)?.as_u64());
        assert_eq!(entry[3].as_canonical_u64(), 1, "the schedule entry must carry its set marker");
    }

    Ok(())
}

#[test]
fn agglayer_accounts_install_priced_basic_constant_fee_policies() -> anyhow::Result<()> {
    let pricer = pricer();
    let admin = bridge_admin_account_id();

    let bridge_roots = AggLayerBridge::fee_policy_notes();
    let bridge_manager = pricer.basic_constant_fee_policy_manager(bridge_roots.clone())?;
    let bridge = create_existing_bridge_account_with_roles_and_fee_policy(
        Word::default(),
        admin,
        admin,
        admin,
        admin,
        MIDEN_NETWORK_ID,
        bridge_manager,
    );
    assert_priced_account(&bridge, bridge_roots)?;

    let faucet_roots = AggLayerFaucet::fee_policy_notes();
    let faucet_manager = pricer.basic_constant_fee_policy_manager(faucet_roots.clone())?;
    let faucet = create_existing_agglayer_faucet_with_fee_policy(
        Word::from([1u32, 0, 0, 0]),
        "AGG",
        6,
        1_000u32.into(),
        0u32.into(),
        bridge.id(),
        faucet_manager,
    );
    assert_priced_account(&faucet, faucet_roots)?;

    Ok(())
}
