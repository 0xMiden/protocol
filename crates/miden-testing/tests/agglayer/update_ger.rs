use miden_agglayer::{ExitRoot, UpdateGerNote, create_existing_bridge_account};
use miden_protocol::Word;
use miden_protocol::account::StorageSlotName;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::OutputNote;
use miden_testing::{Auth, MockChain};

#[tokio::test]
async fn test_update_ger_note_updates_storage() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(bridge_seed);
    builder.add_account(bridge_account.clone())?;

    // CREATE USER ACCOUNT (NOTE SENDER)
    // --------------------------------------------------------------------------------------------
    let user_account = builder.add_existing_wallet(Auth::BasicAuth)?;
    builder.add_account(user_account.clone())?;

    // CREATE UPDATE_GER NOTE WITH 8 STORAGE ITEMS (NEW GER AS TWO WORDS)
    // --------------------------------------------------------------------------------------------

    let ger_bytes: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];
    let ger = ExitRoot::from(ger_bytes);
    let update_ger_note =
        UpdateGerNote::create(ger, user_account.id(), bridge_account.id(), builder.rng_mut())?;

    builder.add_output_note(OutputNote::Full(update_ger_note.clone()));
    let mock_chain = builder.build()?;

    // EXECUTE UPDATE_GER NOTE AGAINST BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // VERIFY GER WAS UPDATED IN STORAGE
    // --------------------------------------------------------------------------------------------
    let mut updated_bridge_account = bridge_account.clone();
    updated_bridge_account.apply_delta(executed_transaction.account_delta())?;

    let ger_upper = updated_bridge_account
        .storage()
        .get_item(&StorageSlotName::new("miden::agglayer::bridge::ger_upper")?)
        .unwrap();
    let ger_lower = updated_bridge_account
        .storage()
        .get_item(&StorageSlotName::new("miden::agglayer::bridge::ger_lower")?)
        .unwrap();
    let expected_lower: Word = ger.to_elements()[0..4].try_into().unwrap();
    let expected_upper: Word = ger.to_elements()[4..8].try_into().unwrap();
    assert_eq!(ger_upper, expected_upper);
    assert_eq!(ger_lower, expected_lower);

    Ok(())
}
