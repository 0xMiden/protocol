use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::note::FeeNote;
use miden_testing::{Auth, MockChain};

/// One and the same FEE note is consumable by either of two unrelated accounts.
///
/// This is the property the batch-builder fee flow relies on: the payer does not know which account
/// will build the batch, so the note must be payable to nobody in particular. Both accounts consume
/// *the same note* against the same chain state, and neither is the note's sender. Building two
/// separate notes would not have demonstrated the absence of target binding.
#[tokio::test]
async fn fee_note_is_consumable_by_any_account() -> anyhow::Result<()> {
    let fee_asset: Asset = FungibleAsset::mock(500);
    let mut rng = RandomCoin::new(Word::empty());

    let mut builder = MockChain::builder();

    // Two unrelated accounts, neither of which is the note's sender.
    let account_a = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let account_b = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let fee_note = Note::from(
        FeeNote::builder()
            .sender(ACCOUNT_ID_SENDER.try_into()?)
            .asset(fee_asset)
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(fee_note.clone()));

    let mock_chain = builder.build()?;

    // Neither transaction is committed, so both consume the same note from the same chain state.
    for mut account in [account_a, account_b] {
        let executed_transaction = mock_chain
            .build_transaction(account.id())
            .authenticated_input_note(fee_note.id())
            .build()?
            .execute()
            .await?;

        account.apply_patch(executed_transaction.account_patch())?;
        assert_eq!(
            account.vault().get_balance(fee_asset.id())?.as_u64(),
            500,
            "the consuming account should keep the entire fee",
        );
    }

    Ok(())
}
