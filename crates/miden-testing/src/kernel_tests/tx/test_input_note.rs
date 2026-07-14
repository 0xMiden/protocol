use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Context;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::errors::tx_kernel::{
    ERR_INPUT_NOTE_ASSET_INDEX_OUT_OF_BOUNDS, ERR_INPUT_NOTE_ASSET_TO_REMOVE_NOT_FOUND,
    ERR_INPUT_NOTE_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND,
    ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW,
};
use miden_protocol::note::{Note, NoteAssets, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1, ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::memory::ASSET_SIZE;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;
use rstest::rstest;

use super::{TestSetup, setup_test};
use crate::utils::create_public_p2any_note;
use crate::{Auth, MockChain, TestTransactionBuilder, TxContextInput, assert_execution_error};

/// Check that the initial assets number and assets commitment obtained from the
/// `input_note::get_initial_assets_info` and `input_note::get_initial_num_assets` procedures are
/// correct for each note with zero, one and two different assets.
///
/// The note scripts remove the assets from the notes while they are consumed, so this also checks
/// that the initial assets info is unaffected by asset removal.
#[tokio::test]
async fn test_get_initial_assets() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets,
        p2id_note_1_asset,
        p2id_note_2_assets,
    } = setup_test()?;

    fn check_asset_info_code(
        note_index: u8,
        assets_commitment: Word,
        assets_number: usize,
    ) -> String {
        format!(
            r#"
            # get the assets hash and assets number from the requested input note
            push.{note_index}
            exec.input_note::get_initial_assets_info
            # => [ASSETS_COMMITMENT, num_assets]

            # assert the correctness of the assets hash
            push.{assets_commitment}
            assert_eqw.err="note {note_index} has incorrect assets hash"
            # => [num_assets]

            # assert the number of note assets
            push.{assets_number}
            assert_eq.err="note {note_index} has incorrect assets number"
            # => []

            # assert the number of note assets returned by get_initial_num_assets
            push.{note_index}
            exec.input_note::get_initial_num_assets
            push.{assets_number}
            assert_eq.err="note {note_index} has incorrect initial assets number"
            # => []
        "#
        )
    }

    let code = format!(
        "
        use miden::protocol::input_note

        @transaction_script
        pub proc main
            {check_note_0}

            {check_note_1}

            {check_note_2}
        end
    ",
        check_note_0 = check_asset_info_code(
            0,
            p2any_note_0_assets.assets().commitment(),
            p2any_note_0_assets.assets().num_assets()
        ),
        check_note_1 = check_asset_info_code(
            1,
            p2id_note_1_asset.assets().commitment(),
            p2id_note_1_asset.assets().num_assets()
        ),
        check_note_2 = check_asset_info_code(
            2,
            p2id_note_2_assets.assets().commitment(),
            p2id_note_2_assets.assets().num_assets()
        ),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_notes([p2any_note_0_assets, p2id_note_1_asset, p2id_note_2_assets])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Check that `input_note::get_initial_assets` writes the initial assets of a note into memory and
/// returns their count for notes with zero, one and two assets.
///
/// The note scripts remove the assets from the notes while they are consumed, so this also checks
/// that the written initial assets are unaffected by asset removal.
#[tokio::test]
async fn test_get_initial_assets_writes_to_memory() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets,
        p2id_note_1_asset,
        p2id_note_2_assets,
    } = setup_test()?;

    fn check_written_assets_code(note_index: u8, dest_ptr: u32, note: &Note) -> String {
        // build the assertions that load each written asset from memory and compare it against the
        // note's initial assets
        let mut load_assets_code = String::new();
        for (asset_index, asset) in note.assets().iter().enumerate() {
            load_assets_code.push_str(&format!(
                r#"
                # load the initial asset at index {asset_index} from memory
                push.{asset_ptr} exec.asset::load
                # => [ASSET_ID, ASSET_VALUE]

                push.{asset_id}
                assert_eqw.err="note {note_index} initial asset {asset_index} has incorrect id"
                push.{asset_value}
                assert_eqw.err="note {note_index} initial asset {asset_index} has incorrect value"
                # => []
                "#,
                asset_ptr = dest_ptr + asset_index as u32 * ASSET_SIZE,
                asset_id = asset.to_id_word(),
                asset_value = asset.to_value_word(),
            ));
        }

        format!(
            r#"
            # write the initial assets of the requested input note into memory
            push.{note_index} push.{dest_ptr}
            exec.input_note::get_initial_assets
            # => [num_assets]

            push.{num_assets}
            assert_eq.err="note {note_index} has incorrect initial assets number"
            # => []

            {load_assets_code}
        "#,
            num_assets = note.assets().num_assets(),
        )
    }

    // give each note a disjoint 16-element (MAX_ASSETS_PER_NOTE * ASSET_SIZE) memory region
    let code = format!(
        "
        use miden::protocol::asset
        use miden::protocol::input_note

        @transaction_script
        pub proc main
            {check_note_0}

            {check_note_1}

            {check_note_2}
        end
    ",
        check_note_0 = check_written_assets_code(0, 0, &p2any_note_0_assets),
        check_note_1 = check_written_assets_code(1, 16, &p2id_note_1_asset),
        check_note_2 = check_written_assets_code(2, 32, &p2id_note_2_assets),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_notes([p2any_note_0_assets, p2id_note_1_asset, p2id_note_2_assets])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Check that recipient and metadata of a note with one asset obtained from the
/// `input_note::get_recipient` and `input_note::get_metadata` procedures are correct.
#[tokio::test]
async fn test_get_recipient_and_metadata() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        @transaction_script
        pub proc main
            # get the recipient from the input note
            push.0
            exec.input_note::get_recipient
            # => [RECIPIENT]

            # assert the correctness of the recipient
            push.{RECIPIENT}
            assert_eqw.err="note 0 has incorrect recipient"
            # => []

            # get the metadata from the requested input note
            push.0
            exec.input_note::get_metadata
            # => [METADATA]

            push.{METADATA}
            assert_eqw.err="note 0 has incorrect metadata"
            # => []
        end
    "#,
        RECIPIENT = p2id_note_1_asset.recipient().digest(),
        METADATA = p2id_note_1_asset.metadata().to_metadata_word(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note_1_asset])?
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Check that a sender of a note with one asset obtained from the `input_note::get_sender`
/// procedure is correct.
#[tokio::test]
async fn test_get_sender() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        @transaction_script
        pub proc main
            # get the sender from the input note
            push.0
            exec.input_note::get_sender
            # => [sender_id_suffix, sender_id_prefix]

            # assert the correctness of the suffix
            push.{sender_suffix}
            assert_eq.err="sender id suffix of the note 0 is incorrect"
            # => [sender_id_prefix]

            # assert the correctness of the prefix
            push.{sender_prefix}
            assert_eq.err="sender id prefix of the note 0 is incorrect"
            # => []
        end
    "#,
        sender_prefix = p2id_note_1_asset.metadata().sender().prefix().as_felt(),
        sender_suffix = p2id_note_1_asset.metadata().sender().suffix(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note_1_asset])?
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Check that `input_note::remove_all_assets` returns zero assets for notes whose assets were
/// already removed by their note scripts during consumption, while the initial assets info stays
/// unchanged.
#[tokio::test]
async fn test_remove_all_assets_after_note_scripts() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets,
        p2id_note_1_asset,
        p2id_note_2_assets,
    } = setup_test()?;

    fn check_removed_assets_code(
        note_index: u8,
        dest_ptr: u8,
        assets_commitment: Word,
        assets_number: usize,
    ) -> String {
        format!(
            r#"
            # remove all assets from the requested input note; the note script has already removed
            # them while the note was consumed, so no assets remain
            push.{note_index} push.{dest_ptr}
            exec.input_note::remove_all_assets
            # => [num_assets]

            assertz.err="note {note_index} should not have any assets left"
            # => []

            # assert the initial assets info is unaffected by the removals
            push.{note_index}
            exec.input_note::get_initial_assets_info
            # => [ASSETS_COMMITMENT, num_assets]

            push.{assets_commitment}
            assert_eqw.err="note {note_index} has incorrect initial assets hash"
            push.{assets_number}
            assert_eq.err="note {note_index} has incorrect initial assets number"
            # => []
        "#
        )
    }

    let code = format!(
        "
        use miden::protocol::input_note

        @transaction_script
        pub proc main
            {check_note_0}

            {check_note_1}

            {check_note_2}
        end
    ",
        check_note_0 = check_removed_assets_code(
            0,
            0,
            p2any_note_0_assets.assets().commitment(),
            p2any_note_0_assets.assets().num_assets()
        ),
        check_note_1 = check_removed_assets_code(
            1,
            8,
            p2id_note_1_asset.assets().commitment(),
            p2id_note_1_asset.assets().num_assets()
        ),
        check_note_2 = check_removed_assets_code(
            2,
            16,
            p2id_note_2_assets.assets().commitment(),
            p2id_note_2_assets.assets().num_assets()
        ),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_notes([p2any_note_0_assets, p2id_note_1_asset, p2id_note_2_assets])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Check that a transaction script can take a "fee" out of an input note via
/// `input_note::remove_asset` and consume the remaining assets via
/// `input_note::remove_all_assets`, with the asset conservation check of the epilogue passing.
///
/// The consumed note carries a no-op note script, so the transaction script is responsible for
/// claiming all of the note's assets.
#[tokio::test]
async fn test_remove_asset_from_tx_script() -> anyhow::Result<()> {
    const ASSET_0_AMOUNT: u64 = 100;
    const FEE_AMOUNT: u64 = 30;
    const ASSET_1_AMOUNT: u64 = 10;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let faucet_id_0 = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let faucet_id_1 = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?;
    let asset_0 = Asset::Fungible(FungibleAsset::new(faucet_id_0, ASSET_0_AMOUNT)?);
    let asset_1 = Asset::Fungible(FungibleAsset::new(faucet_id_1, ASSET_1_AMOUNT)?);

    let fee_asset = Asset::Fungible(FungibleAsset::new(faucet_id_0, FEE_AMOUNT)?);
    let remaining_asset =
        Asset::Fungible(FungibleAsset::new(faucet_id_0, ASSET_0_AMOUNT - FEE_AMOUNT)?);

    // a note with a no-op script that does not touch its own assets
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let note = NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, &mut rng)
        .add_assets([asset_0, asset_1])
        .note_type(NoteType::Public)
        .build()?;

    // generate the code receiving each of the assets written to memory into the account
    let mut receive_remaining_assets_code = String::new();
    for asset_index in 0..note.assets().num_assets() {
        receive_remaining_assets_code.push_str(&format!(
            r#"
            # load the asset at index {asset_index} from memory
            push.{asset_ptr} exec.asset::load
            # => [ASSET_ID, ASSET_VALUE]

            padw padw swapdw
            # => [ASSET_ID, ASSET_VALUE, pad(8)]

            call.wallet::receive_asset
            dropw dropw dropw dropw
            # => []
            "#,
            asset_ptr = asset_index * ASSET_SIZE as usize,
        ));
    }

    let code = format!(
        r#"
        use miden::protocol::asset
        use miden::protocol::input_note
        use miden::standards::wallets::basic as wallet

        @transaction_script
        pub proc main
            # remove the fee asset from note 0
            push.0 push.{FEE_ASSET_VALUE} push.{FEE_ASSET_ID}
            exec.input_note::remove_asset
            # => [FINAL_ASSET_VALUE]

            push.{REMAINING_ASSET_VALUE}
            assert_eqw.err="unexpected value remaining in the note after fee removal"
            # => []

            # receive the fee asset into the account
            push.{FEE_ASSET_VALUE} push.{FEE_ASSET_ID}
            padw padw swapdw
            call.wallet::receive_asset
            dropw dropw dropw dropw
            # => []

            # remove the remaining assets from note 0 and write them to memory address 0
            push.0 push.0
            exec.input_note::remove_all_assets
            # => [num_assets]

            push.{NUM_REMAINING_ASSETS}
            assert_eq.err="unexpected number of assets remaining in the note"
            # => []

            # receive the remaining assets into the account
            {receive_remaining_assets_code}
        end
    "#,
        FEE_ASSET_ID = fee_asset.to_id_word(),
        FEE_ASSET_VALUE = fee_asset.to_value_word(),
        REMAINING_ASSET_VALUE = remaining_asset.to_value_word(),
        NUM_REMAINING_ASSETS = note.assets().num_assets(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let executed_transaction = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(note)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    // all of the note's assets should have ended up in the account's vault
    let added_assets: Vec<Asset> =
        executed_transaction.account_patch().vault().updated_assets().collect();
    assert_eq!(added_assets.len(), 2);
    assert!(added_assets.contains(&asset_0));
    assert!(added_assets.contains(&asset_1));

    Ok(())
}

/// Check that `active_note::get_asset` and `input_note::get_asset` return the same asset for every
/// asset index of a note, and that the returned assets match the note's assets.
///
/// The check is performed from within the note's own script: while that script runs the note is the
/// active note, so `active_note::get_asset` targets it directly, whereas `input_note::get_asset` is
/// called with the note's known input index. Both must agree with each other and with the expected
/// asset. A filler note is consumed first so that the note under test sits at a non-zero index,
/// exercising the `note_index` parameter of the input note API.
#[tokio::test]
async fn test_get_asset_from_active_and_input_note() -> anyhow::Result<()> {
    // the note under test is consumed at index 1, after the filler note at index 0
    const NOTE_INDEX: u8 = 1;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let faucet_id_0 = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let faucet_id_1 = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?;
    let asset_0 = Asset::Fungible(FungibleAsset::new(faucet_id_0, 100)?);
    let asset_1 = Asset::Fungible(FungibleAsset::new(faucet_id_1, 50)?);

    // derive the asset order the note will store them in, so the expected asset per index is known
    let ordered_assets: Vec<Asset> =
        NoteAssets::new(vec![asset_0, asset_1])?.iter().copied().collect();

    // for each asset index, query the asset via both APIs and assert they match the expected asset
    let mut checks = String::new();
    for (asset_index, asset) in ordered_assets.iter().enumerate() {
        checks.push_str(&format!(
            r#"
            # active note API: asset at index {asset_index} of the active note (this note)
            push.{asset_index} exec.active_note::get_asset
            # => [ASSET_ID, ASSET_VALUE]

            push.{ASSET_ID}
            assert_eqw.err="active note asset {asset_index} has unexpected id"
            push.{ASSET_VALUE}
            assert_eqw.err="active note asset {asset_index} has unexpected value"
            # => []

            # input note API: the same asset addressed via the note's known input index
            push.{NOTE_INDEX} push.{asset_index} exec.input_note::get_asset
            # => [ASSET_ID, ASSET_VALUE]

            push.{ASSET_ID}
            assert_eqw.err="input note asset {asset_index} has unexpected id"
            push.{ASSET_VALUE}
            assert_eqw.err="input note asset {asset_index} has unexpected value"
            # => []
            "#,
            ASSET_ID = asset.to_id_word(),
            ASSET_VALUE = asset.to_value_word(),
        ));
    }

    let note_code = format!(
        r#"
        use miden::protocol::active_note
        use miden::protocol::input_note
        use miden::standards::wallets::basic as wallet

        @note_script
        pub proc main
            {checks}

            # claim the note's assets into the account so the epilogue conservation check passes
            exec.wallet::add_assets_to_account
        end
    "#
    );

    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let sender = ACCOUNT_ID_SENDER.try_into()?;

    // filler note consumed at index 0; it has no assets and a no-op script
    let filler_note = NoteBuilder::new(sender, &mut rng).note_type(NoteType::Public).build()?;

    let note = NoteBuilder::new(sender, &mut rng)
        .add_assets([asset_0, asset_1])
        .note_type(NoteType::Public)
        .code(note_code)
        .build()?;

    mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_notes([filler_note, note])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Check that `active_note::remove_asset` and `input_note::remove_asset` both fail when the asset
/// cannot be removed from the note.
///
/// The same note is targeted as the active note and by its input index, so both wrappers exercise
/// the shared kernel removal logic and must reject the removal with the same error.
#[rstest]
#[tokio::test]
async fn test_remove_asset_fails(
    #[values(
        "fungible_asset_not_found",
        "fungible_amount_exceeded",
        "non_fungible_wrong_value"
    )]
    scenario: &str,
    #[values(("", "active_note"), ("push.0", "input_note"))] (note_arg, note_module): (&str, &str),
) -> anyhow::Result<()> {
    const FUNGIBLE_AMOUNT: u64 = 100;

    let fungible_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let non_fungible_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1.try_into()?;

    let fungible_asset = Asset::Fungible(FungibleAsset::new(fungible_faucet_id, FUNGIBLE_AMOUNT)?);
    let non_fungible_asset = Asset::NonFungible(NonFungibleAsset::new(
        &NonFungibleAssetDetails::new(non_fungible_faucet_id, vec![1, 2, 3]),
    ));

    let (asset_id, asset_value, expected_err) = match scenario {
        "fungible_asset_not_found" => {
            // an asset from a faucet whose assets are not in the note
            let other_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?;
            let other_asset = Asset::Fungible(FungibleAsset::new(other_faucet_id, 10)?);
            (
                other_asset.to_id_word(),
                other_asset.to_value_word(),
                ERR_INPUT_NOTE_ASSET_TO_REMOVE_NOT_FOUND,
            )
        },
        "fungible_amount_exceeded" => {
            let over_asset =
                Asset::Fungible(FungibleAsset::new(fungible_faucet_id, FUNGIBLE_AMOUNT + 1)?);
            (
                over_asset.to_id_word(),
                over_asset.to_value_word(),
                ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW,
            )
        },
        "non_fungible_wrong_value" => (
            non_fungible_asset.to_id_word(),
            Word::from([9, 9, 9, 9u32]),
            ERR_INPUT_NOTE_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND,
        ),
        other => anyhow::bail!("unknown scenario {other}"),
    };

    // the note is consumed at input index 0: `active_note` targets it directly while `input_note`
    // targets it via that index; both removals must fail identically

    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into()?,
            [fungible_asset, non_fungible_asset],
        );
        TestTransactionBuilder::new(account)
            .extend_input_notes(vec![input_note])
            .build()?
    };

    let code = format!(
        r#"
            use miden::tx_kernel_core::prologue
            use miden::tx_kernel_core::note as note_internal
            use miden::protocol::input_note
            use miden::protocol::active_note

            begin
                exec.prologue::prepare_transaction
                exec.note_internal::prepare_note
                dropw dropw dropw dropw

                # try to remove an asset that cannot be removed from the note
                {note_arg} push.{asset_value} push.{asset_id} exec.{note_module}::remove_asset
            end
            "#,
    );

    let result = tx_context.execute_code(&code).await;
    assert_execution_error!(result, expected_err);

    Ok(())
}

/// Check that `active_note::get_asset` and `input_note::get_asset` both fail for an asset index
/// that is greater or equal to the number of assets in the note.
#[rstest]
#[case::active_note("push.1 exec.active_note::get_asset")]
#[case::input_note("push.0 push.1 exec.input_note::get_asset")]
#[tokio::test]
async fn test_get_asset_index_out_of_bounds(#[case] get_asset_call: &str) -> anyhow::Result<()> {
    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note =
            create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, [FungibleAsset::mock(100)]);
        TestTransactionBuilder::new(account)
            .extend_input_notes(vec![input_note])
            .build()?
    };

    // the note has a single asset, so asset index 1 is out of bounds for both APIs (the input note
    // is at index 0)
    let code = format!(
        r#"
        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::note as note_internal
        use miden::protocol::input_note
        use miden::protocol::active_note

        begin
            exec.prologue::prepare_transaction
            exec.note_internal::prepare_note
            dropw dropw dropw dropw

            {get_asset_call}
            exec.::miden::core::sys::truncate_stack
        end
        "#,
    );

    let result = tx_context.execute_code(&code).await;
    assert_execution_error!(result, ERR_INPUT_NOTE_ASSET_INDEX_OUT_OF_BOUNDS);

    Ok(())
}

/// Check that `remove_asset` supports partial and full removal of assets and that `get_asset`
/// reflects the note's current state after each removal, while the initial assets info stays
/// unchanged.
///
/// The same note is exercised through the `active_note` API (targeting the note directly) and the
/// `input_note` API (targeting it by its input index 0); both must behave identically.
#[rstest]
#[case::active_note("active_note", "")]
#[case::input_note("input_note", "push.0")]
#[tokio::test]
async fn test_remove_asset(
    #[case] note_module: &str,
    #[case] note_arg: &str,
) -> anyhow::Result<()> {
    const FUNGIBLE_AMOUNT: u64 = 100;
    const PARTIAL_AMOUNT: u64 = 30;

    let fungible_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let non_fungible_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1.try_into()?;

    let fungible_asset = Asset::Fungible(FungibleAsset::new(fungible_faucet_id, FUNGIBLE_AMOUNT)?);
    let non_fungible_asset = Asset::NonFungible(NonFungibleAsset::new(
        &NonFungibleAssetDetails::new(non_fungible_faucet_id, vec![1, 2, 3]),
    ));

    let partial_asset = Asset::Fungible(FungibleAsset::new(fungible_faucet_id, PARTIAL_AMOUNT)?);
    let remaining_asset =
        Asset::Fungible(FungibleAsset::new(fungible_faucet_id, FUNGIBLE_AMOUNT - PARTIAL_AMOUNT)?);

    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into()?,
            [fungible_asset, non_fungible_asset],
        );
        TestTransactionBuilder::new(account)
            .extend_input_notes(vec![input_note])
            .build()?
    };

    // derive the indices of the assets from the note's asset order
    let note = tx_context.input_notes().get_note(0).note().clone();
    let note_assets: Vec<Asset> = note.assets().iter().copied().collect();
    let fungible_index = note_assets
        .iter()
        .position(|asset| matches!(asset, Asset::Fungible(_)))
        .context("note should contain a fungible asset")?;
    let non_fungible_index = note_assets
        .iter()
        .position(|asset| matches!(asset, Asset::NonFungible(_)))
        .context("note should contain a non-fungible asset")?;

    let code = format!(
        r#"
        use miden::core::sys

        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::note as note_internal
        use miden::protocol::{note_module}

        # allocate ASSET_SIZE * MAX_ASSETS_PER_NOTE locals as the destination buffer for
        # remove_all_assets; no assets remain by then, but the buffer must fit the maximum
        @locals(512)
        proc process_note
            # drop the note storage
            dropw dropw dropw dropw

            # partially remove the fungible asset
            {note_arg} push.{PARTIAL_VALUE} push.{FUNGIBLE_ID}
            exec.{note_module}::remove_asset
            # => [FINAL_ASSET_VALUE]

            push.{REMAINING_VALUE}
            assert_eqw.err="unexpected value remaining after the partial removal"

            # the asset at the fungible index reflects the reduced value
            {note_arg} push.{fungible_index} exec.{note_module}::get_asset
            # => [ASSET_ID, ASSET_VALUE]

            push.{FUNGIBLE_ID}
            assert_eqw.err="unexpected asset ID after the partial removal"
            push.{REMAINING_VALUE}
            assert_eqw.err="unexpected asset value after the partial removal"

            # fully remove the non-fungible asset
            {note_arg} push.{NON_FUNGIBLE_VALUE} push.{NON_FUNGIBLE_ID}
            exec.{note_module}::remove_asset
            # => [FINAL_ASSET_VALUE]

            padw assert_eqw.err="expected empty value remaining after the full removal"

            # the non-fungible asset's slot is now cleared
            {note_arg} push.{non_fungible_index} exec.{note_module}::get_asset
            # => [ASSET_ID, ASSET_VALUE]

            padw assert_eqw.err="expected empty asset ID after the full removal"
            padw assert_eqw.err="expected empty asset value after the full removal"

            # remove the remainder of the fungible asset
            {note_arg} push.{REMAINING_VALUE} push.{FUNGIBLE_ID}
            exec.{note_module}::remove_asset
            # => [FINAL_ASSET_VALUE]

            padw assert_eqw.err="expected empty value remaining after removing the remainder"

            # the initial assets info is unaffected by the removals
            {note_arg} exec.{note_module}::get_initial_assets_info
            # => [ASSETS_COMMITMENT, num_assets]

            push.{ASSETS_COMMITMENT}
            assert_eqw.err="unexpected initial assets commitment"
            push.2
            assert_eq.err="unexpected initial num assets"

            # no assets remain in the note
            {note_arg} locaddr.0 exec.{note_module}::remove_all_assets
            assertz.err="note should not have any assets left"
        end

        begin
            # prepare tx
            exec.prologue::prepare_transaction

            # prepare the note
            exec.note_internal::prepare_note

            # process the note
            call.process_note

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        FUNGIBLE_ID = fungible_asset.to_id_word(),
        PARTIAL_VALUE = partial_asset.to_value_word(),
        REMAINING_VALUE = remaining_asset.to_value_word(),
        NON_FUNGIBLE_ID = non_fungible_asset.to_id_word(),
        NON_FUNGIBLE_VALUE = non_fungible_asset.to_value_word(),
        ASSETS_COMMITMENT = note.assets().commitment(),
    );

    tx_context.execute_code(&code).await?;
    Ok(())
}

/// Check that the number of the storage items and their commitment of a note with one asset
/// obtained from the `input_note::get_storage_info` procedure is correct.
#[tokio::test]
async fn test_get_storage_info() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        @transaction_script
        pub proc main
            # get the storage commitment and length from the input note with index 0 (the only one
            # we have)
            push.0
            exec.input_note::get_storage_info
            # => [NOTE_STORAGE_COMMITMENT, num_storage_items]

            # assert the correctness of the storage commitment
            push.{STORAGE_COMMITMENT}
            assert_eqw.err="note 0 has incorrect storage commitment"
            # => [num_storage_items]

            # assert the storage has correct length
            push.{num_storage_items}
            assert_eq.err="note 0 has incorrect number of storage items"
            # => []
        end
    "#,
        STORAGE_COMMITMENT = p2id_note_1_asset.storage().commitment(),
        num_storage_items = p2id_note_1_asset.storage().num_items(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note_1_asset])?
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Check that the script root of a note with one asset obtained from the
/// `input_note::get_script_root` procedure is correct.
#[tokio::test]
async fn test_get_script_root() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        @transaction_script
        pub proc main
            # get the script root from the input note with index 0 (the only one we have)
            push.0
            exec.input_note::get_script_root
            # => [SCRIPT_ROOT]

            # assert the correctness of the script root
            push.{SCRIPT_ROOT}
            assert_eqw.err="note 0 has incorrect script root"
            # => []
        end
    "#,
        SCRIPT_ROOT = p2id_note_1_asset.script().root(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note_1_asset])?
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Check that the serial number of a note with one asset obtained from the
/// `input_note::get_serial_number` procedure is correct.
#[tokio::test]
async fn test_get_serial_number() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        @transaction_script
        pub proc main
            # get the serial number from the input note with index 0 (the only one we have)
            push.0
            exec.input_note::get_serial_number
            # => [SERIAL_NUMBER]

            # assert the correctness of the serial number
            push.{SERIAL_NUMBER}
            assert_eqw.err="note 0 has incorrect serial number"
            # => []
        end
    "#,
        SERIAL_NUMBER = p2id_note_1_asset.serial_num(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note_1_asset])?
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}
