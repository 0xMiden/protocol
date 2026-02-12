use alloc::string::String;

use miden_protocol::Word;
use miden_protocol::note::Note;
use miden_standards::code_builder::CodeBuilder;

use super::{TestSetup, setup_test};
use crate::TxContextInput;

/// Check that the assets number and assets commitment obtained from the
/// `input_note::get_assets_info` procedure is correct for each note with zero, one and two
/// different assets.
#[tokio::test]
async fn test_get_asset_info() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2id_note_0_assets,
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
            exec.input_note::get_assets_info
            # => [ASSETS_COMMITMENT, num_assets]

            # assert the correctness of the assets hash
            push.{assets_commitment}
            assert_eqw.err="note {note_index} has incorrect assets hash"
            # => [num_assets]

            # assert the number of note assets
            push.{assets_number}
            assert_eq.err="note {note_index} has incorrect assets number"
            # => []
        "#
        )
    }

    let code = format!(
        "
        use miden::protocol::input_note

        begin
            {check_note_0}

            {check_note_1}

            {check_note_2}
        end
    ",
        check_note_0 = check_asset_info_code(
            0,
            p2id_note_0_assets.assets().commitment(),
            p2id_note_0_assets.assets().num_assets()
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

    let tx_context = mock_chain
        .build_tx_context(
            TxContextInput::AccountId(account.id()),
            &[],
            &[p2id_note_0_assets, p2id_note_1_asset, p2id_note_2_assets],
        )?
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Check that recipient and metadata of a note with one asset obtained from the
/// `input_note::get_recipient` and `input_note::get_metadata` procedures are correct.
#[tokio::test]
async fn test_get_recipient_and_metadata() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2id_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        begin
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
            # => [NOTE_ATTACHMENT, METADATA_HEADER]

            push.{NOTE_ATTACHMENT}
            assert_eqw.err="note 0 has incorrect note attachment"
            # => [METADATA_HEADER]

            push.{METADATA_HEADER}
            assert_eqw.err="note 0 has incorrect metadata header"
            # => []
        end
    "#,
        RECIPIENT = p2id_note_1_asset.recipient().digest(),
        METADATA_HEADER = p2id_note_1_asset.metadata().to_header_word(),
        NOTE_ATTACHMENT = p2id_note_1_asset.metadata().to_attachment_word(),
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
        p2id_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        begin
            # get the sender from the input note
            push.0
            exec.input_note::get_sender
            # => [sender_id_prefix, sender_id_suffix]

            # assert the correctness of the prefix
            push.{sender_prefix}
            assert_eq.err="sender id prefix of the note 0 is incorrect"
            # => [sender_id_suffix]

            # assert the correctness of the suffix
            push.{sender_suffix}
            assert_eq.err="sender id suffix of the note 0 is incorrect"
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

/// Check that the assets number and assets data obtained from the `input_note::get_assets`
/// procedure is correct for each note with zero, one and two different assets.
#[tokio::test]
async fn test_get_assets() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2id_note_0_assets,
        p2id_note_1_asset,
        p2id_note_2_assets,
    } = setup_test()?;

    fn check_assets_code(note_index: u8, dest_ptr: u8, note: &Note) -> String {
        let mut check_assets_code = format!(
            r#"
            # push the note index and memory destination pointer
            push.{note_idx} push.{dest_ptr}
            # => [dest_ptr, note_index]

            # write the assets to the memory
            exec.input_note::get_assets
            # => [num_assets, dest_ptr, note_index]

            # assert the number of note assets
            push.{assets_number}
            assert_eq.err="note {note_index} has incorrect assets number"
            # => [dest_ptr, note_index]
        "#,
            note_idx = note_index,
            dest_ptr = dest_ptr,
            assets_number = note.assets().num_assets(),
        );

        // check each asset in the note
        for (asset_index, asset) in note.assets().iter().enumerate() {
            check_assets_code.push_str(&format!(
                r#"
                    # load the asset stored in memory
                    padw dup.4 mem_loadw_be
                    # => [STORED_ASSET, dest_ptr, note_index]

                    # assert the asset
                    push.{NOTE_ASSET}
                    assert_eqw.err="asset {asset_index} of the note {note_index} is incorrect"
                    # => [dest_ptr, note_index]

                    # move the pointer
                    add.4
                    # => [dest_ptr+4, note_index]
                "#,
                NOTE_ASSET = Word::from(*asset),
                asset_index = asset_index,
                note_index = note_index,
            ));
        }

        // drop the final `dest_ptr` and `note_index` from the stack
        check_assets_code.push_str("\ndrop drop");

        check_assets_code
    }

    let code = format!(
        "
        use miden::protocol::input_note

        begin
            {check_note_0}

            {check_note_1}

            {check_note_2}
        end
    ",
        check_note_0 = check_assets_code(0, 0, &p2id_note_0_assets),
        check_note_1 = check_assets_code(1, 4, &p2id_note_1_asset),
        check_note_2 = check_assets_code(2, 8, &p2id_note_2_assets),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(
            TxContextInput::AccountId(account.id()),
            &[],
            &[p2id_note_0_assets, p2id_note_1_asset, p2id_note_2_assets],
        )?
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Check that the number of the storage items and their commitment of a note with one asset
/// obtained from the `input_note::get_storage_info` procedure is correct.
#[tokio::test]
async fn test_get_storage_info() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2id_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        begin
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
        p2id_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        begin
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
        p2id_note_0_assets: _,
        p2id_note_1_asset,
        p2id_note_2_assets: _,
    } = setup_test()?;

    let code = format!(
        r#"
        use miden::protocol::input_note

        begin
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
