use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::ExecutionError;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::errors::protocol::ERR_INPUT_NOTE_INDEX_LOOKUP_INVALID;
use miden_protocol::errors::tx_kernel::{
    ERR_ACCOUNT_IS_NOT_NATIVE,
    ERR_FUNGIBLE_ASSET_VALUE_MOST_SIGNIFICANT_ELEMENTS_MUST_BE_ZERO,
    ERR_INPUT_NOTE_ASSET_ID_TO_REMOVE_IS_EMPTY,
    ERR_INPUT_NOTE_ASSET_INDEX_OUT_OF_BOUNDS,
    ERR_INPUT_NOTE_ASSET_TO_REMOVE_NOT_FOUND,
    ERR_INPUT_NOTE_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND,
    ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW,
};
use miden_protocol::note::{Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::memory::ASSET_SIZE;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::{TransactionExecutorError, TransactionKernelError};
use rstest::rstest;

use super::{ExecutionOutputExt, TestSetup, setup_test};
use crate::utils::create_public_p2any_note;
use crate::{
    Auth,
    MockChain,
    MockChainBuilder,
    MockTransaction,
    TestTransactionBuilder,
    assert_execution_error,
    assert_transaction_executor_error,
};

const P2ID_INPUT_NOTE_INDEX: u8 = 1;
const STOLEN_ASSET_PTR: u32 = 1024;

fn assert_rejected_by_account_origin_auth(
    result: Result<ExecutedTransaction, TransactionExecutorError>,
) {
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if matches!(
                event_err.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::UnknownAccountProcedure(_))
            )
    );
}

fn build_victim_p2id_note(target: AccountId, asset: Asset) -> anyhow::Result<Note> {
    Ok(P2idNote::builder()
        .sender(ACCOUNT_ID_SENDER.try_into()?)
        .target(target)
        .asset(asset)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([2, 2, 2, 2u32])))
        .build()
        .map(Note::from)?)
}

fn build_attacker_output_note(sender: AccountId, asset: Asset) -> anyhow::Result<Note> {
    Ok(NoteBuilder::new(sender, RandomCoin::new(Word::from([3, 3, 3, 3u32])))
        .note_type(NoteType::Public)
        .add_assets([asset])
        .build()?)
}

fn build_malicious_note(code: String) -> anyhow::Result<Note> {
    Ok(NoteBuilder::new(
        ACCOUNT_ID_SENDER.try_into()?,
        RandomCoin::new(Word::from([1, 1, 1, 1u32])),
    )
    .note_type(NoteType::Public)
    .code(code)
    .dynamically_linked_packages(CodeBuilder::mock_packages())
    .build()?)
}

/// A transaction consuming a bare note (note 0: no assets, no attachments) and a rich note
/// (note 1: an asset and two attachments), covering the empty and non-empty commitment branches.
fn two_note_tx() -> anyhow::Result<MockTransaction> {
    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));

    let bare_note = NoteBuilder::new(account.id(), &mut rng).build()?;
    let rich_note = NoteBuilder::new(account.id(), &mut rng)
        .note_type(NoteType::Public)
        .add_assets(vec![FungibleAsset::mock(150)])
        .attachment(NoteAttachment::with_word(
            NoteAttachmentScheme::new(10)?,
            Word::from([3, 4, 5, 6u32]),
        ))
        .attachment(NoteAttachment::with_word(
            NoteAttachmentScheme::new(20)?,
            Word::from([7, 8, 9, 10u32]),
        ))
        .build()?;

    TestTransactionBuilder::new(account)
        .input_notes(vec![bare_note, rich_note])
        .build()
}

/// A note's ID read from MASM must match `Note::id()` in Rust through both the indexed and active
/// note accessors.
#[rstest]
#[tokio::test]
async fn active_and_input_note_id_matches_rust(
    #[values(0, 1, 2)] note_index: u8,
    #[values("active_note", "input_note")] module: &str,
) -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets,
        p2id_note_1_asset,
        p2id_note_2_assets,
    } = setup_test()?;
    let input_notes = [p2any_note_0_assets, p2id_note_1_asset, p2id_note_2_assets];
    let expected_note_id = input_notes[note_index as usize].id();
    let mock_tx = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_notes(input_notes)
        .build()?;

    // The input variant takes the note index from the stack; the active variant reads the active
    // note, so the test points the active-note pointer at the note under test instead.
    let setup_code = if module == "active_note" {
        format!(
            "push.{note_index} exec.memory::get_input_note_ptr exec.memory::set_active_input_note_ptr"
        )
    } else {
        format!("push.{note_index}")
    };

    let code = format!(
        r#"
        use miden::tx_kernel_core::memory
        use miden::tx_kernel_core::prologue
        use miden::protocol::{module}

        begin
            exec.prologue::prepare_transaction

            {setup_code}
            exec.{module}::get_note_id
            # => [NOTE_ID]

            # truncate the stack
            swapw dropw
        end
        "#
    );

    let exec_output = mock_tx.execute_code(&code).await?;
    assert_eq!(exec_output.get_stack_word(0), expected_note_id.as_word());

    Ok(())
}

/// Finding an input note by its ID returns the note's index; both fixture notes must be found at
/// their own index.
#[rstest]
#[tokio::test]
async fn find_note_returns_index(#[values(0, 1)] note_index: u8) -> anyhow::Result<()> {
    let mock_tx = two_note_tx()?;
    let note_id = mock_tx.input_notes().get_note(note_index as usize).note().id();

    let code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::input_note
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction

            push.{note_id}
            exec.input_note::find_note
            # => [is_found, note_idx]

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        note_id = note_id.as_word(),
    );

    let exec_output = mock_tx.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), Word::from([1, note_index as u32, 0, 0]));

    Ok(())
}

/// An ID that matches no input note reports is_found = 0.
#[tokio::test]
async fn find_note_reports_missing_note() -> anyhow::Result<()> {
    let mock_tx = two_note_tx()?;
    let unknown_id = Word::from([11, 12, 13, 14u32]);

    let code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::input_note
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction

            push.{unknown_id}
            exec.input_note::find_note
            # => [is_found, note_idx]

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#
    );

    let exec_output = mock_tx.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), Word::empty());

    Ok(())
}

/// Invalid host claims are rejected: a reported match must identify the requested note, and a
/// reported miss must survive a full scan of all input notes.
#[rstest]
#[case::incorrect_match([Felt::ONE, Felt::ONE])]
#[case::incorrect_miss([Felt::ZERO, Felt::ZERO])]
#[tokio::test]
async fn find_note_rejects_invalid_host_claim(#[case] response: [Felt; 2]) -> anyhow::Result<()> {
    let mock_tx = two_note_tx()?;
    let note_id = mock_tx.input_notes().get_note(0).note().id();
    let code = format!(
        r#"
        use miden::protocol::input_note
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction

            push.{note_id}
            exec.input_note::find_note
        end
        "#,
        note_id = note_id.as_word(),
    );

    let result = mock_tx.execute_code_with_input_note_index_response(&code, response).await;

    assert_execution_error!(result, ERR_INPUT_NOTE_INDEX_LOOKUP_INVALID);

    Ok(())
}

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

    // give each note a disjoint 16-element memory region, enough for the two assets of the
    // largest note
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

    let mock_tx = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(p2id_note_1_asset)
        .tx_script(tx_script)
        .build()?;

    mock_tx.execute().await?;

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

    let mock_tx = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(p2id_note_1_asset)
        .tx_script(tx_script)
        .build()?;

    mock_tx.execute().await?;

    Ok(())
}

/// Check that notes whose assets were removed by their note scripts have empty current asset slots,
/// while their initial assets info stays unchanged.
#[tokio::test]
async fn test_assets_removed_after_note_scripts() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2any_note_0_assets,
        p2id_note_1_asset,
        p2id_note_2_assets,
    } = setup_test()?;

    fn check_removed_assets_code(note_index: u8, note: &Note) -> String {
        let mut check_current_assets = String::new();
        for asset_index in 0..note.assets().num_assets() {
            check_current_assets.push_str(&format!(
                r#"
                # the note script removed this asset, so its current slot must be empty
                push.{note_index} push.{asset_index}
                exec.input_note::get_asset
                # => [ASSET_ID, ASSET_VALUE]

                padw assert_eqw.err="note {note_index} asset {asset_index} ID was not removed"
                padw assert_eqw.err="note {note_index} asset {asset_index} value was not removed"
                # => []
                "#,
            ));
        }

        format!(
            r#"
            {check_current_assets}

            # assert the initial assets info is unaffected by the removals
            push.{note_index}
            exec.input_note::get_initial_assets_info
            # => [ASSETS_COMMITMENT, num_assets]

            push.{assets_commitment}
            assert_eqw.err="note {note_index} has incorrect initial assets hash"
            push.{assets_number}
            assert_eq.err="note {note_index} has incorrect initial assets number"
            # => []
        "#,
            assets_commitment = note.assets().commitment(),
            assets_number = note.assets().num_assets(),
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
        check_note_0 = check_removed_assets_code(0, &p2any_note_0_assets),
        check_note_1 = check_removed_assets_code(1, &p2id_note_1_asset),
        check_note_2 = check_removed_assets_code(2, &p2id_note_2_assets),
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

/// A malicious note cannot move assets from a later P2ID note by removing them from the P2ID note
/// by index and moving them into an attacker-controlled output note.
#[tokio::test]
async fn test_malicious_note_cannot_remove_asset_from_later_p2id_note() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let p2id_asset = FungibleAsset::mock(100);
    let p2id_note = build_victim_p2id_note(account.id(), p2id_asset)?;
    let attacker_output_note = build_attacker_output_note(account.id(), p2id_asset)?;

    let malicious_note_code = format!(
        r#"
        use miden::protocol::input_note
        use miden::protocol::output_note
        use miden::core::sys

        @note_script
        pub proc main
            # This malicious note is input note 0. The victim's P2ID note is input note 1.
            push.{p2id_note_index}
            push.{asset_value}
            push.{asset_id}
            exec.input_note::remove_asset
            # => [remaining_asset]
            dropw

            # If the indexed removal above were allowed, create an attacker-controlled output note.
            push.{recipient}
            push.{note_type}
            push.{tag}
            call.::mock::account::create_note
            # => [note_idx, pad(15)]

            # Move the asset stolen from the P2ID note into the attacker's output note.
            push.{asset_value}
            push.{asset_id}
            exec.output_note::add_asset
            exec.sys::truncate_stack
        end
    "#,
        asset_id = p2id_asset.to_id_word(),
        asset_value = p2id_asset.to_value_word(),
        p2id_note_index = P2ID_INPUT_NOTE_INDEX,
        recipient = attacker_output_note.recipient().digest(),
        note_type = attacker_output_note.metadata().note_type() as u8,
        tag = Felt::from(attacker_output_note.metadata().tag()),
    );

    let malicious_note = build_malicious_note(malicious_note_code)?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_notes([malicious_note, p2id_note])
        .expected_output_note(RawOutputNote::Full(attacker_output_note))
        .build()?
        .execute()
        .await;

    assert_rejected_by_account_origin_auth(result);

    Ok(())
}

/// A malicious note also cannot use the bulk indexed removal API to empty a later P2ID note.
#[tokio::test]
async fn test_malicious_note_cannot_remove_all_assets_from_later_p2id_note() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let p2id_asset = FungibleAsset::mock(100);
    let p2id_note = build_victim_p2id_note(account.id(), p2id_asset)?;
    let attacker_output_note = build_attacker_output_note(account.id(), p2id_asset)?;

    let malicious_note_code = format!(
        r#"
        use miden::protocol::asset
        use miden::protocol::input_note
        use miden::protocol::output_note
        use miden::core::sys

        @note_script
        pub proc main
            # This malicious note is input note 0. The victim's P2ID note is input note 1.
            push.{p2id_note_index}
            push.{stolen_asset_ptr}
            exec.input_note::remove_all_assets
            # => [num_assets]
            push.1 assert_eq

            # If the indexed removal above were allowed, create an attacker-controlled output note.
            push.{recipient}
            push.{note_type}
            push.{tag}
            call.::mock::account::create_note
            # => [note_idx, pad(15)]

            # Move the asset stolen from the P2ID note into the attacker's output note.
            push.{stolen_asset_ptr}
            exec.asset::load
            exec.output_note::add_asset
            exec.sys::truncate_stack
        end
    "#,
        p2id_note_index = P2ID_INPUT_NOTE_INDEX,
        recipient = attacker_output_note.recipient().digest(),
        stolen_asset_ptr = STOLEN_ASSET_PTR,
        note_type = attacker_output_note.metadata().note_type() as u8,
        tag = Felt::from(attacker_output_note.metadata().tag()),
    );

    let malicious_note = build_malicious_note(malicious_note_code)?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_notes([malicious_note, p2id_note])
        .expected_output_note(RawOutputNote::Full(attacker_output_note))
        .build()?
        .execute()
        .await;

    assert_rejected_by_account_origin_auth(result);

    Ok(())
}

/// The account-origin check resolves the caller against the *active* account, so on its own it
/// would let a malicious note reach indexed removal through an attacker-controlled foreign account:
/// inside the FPI context that foreign account is active and vouches for its own procedures. The
/// native account check closes that path, keeping indexed removal available only to the account the
/// transaction is executed against.
#[tokio::test]
async fn test_malicious_note_cannot_remove_assets_via_foreign_account() -> anyhow::Result<()> {
    let stolen_asset = FungibleAsset::mock(100);

    let foreign_account_component = AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "foreign_account",
            "
            use miden::protocol::input_note

            @account_procedure
            pub proc drain
                exec.input_note::remove_asset
            end
            ",
        )?,
        Vec::new(),
        AccountComponentMetadata::mock("foreign_account"),
    )?;

    let foreign_account = AccountBuilder::new(rand::random())
        .with_components(Auth::IncrNonce)
        .with_component(foreign_account_component.clone())
        .build_existing()?;

    let native_account = AccountBuilder::new(rand::random())
        .with_components(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .account_type(AccountType::Public)
        .build_existing()?;

    let victim_note = build_victim_p2id_note(native_account.id(), stolen_asset)?;
    let attacker_output_note = build_attacker_output_note(native_account.id(), stolen_asset)?;

    let malicious_note_code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::output_note
        use miden::protocol::tx

        @note_script
        pub proc main
            # This malicious note is input note 0. The victim's P2ID note is input note 1.
            # Route the indexed removal through the attacker's foreign account, which is the
            # active account for the duration of the FPI call.
            padw push.0.0.0
            push.{p2id_note_index}
            push.{asset_value}
            push.{asset_id}
            procref.::foreign_account::drain
            push.{foreign_prefix} push.{foreign_suffix}
            exec.tx::execute_foreign_procedure
            dropw
            exec.sys::truncate_stack

            # If the removal above were allowed, create an attacker-controlled output note and
            # move the stolen asset into it.
            push.{recipient}
            push.{note_type}
            push.{tag}
            call.::mock::account::create_note
            # => [note_idx, pad(15)]

            push.{asset_value}
            push.{asset_id}
            exec.output_note::add_asset
            exec.sys::truncate_stack
        end
    "#,
        asset_id = stolen_asset.to_id_word(),
        asset_value = stolen_asset.to_value_word(),
        p2id_note_index = P2ID_INPUT_NOTE_INDEX,
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        recipient = attacker_output_note.recipient().digest(),
        note_type = attacker_output_note.metadata().note_type() as u8,
        tag = Felt::from(attacker_output_note.metadata().tag()),
    );

    let malicious_note_script = CodeBuilder::with_mock_packages()
        .with_dynamically_linked_package(foreign_account_component.component_code())?
        .compile_note_script(malicious_note_code)?;

    let malicious_note = NoteBuilder::new(
        ACCOUNT_ID_SENDER.try_into()?,
        RandomCoin::new(Word::from([1, 1, 1, 1u32])),
    )
    .note_type(NoteType::Public)
    .script(malicious_note_script)
    .build()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    let foreign_account_inputs = mock_chain
        .get_foreign_account_inputs(foreign_account.id())
        .expect("foreign account inputs should be available");

    let result = mock_chain
        .build_transaction(native_account.id())
        .unauthenticated_input_notes([malicious_note, victim_note])
        .foreign_accounts(vec![foreign_account_inputs])
        .expected_output_note(RawOutputNote::Full(attacker_output_note))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_NATIVE);

    Ok(())
}

/// Transaction scripts run outside the account context, so the account-origin gate on indexed
/// input-note asset removal rejects them as well. This intentionally retires the previously
/// supported pattern of a transaction script taking assets out of an input note by index;
/// indexed removal on behalf of a transaction now requires a procedure of the native account (as
/// the fee manager does for sponsorship notes, from its auth procedure).
#[rstest]
#[tokio::test]
async fn test_tx_script_cannot_remove_input_note_assets_by_index(
    #[values("remove_asset", "remove_all_assets")] removal_call: &str,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let asset = FungibleAsset::mock(100);

    // a note with a no-op script that does not touch its own assets
    let note = NoteBuilder::new(
        ACCOUNT_ID_SENDER.try_into()?,
        RandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )
    .note_type(NoteType::Public)
    .add_assets([asset])
    .build()?;

    let removal_code = match removal_call {
        "remove_asset" => format!(
            "push.0 push.{asset_value} push.{asset_id} exec.input_note::remove_asset dropw",
            asset_id = asset.to_id_word(),
            asset_value = asset.to_value_word(),
        ),
        "remove_all_assets" => {
            format!("push.0 push.{STOLEN_ASSET_PTR} exec.input_note::remove_all_assets drop")
        },
        other => anyhow::bail!("unknown removal call {other}"),
    };

    let code = format!(
        r#"
        use miden::protocol::input_note

        @transaction_script
        pub proc main
            # attempt to remove assets from input note 0 by index from the tx script context
            {removal_code}
        end
    "#
    );

    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let result = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(note)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_rejected_by_account_origin_auth(result);

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
    let asset_0 = Asset::from(FungibleAsset::new(faucet_id_0, 100)?);
    let asset_1 = Asset::from(FungibleAsset::new(faucet_id_1, 50)?);

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
            exec.wallet::move_note_assets_to_account
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

/// Check that `active_note::remove_asset` fails when the asset cannot be removed from the note.
#[rstest]
#[tokio::test]
async fn test_remove_asset_fails(
    #[values(
        "fungible_asset_not_found",
        "fungible_amount_exceeded",
        "fungible_non_canonical_value",
        "non_fungible_wrong_value"
    )]
    scenario: &str,
) -> anyhow::Result<()> {
    const FUNGIBLE_AMOUNT: u64 = 100;

    let fungible_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let non_fungible_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1.try_into()?;

    let fungible_asset = Asset::from(FungibleAsset::new(fungible_faucet_id, FUNGIBLE_AMOUNT)?);
    let non_fungible_asset = Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        non_fungible_faucet_id,
        vec![1, 2, 3],
    )));

    let (asset_id, asset_value, expected_err) = match scenario {
        "fungible_asset_not_found" => {
            // an asset from a faucet whose assets are not in the note
            let other_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?;
            let other_asset = Asset::from(FungibleAsset::new(other_faucet_id, 10)?);
            (
                other_asset.to_id_word(),
                other_asset.to_value_word(),
                ERR_INPUT_NOTE_ASSET_TO_REMOVE_NOT_FOUND,
            )
        },
        "fungible_amount_exceeded" => {
            let over_asset =
                Asset::from(FungibleAsset::new(fungible_faucet_id, FUNGIBLE_AMOUNT + 1)?);
            (
                over_asset.to_id_word(),
                over_asset.to_value_word(),
                ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW,
            )
        },
        "fungible_non_canonical_value" => {
            // regression for audit finding L-03 (#3591): the amount limb matches the note's full
            // amount, but a non-zero upper limb makes the value non-canonical.
            (
                fungible_asset.to_id_word(),
                Word::new([Felt::new(FUNGIBLE_AMOUNT)?, Felt::ONE, Felt::ZERO, Felt::ZERO]),
                ERR_FUNGIBLE_ASSET_VALUE_MOST_SIGNIFICANT_ELEMENTS_MUST_BE_ZERO,
            )
        },
        "non_fungible_wrong_value" => (
            non_fungible_asset.to_id_word(),
            Word::from([9, 9, 9, 9u32]),
            ERR_INPUT_NOTE_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND,
        ),
        other => anyhow::bail!("unknown scenario {other}"),
    };

    let mock_tx = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into()?,
            [fungible_asset, non_fungible_asset],
        );
        TestTransactionBuilder::new(account).input_note(input_note).build()?
    };

    let code = format!(
        r#"
            use miden::tx_kernel_core::prologue
            use miden::tx_kernel_core::note as note_internal
            use miden::protocol::active_note

            begin
                exec.prologue::prepare_transaction
                exec.note_internal::prepare_note
                dropw dropw dropw dropw

                # try to remove an asset that cannot be removed from the note
                push.{asset_value} push.{asset_id} exec.active_note::remove_asset
            end
            "#,
    );

    let result = mock_tx.execute_code(&code).await;
    assert_execution_error!(result, expected_err);

    Ok(())
}

/// Check that `active_note::remove_asset` rejects the empty asset ID, even when the note has a
/// slot that was already cleared by a prior full removal. Without this guard, the empty ID
/// wrongly matches a cleared (EMPTY_WORD, EMPTY_WORD) slot and the removal call, which should
/// panic, would instead succeed (OpenZeppelin audit finding L-04).
#[tokio::test]
async fn test_remove_asset_rejects_empty_asset_id() -> anyhow::Result<()> {
    let fungible_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let fungible_asset = Asset::from(FungibleAsset::new(fungible_faucet_id, 100)?);

    let mock_tx = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note = create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, [fungible_asset]);
        TestTransactionBuilder::new(account).input_note(input_note).build()?
    };

    let code = format!(
        r#"
            use miden::tx_kernel_core::prologue
            use miden::tx_kernel_core::note as note_internal
            use miden::protocol::active_note

            begin
                exec.prologue::prepare_transaction
                exec.note_internal::prepare_note
                dropw dropw dropw dropw

                # fully remove the asset, clearing its slot to (EMPTY_WORD, EMPTY_WORD)
                push.{asset_value} push.{asset_id} exec.active_note::remove_asset
                dropw

                # the empty asset ID must not match the now-cleared slot
                padw padw exec.active_note::remove_asset
            end
            "#,
        asset_id = fungible_asset.to_id_word(),
        asset_value = fungible_asset.to_value_word(),
    );

    let result = mock_tx.execute_code(&code).await;
    assert_execution_error!(result, ERR_INPUT_NOTE_ASSET_ID_TO_REMOVE_IS_EMPTY);

    Ok(())
}

/// Check that `active_note::get_asset` and `input_note::get_asset` both fail for an asset index
/// that is greater or equal to the number of assets in the note.
#[rstest]
#[case::active_note("push.1 exec.active_note::get_asset")]
#[case::input_note("push.0 push.1 exec.input_note::get_asset")]
#[tokio::test]
async fn test_get_asset_index_out_of_bounds(#[case] get_asset_call: &str) -> anyhow::Result<()> {
    let mock_tx = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note =
            create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, [FungibleAsset::mock(100)]);
        TestTransactionBuilder::new(account).input_note(input_note).build()?
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

    let result = mock_tx.execute_code(&code).await;
    assert_execution_error!(result, ERR_INPUT_NOTE_ASSET_INDEX_OUT_OF_BOUNDS);

    Ok(())
}

/// Check that active-note asset removal supports partial and full removal and that `get_asset`
/// reflects the note's current state, while the initial assets info stays unchanged.
#[tokio::test]
async fn test_remove_asset() -> anyhow::Result<()> {
    const FUNGIBLE_AMOUNT: u64 = 100;
    const PARTIAL_AMOUNT: u64 = 30;

    let fungible_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let non_fungible_faucet_id: AccountId = ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1.try_into()?;

    let fungible_asset = Asset::from(FungibleAsset::new(fungible_faucet_id, FUNGIBLE_AMOUNT)?);
    let non_fungible_asset = Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        non_fungible_faucet_id,
        vec![1, 2, 3],
    )));

    let partial_asset = Asset::from(FungibleAsset::new(fungible_faucet_id, PARTIAL_AMOUNT)?);
    let remaining_asset =
        Asset::from(FungibleAsset::new(fungible_faucet_id, FUNGIBLE_AMOUNT - PARTIAL_AMOUNT)?);

    let mock_tx = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into()?,
            [fungible_asset, non_fungible_asset],
        );
        TestTransactionBuilder::new(account).input_note(input_note).build()?
    };

    // derive the indices of the assets from the note's asset order
    let note = mock_tx.input_notes().get_note(0).note().clone();
    let note_assets: Vec<Asset> = note.assets().iter().copied().collect();
    let fungible_index = note_assets
        .iter()
        .position(|asset| asset.is_fungible())
        .context("note should contain a fungible asset")?;
    let non_fungible_index = note_assets
        .iter()
        .position(|asset| asset.is_non_fungible())
        .context("note should contain a non-fungible asset")?;

    let code = format!(
        r#"
        use miden::core::sys

        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::note as note_internal
        use miden::protocol::active_note

        # allocate ASSET_SIZE * MAX_ASSETS_PER_NOTE locals as the destination buffer for
        # remove_all_assets; no assets remain by then, but the buffer must fit the maximum
        @locals(128)
        proc process_note
            # drop the note storage
            dropw dropw dropw dropw

            # partially remove the fungible asset
            push.{PARTIAL_VALUE} push.{FUNGIBLE_ID}
            exec.active_note::remove_asset
            # => [FINAL_ASSET_VALUE]

            push.{REMAINING_VALUE}
            assert_eqw.err="unexpected value remaining after the partial removal"

            # the asset at the fungible index reflects the reduced value
            push.{fungible_index} exec.active_note::get_asset
            # => [ASSET_ID, ASSET_VALUE]

            push.{FUNGIBLE_ID}
            assert_eqw.err="unexpected asset ID after the partial removal"
            push.{REMAINING_VALUE}
            assert_eqw.err="unexpected asset value after the partial removal"

            # fully remove the non-fungible asset
            push.{NON_FUNGIBLE_VALUE} push.{NON_FUNGIBLE_ID}
            exec.active_note::remove_asset
            # => [FINAL_ASSET_VALUE]

            padw assert_eqw.err="expected empty value remaining after the full removal"

            # the non-fungible asset's slot is now cleared
            push.{non_fungible_index} exec.active_note::get_asset
            # => [ASSET_ID, ASSET_VALUE]

            padw assert_eqw.err="expected empty asset ID after the full removal"
            padw assert_eqw.err="expected empty asset value after the full removal"

            # remove the remainder of the fungible asset
            push.{REMAINING_VALUE} push.{FUNGIBLE_ID}
            exec.active_note::remove_asset
            # => [FINAL_ASSET_VALUE]

            padw assert_eqw.err="expected empty value remaining after removing the remainder"

            # the initial assets info is unaffected by the removals
            exec.active_note::get_initial_assets_info
            # => [ASSETS_COMMITMENT, num_assets]

            push.{ASSETS_COMMITMENT}
            assert_eqw.err="unexpected initial assets commitment"
            push.2
            assert_eq.err="unexpected initial num assets"

            # no assets remain in the note
            locaddr.0 exec.active_note::remove_all_assets
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

    mock_tx.execute_code(&code).await?;
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

    let mock_tx = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(p2id_note_1_asset)
        .tx_script(tx_script)
        .build()?;

    mock_tx.execute().await?;

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

    let mock_tx = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(p2id_note_1_asset)
        .tx_script(tx_script)
        .build()?;

    mock_tx.execute().await?;

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

    let mock_tx = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(p2id_note_1_asset)
        .tx_script(tx_script)
        .build()?;

    mock_tx.execute().await?;

    Ok(())
}
