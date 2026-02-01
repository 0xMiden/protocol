use anyhow::Result;
use miden_protocol::Word;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::OutputNote;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain, TransactionContext};

/// Returns the transaction context which could be used to run the transaction which creates a
/// single P2ID note.
pub fn tx_create_single_p2id_note() -> Result<TransactionContext> {
    let mut builder = MockChain::builder();
    let fungible_asset = FungibleAsset::mock(150);
    let account = builder.add_existing_wallet_with_assets(Auth::BasicAuth, [fungible_asset])?;

    let output_note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset],
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    let tx_note_creation_script = format!(
        "
        use miden::protocol::output_note
        use miden::core::sys

        begin
            # create an output note with fungible asset
            push.{RECIPIENT}
            push.{note_type}
            push.{tag}
            exec.output_note::create
            # => [note_idx]

            # move the asset to the note
            push.{asset}
            call.::miden::standards::wallets::basic::move_asset_to_note
            dropw
            # => [note_idx]

            # truncate the stack
            exec.sys::truncate_stack
        end
        ",
        RECIPIENT = output_note.recipient().digest(),
        note_type = NoteType::Public as u8,
        tag = output_note.metadata().tag(),
        asset = Word::from(fungible_asset),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_note_creation_script)?;

    // construct the transaction context
    mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .tx_script(tx_script)
        .disable_debug_mode()
        .build()
}

/// Returns the transaction context which could be used to run the transaction which consumes a
/// single P2ID note into a new basic wallet.
pub fn tx_consume_single_p2id_note() -> Result<TransactionContext> {
    // Create assets
    let fungible_asset: Asset = FungibleAsset::mock(123);

    let mut builder = MockChain::builder();

    // Create target account
    let target_account = builder.create_new_wallet(Auth::BasicAuth)?;

    // Create the note
    let note = builder
        .add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            target_account.id(),
            &[fungible_asset],
            NoteType::Public,
        )
        .unwrap();

    let mock_chain = builder.build()?;

    // construct the transaction context
    mock_chain
        .build_tx_context(target_account.clone(), &[note.id()], &[])?
        .disable_debug_mode()
        .build()
}

/// Returns the transaction context which could be used to run the transaction which consumes two
/// P2ID notes into an existing basic wallet.
pub fn tx_consume_two_p2id_notes() -> Result<TransactionContext> {
    let mut builder = MockChain::builder();

    let account = builder.add_existing_wallet(Auth::BasicAuth)?;
    let fungible_asset_1: Asset = FungibleAsset::mock(100);
    let fungible_asset_2: Asset = FungibleAsset::mock(23);

    let note_1 = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset_1],
        NoteType::Private,
    )?;
    let note_2 = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset_2],
        NoteType::Private,
    )?;

    let mock_chain = builder.build()?;

    // construct the transaction context
    mock_chain
        .build_tx_context(account.id(), &[note_1.id(), note_2.id()], &[])?
        .disable_debug_mode()
        .build()
}
