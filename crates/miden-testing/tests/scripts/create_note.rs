use std::collections::BTreeMap;

use miden_processor::advice::AdviceInputs;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{Note, NoteAssets, NoteRecipient, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_CREATE_NOTE_ASSETS,
    ERR_CREATE_NOTE_FEE_ASSET,
    ERR_CREATE_NOTE_TARGET,
};
use miden_standards::note::{CreateNote, P2idNote, TxFeeNote};
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
use rstest::rstest;

fn setup(
    note_type: NoteType,
    native_principal: bool,
    fee_amount: Option<u64>,
) -> anyhow::Result<(MockChainBuilder, Account, Account, CreateNote)> {
    let mut builder = MockChain::builder();
    let sender = builder.add_existing_wallet(Auth::IncrNonce)?;
    let passthrough = builder.add_account_from_builder(
        Auth::IncrNonce,
        AccountBuilder::new([42; 32])
            .account_type(AccountType::Public)
            .with_component(BasicWallet),
        AccountState::Exists,
    )?;
    let faucet = if native_principal {
        ACCOUNT_ID_FEE_FAUCET
    } else {
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2
    }
    .try_into()?;
    let output: Note = P2idNote::builder()
        .sender(passthrough.id())
        .target(sender.id())
        .serial_number(builder.rng_mut().draw_word())
        .note_type(note_type)
        .asset(FungibleAsset::new(faucet, 100)?)
        .build()?
        .into();
    let fee = fee_amount.map(|amount| {
        FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into().unwrap(), amount).unwrap()
    });
    let request = CreateNote::new(
        sender.id(),
        builder.rng_mut().draw_word(),
        output,
        fee,
        BlockNumber::from(1),
    )?;
    builder.add_output_note(RawOutputNote::Full(request.note().clone()));
    Ok((builder, sender, passthrough, request))
}

#[rstest]
#[tokio::test]
async fn create_note_preserves_output_and_pays_fee(
    #[values(NoteType::Public, NoteType::Private)] note_type: NoteType,
    #[values(false, true)] native_principal: bool,
    #[values(None, Some(50))] fee_amount: Option<u64>,
) -> anyhow::Result<()> {
    let (builder, _, passthrough, request) = setup(note_type, native_principal, fee_amount)?;
    let chain = builder.build()?;
    let tx = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([request.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(request.output_advice()))
        .build()?
        .execute()
        .await?;
    assert_eq!(tx.output_notes().num_notes(), if fee_amount.is_some() { 2 } else { 1 });
    assert_eq!(tx.output_notes().get_note(0).id(), request.output().id());
    assert_eq!(tx.output_notes().get_note(0).assets(), request.output().assets());
    assert_eq!(tx.output_notes().get_note(0).metadata().sender(), passthrough.id());
    if let Some(amount) = fee_amount {
        let fee = tx.output_notes().get_note(1);
        assert_eq!(fee.metadata().tag(), TxFeeNote::TAG);
        assert_eq!(fee.metadata().note_type(), NoteType::Public);
        assert_eq!(fee.assets().iter().next().unwrap().unwrap_fungible().amount().as_u64(), amount);
    }
    assert!(tx.account_patch().vault().is_empty());
    Ok(())
}

#[tokio::test]
async fn create_note_fee_ids_are_unique_for_concurrent_requests() -> anyhow::Result<()> {
    let (mut builder, sender, passthrough, first) = setup(NoteType::Public, true, Some(50))?;
    let second_output = Note::new(
        first.output().assets().clone(),
        first.output().metadata().into_partial_metadata(),
        NoteRecipient::new(
            builder.rng_mut().draw_word(),
            first.output().script().clone(),
            first.output().storage().clone(),
        ),
    );
    let second = CreateNote::new(
        sender.id(),
        builder.rng_mut().draw_word(),
        second_output,
        first.fee(),
        first.reclaim_height(),
    )?;
    builder.add_output_note(RawOutputNote::Full(second.note().clone()));
    let chain = builder.build()?;
    let mut ids = Vec::new();
    for request in [&first, &second] {
        let tx = chain
            .build_transaction(passthrough.id())
            .authenticated_input_notes([request.note().clone()])
            .extend_advice_inputs(AdviceInputs::default().with_map(request.output_advice()))
            .build()?
            .execute()
            .await?;
        ids.push(tx.output_notes().get_note(1).id());
    }
    assert_ne!(ids[0], ids[1]);
    let tx = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([first.note().clone(), second.note().clone()])
        .extend_advice_inputs(
            AdviceInputs::default()
                .with_map(first.output_advice())
                .with_map(second.output_advice()),
        )
        .build()?
        .execute()
        .await?;
    assert_ne!(tx.output_notes().get_note(1).id(), tx.output_notes().get_note(3).id());
    Ok(())
}

#[tokio::test]
async fn create_note_rejects_other_consumers() -> anyhow::Result<()> {
    let (builder, sender, _, request) = setup(NoteType::Public, false, Some(50))?;
    let chain = builder.build()?;
    let result = chain
        .build_transaction(sender.id())
        .authenticated_input_notes([request.note().clone()])
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_CREATE_NOTE_TARGET);
    Ok(())
}

#[tokio::test]
async fn create_note_rejects_changed_input_assets() -> anyhow::Result<()> {
    let (mut builder, _, passthrough, request) = setup(NoteType::Public, true, Some(50))?;
    let malformed = Note::new(
        NoteAssets::new(vec![FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 151)?.into()])?,
        request.note().metadata().into_partial_metadata(),
        request.note().recipient().clone(),
    );
    builder.add_output_note(RawOutputNote::Full(malformed.clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([malformed])
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_CREATE_NOTE_ASSETS);
    Ok(())
}

#[tokio::test]
async fn create_note_rejects_fee_in_another_asset() -> anyhow::Result<()> {
    let (mut builder, sender, passthrough, valid) = setup(NoteType::Public, false, None)?;
    let request = CreateNote::new(
        sender.id(),
        builder.rng_mut().draw_word(),
        valid.output().clone(),
        Some(FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?, 50)?),
        BlockNumber::from(1),
    )?;
    builder.add_output_note(RawOutputNote::Full(request.note().clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([request.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(request.output_advice()))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_CREATE_NOTE_FEE_ASSET);
    Ok(())
}

#[tokio::test]
async fn create_note_reclaim_returns_all_funding_to_sender() -> anyhow::Result<()> {
    let (builder, sender, _, request) = setup(NoteType::Public, true, Some(50))?;
    let mut chain = builder.build()?;
    chain.prove_next_block()?;
    let tx = chain
        .build_transaction(sender.id())
        .authenticated_input_notes([request.note().clone()])
        .extend_note_args(BTreeMap::from([(request.note().id(), CreateNote::reclaim_args())]))
        .build()?
        .execute()
        .await?;
    assert_eq!(tx.output_notes().num_notes(), 0);
    let assets: Vec<Asset> = tx.account_patch().vault().updated_assets().collect();
    assert_eq!(assets, request.note().assets().as_slice());
    Ok(())
}

#[rstest]
#[tokio::test]
async fn create_note_seals_outputs(#[values(0, 1)] index: u32) -> anyhow::Result<()> {
    let (builder, _, passthrough, request) = setup(NoteType::Public, false, Some(50))?;
    let chain = builder.build()?;
    let script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::protocol::output_note
        @transaction_script
        pub proc main
            push.{index} push.0.0.0.0 push.99
            exec.output_note::add_word_attachment
        end
    "#
    ))?;
    let result = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([request.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(request.output_advice()))
        .tx_script(script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        miden_protocol::errors::tx_kernel::ERR_OUTPUT_NOTE_IS_SEALED
    );
    Ok(())
}

/// A native issuer callback cannot append an attachment before CREATE_NOTE seals its output.
#[tokio::test]
async fn create_note_checks_output_after_asset_callbacks() -> anyhow::Result<()> {
    use miden_protocol::account::AccountComponent;
    use miden_protocol::account::component::AccountComponentMetadata;
    use miden_protocol::asset::AssetCallbacks;
    use miden_standards::errors::standards::ERR_CREATE_NOTE_OUTPUT;

    let mut builder = MockChain::builder();
    let sender = builder.add_existing_wallet(Auth::IncrNonce)?;
    let code = CodeBuilder::default().compile_component_code(
        "tests::create_note_callback",
        r#"
        use miden::protocol::output_note
        @account_procedure
        pub proc on_before_asset_added_to_note
            dropw dropw
            push.1.2.3.4.99
            exec.output_note::add_word_attachment
        end
    "#,
    )?;
    let root = code
        .as_package()
        .get_procedure_root_by_path("tests::create_note_callback::on_before_asset_added_to_note")
        .unwrap();
    let callback = AccountComponent::new(
        code,
        AssetCallbacks::new().on_before_asset_added_to_note(root).into_storage_slots(),
        AccountComponentMetadata::new("tests::create_note_callback"),
    )?;
    let account = builder.add_account_from_builder(
        Auth::IncrNonce,
        AccountBuilder::new([91; 32])
            .account_type(AccountType::Public)
            .with_component(BasicWallet)
            .with_component(callback),
        AccountState::Exists,
    )?;
    let output: Note = P2idNote::builder()
        .sender(account.id())
        .target(sender.id())
        .serial_number(builder.rng_mut().draw_word())
        .note_type(NoteType::Public)
        .asset(FungibleAsset::new(account.id(), 100)?)
        .build()?
        .into();
    let request = CreateNote::new(
        sender.id(),
        builder.rng_mut().draw_word(),
        output,
        None,
        BlockNumber::from(1),
    )?;
    builder.add_output_note(RawOutputNote::Full(request.note().clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(account.id())
        .authenticated_input_notes([request.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(request.output_advice()))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_CREATE_NOTE_OUTPUT);
    Ok(())
}

#[test]
fn create_note_validates_request_shape() -> anyhow::Result<()> {
    use miden_protocol::Word;
    use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme};
    let (_, sender, passthrough, request) = setup(NoteType::Public, true, Some(50))?;
    let make =
        |output, fee, height| CreateNote::new(sender.id(), Word::empty(), output, fee, height);
    assert!(make(request.output().clone(), request.fee(), BlockNumber::from(0)).is_err());
    assert!(
        make(
            request.output().clone(),
            Some(FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 0)?),
            BlockNumber::from(1)
        )
        .is_err()
    );
    let with_attachment = Note::with_attachments(
        request.output().assets().clone(),
        request.output().metadata().into_partial_metadata(),
        request.output().recipient().clone(),
        NoteAttachment::with_word(NoteAttachmentScheme::new(99)?, Word::empty()).into(),
    );
    assert!(make(with_attachment, request.fee(), BlockNumber::from(1)).is_err());
    let maximal: Note = P2idNote::builder()
        .sender(passthrough.id())
        .target(sender.id())
        .serial_number(Word::empty())
        .asset(FungibleAsset::new(
            ACCOUNT_ID_FEE_FAUCET.try_into()?,
            FungibleAsset::MAX_AMOUNT.as_u64(),
        )?)
        .build()?
        .into();
    assert!(make(maximal, request.fee(), BlockNumber::from(1)).is_err());
    Ok(())
}
