use std::collections::BTreeMap;

use miden_processor::advice::AdviceInputs;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountType};
use miden_protocol::asset::{Asset, AssetCallbacks, FungibleAsset, NonFungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteRecipient,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    AccountIdBuilder,
};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Word, ZERO};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_CREATE_NOTE_FEE_ASSET_NOT_NATIVE,
    ERR_CREATE_NOTE_FUNDING_MISMATCH,
    ERR_CREATE_NOTE_INVALID_OUTPUT_ASSETS,
    ERR_CREATE_NOTE_OUTPUT_ALTERED,
    ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_TARGET_ACCOUNT,
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
    extra_assets: usize,
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
    let fee_faucet = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let faucet = if native_principal {
        fee_faucet
    } else {
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?
    };
    let mut assets = vec![FungibleAsset::new(faucet, 100)?];
    for index in 0..extra_assets {
        let issuer = AccountIdBuilder::new()
            .account_type(AccountType::Public)
            .build_with_seed([100 + index as u8; 32]);
        assets.push(FungibleAsset::new(issuer, 10)?);
    }
    let output: Note = P2idNote::builder()
        .sender(passthrough.id())
        .target(sender.id())
        .serial_number(builder.rng_mut().draw_word())
        .note_type(note_type)
        .assets(assets)
        .build()?
        .into();
    let fee = fee_amount.map(|amount| FungibleAsset::new(fee_faucet, amount)).transpose()?;
    let create_note = CreateNote::new(sender.id(), builder.rng_mut().draw_word(), output, fee)?;
    builder.add_output_note(RawOutputNote::Full(create_note.note().clone()));
    Ok((builder, sender, passthrough, create_note))
}

#[rstest]
#[case::combined_funding(NoteType::Public, true, Some(50), 0, None)]
#[case::fee_before_output(NoteType::Public, false, Some(50), 1, Some(0))]
#[case::private_output(NoteType::Private, false, Some(50), 0, None)]
#[case::without_fee(NoteType::Public, false, None, 0, None)]
#[case::fee_between_outputs(NoteType::Private, false, Some(50), 1, Some(1))]
#[case::maximum_output_assets(NoteType::Public, true, Some(50), NoteAssets::MAX_NUM_ASSETS - 1, None)]
#[tokio::test]
async fn create_note_preserves_output_and_pays_fee(
    #[case] note_type: NoteType,
    #[case] native_principal: bool,
    #[case] fee_amount: Option<u64>,
    #[case] extra_assets: usize,
    #[case] fee_asset_index: Option<usize>,
) -> anyhow::Result<()> {
    let (mut builder, _, passthrough, create_note) =
        setup(note_type, native_principal, fee_amount, extra_assets)?;
    let mut input = create_note.note().clone();
    if let Some(index) = fee_asset_index {
        let mut assets = input.assets().clone().into_vec();
        let fee = assets.pop().unwrap();
        assets.insert(index, fee);
        let assets = NoteAssets::new(assets)?;
        let mut storage = input.storage().items().to_vec();
        storage[4..8].copy_from_slice(assets.commitment().as_elements());
        input = Note::new(
            assets,
            input.metadata().into_partial_metadata(),
            NoteRecipient::new(
                input.serial_num(),
                CreateNote::script(),
                NoteStorage::new(storage)?,
            ),
        );
        builder.add_output_note(RawOutputNote::Full(input.clone()));
    }
    let chain = builder.build()?;
    let tx = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([input])
        .extend_advice_inputs(AdviceInputs::default().with_map(create_note.output_advice()))
        .build()?
        .execute()
        .await?;
    assert_eq!(tx.output_notes().num_notes(), if fee_amount.is_some() { 2 } else { 1 });
    assert_eq!(tx.output_notes().get_note(0).id(), create_note.output().id());
    assert_eq!(tx.output_notes().get_note(0).assets(), create_note.output().assets());
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
async fn create_note_fee_ids_are_unique_within_transaction() -> anyhow::Result<()> {
    let (mut builder, sender, passthrough, first) = setup(NoteType::Public, true, Some(50), 0)?;
    let second_output = Note::new(
        first.output().assets().clone(),
        first.output().metadata().into_partial_metadata(),
        NoteRecipient::new(
            builder.rng_mut().draw_word(),
            first.output().script().clone(),
            first.output().storage().clone(),
        ),
    );
    let second =
        CreateNote::new(sender.id(), builder.rng_mut().draw_word(), second_output, first.fee())?;
    builder.add_output_note(RawOutputNote::Full(second.note().clone()));
    let chain = builder.build()?;
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
    let (builder, sender, _, create_note) = setup(NoteType::Public, false, Some(50), 0)?;
    let chain = builder.build()?;
    let result = chain
        .build_transaction(sender.id())
        .authenticated_input_notes([create_note.note().clone()])
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_TARGET_ACCOUNT);
    Ok(())
}

#[tokio::test]
async fn create_note_rejects_changed_input_assets() -> anyhow::Result<()> {
    let (mut builder, _, passthrough, create_note) = setup(NoteType::Public, true, Some(50), 0)?;
    let malformed = Note::new(
        NoteAssets::new(vec![FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 151)?.into()])?,
        create_note.note().metadata().into_partial_metadata(),
        create_note.note().recipient().clone(),
    );
    builder.add_output_note(RawOutputNote::Full(malformed.clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([malformed])
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_CREATE_NOTE_FUNDING_MISMATCH);
    Ok(())
}

#[rstest]
#[case::empty_output(None, false)]
#[case::fee_only(None, true)]
#[case::nft(Some(NonFungibleAsset::mock(&[1, 2, 3, 4])), false)]
#[case::zero_amount(Some(FungibleAsset::mock(0)), false)]
#[tokio::test]
async fn create_note_rejects_unsupported_output_assets(
    #[case] output_asset: Option<Asset>,
    #[case] fee_only: bool,
) -> anyhow::Result<()> {
    let (mut builder, _, passthrough, template) = setup(NoteType::Public, true, Some(50), 0)?;
    let assets = NoteAssets::new(if fee_only {
        vec![template.fee().unwrap().into()]
    } else {
        output_asset.into_iter().collect()
    })?;
    let mut storage = template.note().storage().items().to_vec();
    storage[4..8].copy_from_slice(assets.commitment().as_elements());
    if !fee_only {
        storage[8..16].fill(ZERO);
    }
    let note = Note::new(
        assets,
        template.note().metadata().into_partial_metadata(),
        NoteRecipient::new(
            builder.rng_mut().draw_word(),
            CreateNote::script(),
            NoteStorage::new(storage)?,
        ),
    );
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([note])
        .extend_advice_inputs(AdviceInputs::default().with_map(template.output_advice()))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_CREATE_NOTE_INVALID_OUTPUT_ASSETS);
    Ok(())
}

#[tokio::test]
async fn create_note_rejects_funding_removed_by_an_earlier_input() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender = builder.add_existing_wallet(Auth::IncrNonce)?;
    let drained = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1)?;
    let code = CodeBuilder::default().compile_component_code(
        "tests::create_note_drain",
        format!(
            r#"
        use miden::protocol::input_note
        use miden::protocol::native_account
        @account_procedure
        pub proc drain
            push.1 push.{value} push.{id}
            exec.input_note::remove_asset dropw
            push.{value} push.{id}
            exec.native_account::add_asset dropw
        end
        "#,
            value = drained.to_value_word(),
            id = drained.to_id_word()
        ),
    )?;
    let drain = AccountComponent::new(
        code,
        vec![],
        AccountComponentMetadata::new("tests::create_note_drain"),
    )?;
    let helper_script = CodeBuilder::default()
        .with_dynamically_linked_package(drain.component_code())?
        .compile_note_script(
            r#"
        @note_script
        pub proc main
            call.::tests::create_note_drain::drain
        end
        "#,
        )?;
    let account = builder.add_account_from_builder(
        Auth::IncrNonce,
        AccountBuilder::new([43; 32])
            .account_type(AccountType::Public)
            .with_component(BasicWallet)
            .with_component(drain),
        AccountState::Exists,
    )?;
    let output: Note = P2idNote::builder()
        .sender(account.id())
        .target(sender.id())
        .serial_number(builder.rng_mut().draw_word())
        .asset(FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 100)?)
        .build()?
        .into();
    let create_note = CreateNote::new(sender.id(), builder.rng_mut().draw_word(), output, None)?;
    let helper = Note::new(
        NoteAssets::default(),
        PartialNoteMetadata::new(sender.id(), NoteType::Private),
        NoteRecipient::new(builder.rng_mut().draw_word(), helper_script, NoteStorage::default()),
    );
    builder.add_output_note(RawOutputNote::Full(helper.clone()));
    builder.add_output_note(RawOutputNote::Full(create_note.note().clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(account.id())
        .authenticated_input_notes([helper, create_note.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(create_note.output_advice()))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_CREATE_NOTE_FUNDING_MISMATCH);
    Ok(())
}

#[tokio::test]
async fn create_note_rejects_fee_in_another_asset() -> anyhow::Result<()> {
    let (mut builder, sender, passthrough, valid) = setup(NoteType::Public, false, None, 0)?;
    let create_note = CreateNote::new(
        sender.id(),
        builder.rng_mut().draw_word(),
        valid.output().clone(),
        Some(FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?, 50)?),
    )?;
    builder.add_output_note(RawOutputNote::Full(create_note.note().clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([create_note.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(create_note.output_advice()))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_CREATE_NOTE_FEE_ASSET_NOT_NATIVE);
    Ok(())
}

#[rstest]
#[case::creator(true)]
#[case::other_account(false)]
#[tokio::test]
async fn create_note_reclaim(#[case] original_sender: bool) -> anyhow::Result<()> {
    let (builder, sender, passthrough, create_note) = setup(NoteType::Public, true, Some(50), 0)?;
    let chain = builder.build()?;
    let consumer = if original_sender { sender.id() } else { passthrough.id() };
    let result = chain
        .build_transaction(consumer)
        .authenticated_input_notes([create_note.note().clone()])
        .extend_note_args(BTreeMap::from([(create_note.note().id(), CreateNote::reclaim_args())]))
        .build()?
        .execute()
        .await;
    if original_sender {
        let tx = result?;
        assert_eq!(tx.output_notes().num_notes(), 0);
        let assets: Vec<Asset> = tx.account_patch().vault().updated_assets().collect();
        assert_eq!(assets, create_note.note().assets().as_slice());
    } else {
        assert_transaction_executor_error!(result, ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_TARGET_ACCOUNT);
    }
    Ok(())
}

#[rstest]
#[case::public_primary(NoteType::Public, 0)]
#[case::private_primary(NoteType::Private, 0)]
#[case::fee_output(NoteType::Public, 1)]
#[tokio::test]
async fn create_note_leaves_outputs_unsealed(
    #[case] note_type: NoteType,
    #[case] index: u32,
) -> anyhow::Result<()> {
    let (builder, _, passthrough, create_note) = setup(note_type, false, Some(50), 0)?;
    let chain = builder.build()?;
    let script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::protocol::output_note
        @transaction_script
        pub proc main
            push.{index} push.0.0.0.0 push.99
            # => [scheme, CONTENT, note_idx]
            exec.output_note::add_word_attachment
        end
    "#
    ))?;
    let tx = chain
        .build_transaction(passthrough.id())
        .authenticated_input_notes([create_note.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(create_note.output_advice()))
        .tx_script(script)
        .build()?
        .execute()
        .await?;
    let attachment = NoteAttachment::with_word(NoteAttachmentScheme::new(99)?, Word::empty());
    assert_eq!(
        tx.output_notes().get_note(index as usize).attachments(),
        &attachment.clone().into()
    );
    if index == 0 {
        let expected = Note::with_attachments(
            create_note.output().assets().clone(),
            create_note.output().metadata().into_partial_metadata(),
            create_note.output().recipient().clone(),
            attachment.into(),
        );
        assert_eq!(tx.output_notes().get_note(0).id(), expected.id());
    }
    Ok(())
}

#[rstest]
#[case::attachment(false)]
#[case::asset_change(true)]
#[tokio::test]
async fn create_note_checks_assets_after_callbacks(
    #[case] change_assets: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender = builder.add_existing_wallet(Auth::IncrNonce)?;
    let extra_asset = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1)?;
    let attachment_word = Word::from([1u32, 2, 3, 4]);
    let callback_body = if change_assets {
        format!(
            "push.{} push.{} exec.output_note::add_asset",
            extra_asset.to_value_word(),
            extra_asset.to_id_word(),
        )
    } else {
        format!("push.{attachment_word} push.99 exec.output_note::add_word_attachment")
    };
    let code = CodeBuilder::default().compile_component_code(
        "tests::create_note_callback",
        format!(
            r#"
        use miden::protocol::output_note
        @account_procedure
        pub proc on_before_asset_added_to_note
            dropw dropw
            {callback_body}
        end
        "#
        ),
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
    let create_note = CreateNote::new(sender.id(), builder.rng_mut().draw_word(), output, None)?;
    builder.add_output_note(RawOutputNote::Full(create_note.note().clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(account.id())
        .authenticated_input_notes([create_note.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(create_note.output_advice()))
        .build()?
        .execute()
        .await;
    if change_assets {
        assert_transaction_executor_error!(result, ERR_CREATE_NOTE_OUTPUT_ALTERED);
        return Ok(());
    }
    let tx = result?;
    let expected = Note::with_attachments(
        create_note.output().assets().clone(),
        create_note.output().metadata().into_partial_metadata(),
        create_note.output().recipient().clone(),
        NoteAttachment::with_word(NoteAttachmentScheme::new(99)?, attachment_word).into(),
    );
    assert_eq!(tx.output_notes().get_note(0).id(), expected.id());
    Ok(())
}

#[test]
fn create_note_validates_funding() -> anyhow::Result<()> {
    let (_, sender, passthrough, create_note) = setup(NoteType::Public, true, Some(50), 0)?;
    let make = |output, fee| CreateNote::new(sender.id(), Word::empty(), output, fee);
    assert!(
        make(
            create_note.output().clone(),
            Some(FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 0)?)
        )
        .is_err()
    );
    let output = create_note.output();
    let with_attachment = Note::with_attachments(
        output.assets().clone(),
        output.metadata().into_partial_metadata(),
        output.recipient().clone(),
        NoteAttachment::with_word(NoteAttachmentScheme::new(99)?, Word::empty()).into(),
    );
    assert!(make(with_attachment, create_note.fee()).is_ok());
    let empty = Note::new(
        NoteAssets::default(),
        output.metadata().into_partial_metadata(),
        output.recipient().clone(),
    );
    assert!(make(empty, create_note.fee()).is_err());
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
    assert!(make(maximal, create_note.fee()).is_err());
    Ok(())
}
