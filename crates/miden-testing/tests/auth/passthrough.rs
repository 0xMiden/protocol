use std::collections::BTreeMap;

use miden_processor::advice::AdviceInputs;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountCodeUpgrade,
    AccountComponent,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNote,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{ONE, Word};
use miden_standards::account::auth::{
    AuthPassthrough,
    FeeConversionInfo,
    NoAuth,
    commit_fee_conversion_info,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_PASSTHROUGH_FEE_NOTE,
    ERR_PASSTHROUGH_INSUFFICIENT_FEE,
    ERR_PASSTHROUGH_STATE_CHANGED,
    ERR_PASSTHROUGH_VAULT_NOT_EMPTY,
};
use miden_standards::note::{
    CreateNote,
    P2idNote,
    P2idNoteRecipient,
    P2idNoteStorage,
    PswapNote,
    PswapNoteAttachment,
    PswapNoteStorage,
    PswapPayback,
    TxFeeNote,
};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use rstest::rstest;

fn native(amount: u64) -> FungibleAsset {
    FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into().unwrap(), amount).unwrap()
}

fn passthrough() -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([42; 32])
        .account_type(AccountType::Public)
        .with_component(AuthPassthrough)
        .with_component(BasicWallet)
        .build_existing()?)
}

/// Publishes a private request, fills or cancels its public order, then claims private paybacks.
#[rstest]
#[tokio::test]
async fn passthrough_private_pswap_e2e(
    #[values(false, true)] cancel_remainder: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder().verification_base_fee(500);
    let offered = FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?, 100)?;
    let requested = FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3.try_into()?, 50)?;
    let owner = builder.add_existing_wallet_with_assets(
        Auth::basic_ecdsa(),
        [Asset::from(offered), native(1_000_000).into()],
    )?;
    let filler = builder.add_existing_wallet_with_assets(
        Auth::basic_ecdsa(),
        [Asset::from(requested), native(1_000_000).into()],
    )?;
    let account = passthrough()?;
    builder.add_account(account.clone())?;
    let recipient =
        P2idNoteRecipient::new(P2idNoteStorage::new(owner.id()), builder.rng_mut().draw_word());
    let order = PswapNote::builder()
        .sender(account.id())
        .storage(
            PswapNoteStorage::builder()
                .min_requested_asset(requested)
                .payback(PswapPayback::private(recipient, NoteTag::new(27)))
                .build(),
        )
        .serial_number(builder.rng_mut().draw_word())
        .note_type(NoteType::Public)
        .offered_asset(offered)
        .build()?;
    let order_note: Note = order.clone().into();
    let request = CreateNote::new(
        owner.id(),
        builder.rng_mut().draw_word(),
        order_note.clone(),
        Some(native(50_000)),
        BlockNumber::from(100),
    )?;
    // Cancellation has its own privately funded fee request, committing a TX_FEE as its output.
    let cancel_fee: Note = TxFeeNote::builder()
        .sender(account.id())
        .serial_number(builder.rng_mut().draw_word())
        .asset(native(50_000))
        .build()?
        .into();
    let cancel_request = CreateNote::new(
        owner.id(),
        builder.rng_mut().draw_word(),
        cancel_fee.clone(),
        None,
        BlockNumber::from(100),
    )?;
    let mut chain = builder.build()?;
    let (fee_args, fee_advice) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(ACCOUNT_ID_FEE_FAUCET.try_into()?),
        Word::from([9u32, 10, 11, 12]),
    );

    let requests = if cancel_remainder {
        vec![request.note().clone(), cancel_request.note().clone()]
    } else {
        vec![request.note().clone()]
    };
    let partials = requests.iter().cloned().map(PartialNote::from).collect::<Vec<_>>();
    let send = SendNotesTransactionScript::new(&owner.code_interface(), &partials)?;
    let publish = chain
        .build_transaction(owner.id())
        .send_notes_script(&send)
        .auth_args(fee_args)
        .add_advice_map_entry(fee_args, fee_advice.clone())
        .expected_output_notes(requests.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?
        .execute()
        .await?;
    assert_eq!(publish.output_notes().get_note(0).metadata().note_type(), NoteType::Private);
    chain.add_pending_executed_transaction(&publish)?;
    chain.prove_next_block()?;

    let creation = chain
        .build_transaction(account.id())
        .authenticated_input_notes([request.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(request.output_advice()))
        .auth_args(AuthPassthrough::auth_args(1))
        .build()?
        .execute()
        .await?;
    assert_eq!(creation.final_account().to_commitment(), account.to_commitment());
    assert_eq!(creation.output_notes().get_note(0).id(), order_note.id());
    assert_eq!(creation.output_notes().get_note(0).metadata().sender(), account.id());
    assert_eq!(creation.output_notes().get_note(1).metadata().tag(), TxFeeNote::TAG);
    assert!(native(50_000).amount() >= creation.compute_fee());
    if !cancel_remainder {
        let (proven, outcome) = crate::prove_and_verify_transaction(creation.clone()).await?;
        assert!(outcome.is_complete());
        assert_eq!(proven.unauthenticated_notes().count(), 0);
    }
    chain.add_pending_executed_transaction(&creation)?;
    chain.prove_next_block()?;

    let mut current = order.clone();
    let mut current_note = order_note;
    let mut paybacks = Vec::new();
    let fills = if cancel_remainder { 1 } else { 2 };
    for depth in 1..=fills {
        let fill = chain
            .build_transaction(filler.id())
            .auth_args(fee_args)
            .add_advice_map_entry(fee_args, fee_advice.clone())
            .authenticated_input_notes([current_note.clone()])
            .extend_note_args(BTreeMap::from([(
                current_note.id(),
                PswapNote::create_fill_args(25, 0)?,
            )]))
            .build()?
            .execute()
            .await?;
        let attachment = PswapNoteAttachment::new(AssetAmount::new(25)?, order.order_id(), depth);
        let payback = order.private_payback_note(filler.id(), &attachment, recipient)?;
        assert_eq!(fill.output_notes().get_note(0).id(), payback.id());
        assert_eq!(payback.metadata().note_type(), NoteType::Private);
        let (_, remainder) = current.execute(
            filler.id(),
            Some(FungibleAsset::new(requested.faucet_id(), 25)?),
            None,
        )?;
        chain.add_pending_executed_transaction(&fill)?;
        chain.prove_next_block()?;
        paybacks.push(payback);
        if let Some(remainder) = remainder {
            current_note = remainder.clone().into();
            current = remainder;
        }
    }
    if cancel_remainder {
        let advice = AdviceInputs::default()
            .with_map(current.cancellation_advice(recipient)?)
            .with_map(cancel_request.output_advice());
        let cancel = chain
            .build_transaction(account.id())
            // Put the fee request first, so the fee remains at index zero.
            .authenticated_input_notes([cancel_request.note().clone(), current_note.clone()])
            .extend_advice_inputs(advice)
            .extend_note_args(BTreeMap::from([(
                current_note.id(),
                PswapNote::create_cancel_args(),
            )]))
            .auth_args(AuthPassthrough::auth_args(0))
            .build()?
            .execute()
            .await?;
        let refund = current.refund_note(account.id(), recipient)?;
        assert!(cancel.output_notes().iter().any(|note| note.id() == refund.id()));
        assert_eq!(cancel.final_account().to_commitment(), account.to_commitment());
        assert!(native(50_000).amount() >= cancel.compute_fee());
        chain.add_pending_executed_transaction(&cancel)?;
        chain.prove_next_block()?;
        paybacks.push(refund);
    }
    let claim = chain
        .build_transaction(owner.id())
        .authenticated_input_notes(paybacks)
        .auth_args(fee_args)
        .add_advice_map_entry(fee_args, fee_advice)
        .build()?
        .execute()
        .await?;
    assert!(claim.account_patch().vault().updated_assets().any(|asset| asset
        == Asset::from(FungibleAsset::new(requested.faucet_id(), 25 * u64::from(fills)).unwrap())));
    if cancel_remainder {
        let refund_asset = Asset::from(FungibleAsset::new(offered.faucet_id(), 50)?);
        assert!(
            claim
                .account_patch()
                .vault()
                .updated_assets()
                .any(|asset| asset == refund_asset)
        );
    }
    Ok(())
}

#[tokio::test]
async fn passthrough_rejects_insufficient_fee() -> anyhow::Result<()> {
    let mut builder = MockChain::builder().verification_base_fee(500);
    let owner = builder.add_existing_wallet(Auth::IncrNonce)?;
    let account = passthrough()?;
    builder.add_account(account.clone())?;
    let output: Note = TxFeeNote::builder()
        .sender(account.id())
        .serial_number(builder.rng_mut().draw_word())
        .asset(native(1))
        .build()?
        .into();
    let request = CreateNote::new(
        owner.id(),
        builder.rng_mut().draw_word(),
        output,
        None,
        BlockNumber::from(100),
    )?;
    builder.add_output_note(RawOutputNote::Full(request.note().clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(account.id())
        .authenticated_input_notes([request.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(request.output_advice()))
        .auth_args(AuthPassthrough::auth_args(0))
        .authenticator(None)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PASSTHROUGH_INSUFFICIENT_FEE);
    Ok(())
}

#[rstest]
#[tokio::test]
async fn passthrough_rejects_vault_deposits(
    #[values(false, true)] new_account: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account_builder = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_component(AuthPassthrough)
        .with_component(BasicWallet);
    let account = if new_account {
        account_builder.build()?
    } else {
        account_builder.build_existing()?
    };
    if !new_account {
        builder.add_account(account.clone())?;
    }
    let sender = builder.add_existing_wallet(Auth::IncrNonce)?;
    let funding: Note = P2idNote::builder()
        .sender(sender.id())
        .target(account.id())
        .serial_number(builder.rng_mut().draw_word())
        .note_type(NoteType::Public)
        .asset(native(10))
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(funding.clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(account)
        .authenticated_input_notes([funding])
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PASSTHROUGH_STATE_CHANGED);
    Ok(())
}

#[tokio::test]
async fn passthrough_deploys_with_one_nonce_increment() -> anyhow::Result<()> {
    let account = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_component(AuthPassthrough)
        .with_component(BasicWallet)
        .build()?;
    let chain = MockChain::builder().build()?;
    let tx = chain.build_transaction(account).build()?.execute().await?;
    assert_eq!(tx.final_account().nonce(), ONE);
    assert!(tx.account_patch().vault().is_empty());
    Ok(())
}

#[rstest]
#[case::storage("change_storage")]
#[case::pending_upgrade("change_code")]
#[tokio::test]
async fn passthrough_rejects_storage_changes_and_pending_upgrades(
    #[case] procedure: &str,
) -> anyhow::Result<()> {
    let code = CodeBuilder::default().compile_component_code(
        "tests::passthrough_mutator",
        r#"
        use miden::protocol::native_account
        const SLOT = word("tests::passthrough::value")
        @account_procedure
        pub proc change_storage
            push.1.2.3.4 push.SLOT[0..2]
            # => [slot_id_suffix, slot_id_prefix, VALUE, pad(16)]
            exec.native_account::set_item dropw
        end
        @account_procedure
        pub proc change_code
            padw swapw
            # => [NEW_CODE_COMMITMENT, EMPTY_STORAGE_UPGRADE, pad(12)]
            exec.native_account::upgrade
        end
    "#,
    )?;
    let root = code
        .as_package()
        .get_procedure_root_by_path(format!("tests::passthrough_mutator::{procedure}").as_str())
        .unwrap();
    let component = AccountComponent::new(
        code,
        vec![StorageSlot::with_value(
            StorageSlotName::new("tests::passthrough::value")?,
            Word::empty(),
        )],
        AccountComponentMetadata::new("tests::passthrough_mutator"),
    )?;
    let account = AccountBuilder::new([44; 32])
        .account_type(AccountType::Public)
        .with_component(AuthPassthrough)
        .with_component(BasicWallet)
        .with_component(component.clone())
        .build_existing()?;
    let upgraded = AccountBuilder::new([45; 32])
        .account_type(AccountType::Public)
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .with_component(component)
        .build_existing()?;
    let upgrade = AccountCodeUpgrade::new(upgraded.code().clone());
    let input = if procedure == "change_code" {
        format!("push.{}", upgrade.commitment())
    } else {
        String::new()
    };
    let script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        @transaction_script
        pub proc main
            {input}
            call.{root}
            exec.sys::truncate_stack
        end
        "#
    ))?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let chain = builder.build()?;
    let result = chain
        .build_transaction(account.id())
        .tx_script(script)
        .account_code_upgrade(upgrade)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PASSTHROUGH_STATE_CHANGED);
    Ok(())
}

#[rstest]
#[case::private_fee(true, false, false)]
#[case::wrong_script(false, true, false)]
#[case::wrong_asset(false, false, true)]
#[tokio::test]
async fn passthrough_rejects_invalid_fee_outputs(
    #[case] private: bool,
    #[case] wrong_script: bool,
    #[case] wrong_asset: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder().verification_base_fee(500);
    let owner = builder.add_existing_wallet(Auth::IncrNonce)?;
    let account = passthrough()?;
    builder.add_account(account.clone())?;
    let recipient = if wrong_script {
        P2idNoteStorage::new(owner.id()).into_recipient(builder.rng_mut().draw_word())
    } else {
        NoteRecipient::new(
            builder.rng_mut().draw_word(),
            TxFeeNote::script(),
            NoteStorage::default(),
        )
    };
    let asset = if wrong_asset {
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?, 50_000)?
    } else {
        native(50_000)
    };
    let output = Note::new(
        NoteAssets::new(vec![asset.into()])?,
        PartialNoteMetadata::new(
            account.id(),
            if private { NoteType::Private } else { NoteType::Public },
        )
        .with_tag(TxFeeNote::TAG),
        recipient,
    );
    let request = CreateNote::new(
        owner.id(),
        builder.rng_mut().draw_word(),
        output,
        None,
        BlockNumber::from(100),
    )?;
    builder.add_output_note(RawOutputNote::Full(request.note().clone()));
    let chain = builder.build()?;
    let result = chain
        .build_transaction(account.id())
        .authenticated_input_notes([request.note().clone()])
        .extend_advice_inputs(AdviceInputs::default().with_map(request.output_advice()))
        .auth_args(AuthPassthrough::auth_args(0))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PASSTHROUGH_FEE_NOTE);
    Ok(())
}

#[tokio::test]
async fn passthrough_rejects_unsealed_fee_output() -> anyhow::Result<()> {
    let account = passthrough()?;
    let mut builder = MockChain::builder().verification_base_fee(500);
    builder.add_account(account.clone())?;
    let chain = builder.build()?;
    let script = CodeBuilder::default().compile_tx_script(
        r#"
        use miden::standards::notes::tx_fee
        @transaction_script
        pub proc main
            push.1.2.3.4 exec.tx_fee::create_output_note drop
        end
    "#,
    )?;
    let result = chain
        .build_transaction(account.id())
        .tx_script(script)
        .auth_args(AuthPassthrough::auth_args(0))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PASSTHROUGH_FEE_NOTE);
    Ok(())
}

#[tokio::test]
async fn passthrough_rejects_an_existing_balance() -> anyhow::Result<()> {
    let account = AccountBuilder::new([46; 32])
        .account_type(AccountType::Public)
        .with_component(AuthPassthrough)
        .with_component(BasicWallet)
        .with_assets([native(10).into()])
        .build_existing()?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let chain = builder.build()?;
    let result = chain.build_transaction(account.id()).build()?.execute().await;
    assert_transaction_executor_error!(result, ERR_PASSTHROUGH_VAULT_NOT_EMPTY);
    Ok(())
}

/// Independent requests can use the same account state and reference block without fee ID clashes.
#[tokio::test]
async fn passthrough_concurrent_creations_share_account_state() -> anyhow::Result<()> {
    let mut builder = MockChain::builder().verification_base_fee(500);
    let owner = builder.add_existing_wallet(Auth::IncrNonce)?;
    let account = passthrough()?;
    builder.add_account(account.clone())?;
    let mut requests = Vec::new();
    for _ in 0..2 {
        let output: Note = P2idNote::builder()
            .sender(account.id())
            .target(owner.id())
            .serial_number(builder.rng_mut().draw_word())
            .note_type(NoteType::Public)
            .asset(native(100))
            .build()?
            .into();
        let request = CreateNote::new(
            owner.id(),
            builder.rng_mut().draw_word(),
            output,
            Some(native(50_000)),
            BlockNumber::from(100),
        )?;
        builder.add_output_note(RawOutputNote::Full(request.note().clone()));
        requests.push(request);
    }
    let mut chain = builder.build()?;
    let mut transactions = Vec::new();
    for request in &requests {
        let tx = chain
            .build_transaction(account.id())
            .authenticated_input_notes([request.note().clone()])
            .extend_advice_inputs(AdviceInputs::default().with_map(request.output_advice()))
            .auth_args(AuthPassthrough::auth_args(1))
            .build()?
            .execute()
            .await?;
        assert_eq!(tx.final_account().to_commitment(), account.to_commitment());
        assert_eq!(tx.output_notes().get_note(0).id(), request.output().id());
        transactions.push(tx);
    }
    assert_ne!(
        transactions[0].output_notes().get_note(1).id(),
        transactions[1].output_notes().get_note(1).id()
    );
    for tx in &transactions {
        chain.add_pending_executed_transaction(tx)?;
    }
    chain.prove_next_block()?;
    Ok(())
}
