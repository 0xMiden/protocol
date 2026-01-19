extern crate alloc;

use alloc::sync::Arc;

use miden_processor::crypto::RpoRandomCoin;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{NoteAttachment, NoteTag, NoteType};
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::NetworkFungibleFaucet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_SENDER_NOT_OWNER;
use miden_standards::note::{MintNoteInputs, create_mint_note};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use crate::scripts::swap::create_p2id_note_exact;

// Shared test utilities for faucet tests
// ================================================================================================

/// Common test parameters for faucet tests
#[allow(dead_code)] // Suppresses warning as this is used in shared contexts
pub struct FaucetTestParams {
    pub recipient: Word,
    pub tag: NoteTag,
    pub note_type: NoteType,
    pub amount: Felt,
}

// TESTS FOR NETWORK FAUCET ACCESS
// ================================================================================================

/// Tests that the owner can mint assets on network faucet.
#[tokio::test]
async fn test_network_faucet_owner_can_mint() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let amount = Felt::new(75);
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.into())?.into();

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        NoteType::Private,
        Word::default(),
    )?;
    let recipient = p2id_note.recipient().digest();

    let mint_inputs = MintNoteInputs::new_private(recipient, amount, output_note_tag.into());

    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = create_mint_note(
        faucet.id(),
        owner_account_id,
        mint_inputs,
        NoteAttachment::default(),
        &mut rng,
    )?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[], &[mint_note])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 1);

    Ok(())
}

/// Tests that a non-owner cannot mint assets on network faucet.
#[tokio::test]
async fn test_network_faucet_non_owner_cannot_mint() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let non_owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let amount = Felt::new(75);
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.into())?.into();

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        NoteType::Private,
        Word::default(),
    )?;
    let recipient = p2id_note.recipient().digest();

    let mint_inputs = MintNoteInputs::new_private(recipient, amount, output_note_tag.into());

    // Create mint note from NON-OWNER
    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = create_mint_note(
        faucet.id(),
        non_owner_account_id,
        mint_inputs,
        NoteAttachment::default(),
        &mut rng,
    )?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[], &[mint_note])?.build()?;
    let result = tx_context.execute().await;

    // The distribute function uses ERR_ONLY_OWNER, which is "note sender is not the owner"
    let expected_error = ERR_SENDER_NOT_OWNER;
    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// Tests that get_owner returns the correct owner AccountId.
#[tokio::test]
async fn test_network_faucet_get_owner() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [11; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;
    let _mock_chain = builder.build()?;

    // Verify the owner is stored correctly in storage
    let stored_owner = faucet.storage().get_item(NetworkFungibleFaucet::owner_config_slot())?;

    assert_eq!(
        stored_owner[3],
        owner_account_id.prefix().as_felt(),
        "Owner prefix should match stored value"
    );
    assert_eq!(
        stored_owner[2],
        Felt::new(owner_account_id.suffix().as_int()),
        "Owner suffix should match stored value"
    );
    assert_eq!(stored_owner[1], Felt::new(0), "Storage word[1] should be zero");
    assert_eq!(stored_owner[0], Felt::new(0), "Storage word[0] should be zero");

    Ok(())
}

/// Tests that transfer_ownership updates the owner correctly.
#[tokio::test]
async fn test_network_faucet_transfer_ownership() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let initial_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let new_owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet =
        builder.add_existing_network_faucet("NET", 1000, initial_owner_account_id, Some(50))?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let amount = Felt::new(75);
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.into())?.into();

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        NoteType::Private,
        Word::default(),
    )?;
    let recipient = p2id_note.recipient().digest();

    let mint_inputs = MintNoteInputs::new_private(recipient, amount, output_note_tag.into());

    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = create_mint_note(
        faucet.id(),
        initial_owner_account_id,
        mint_inputs.clone(),
        NoteAttachment::default(),
        &mut rng,
    )?;

    let transfer_note_script_code = format!(
        r#"
        use miden::standards::faucets::network_fungible->network_faucet

        begin
            repeat.14 push.0 end
            push.{new_owner_suffix}
            push.{new_owner_prefix}
            call.network_faucet::transfer_ownership
            dropw dropw dropw dropw
        end
        "#,
        new_owner_prefix = new_owner_account_id.prefix().as_felt(),
        new_owner_suffix = Felt::new(new_owner_account_id.suffix().as_int()),
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let transfer_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(transfer_note_script_code.clone())?;

    let mut rng = RpoRandomCoin::new([Felt::from(200u32); 4].into());
    let transfer_note = NoteBuilder::new(initial_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([11, 22, 33, 44u32]))
        .code(transfer_note_script_code.clone())
        .build()?;

    builder.add_output_note(OutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[], &[mint_note])?.build()?;
    let executed_transaction = tx_context.execute().await?;
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[transfer_note.id()], &[])?
        .add_note_script(transfer_note_script.clone())
        .with_source_manager(source_manager.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_delta(executed_transaction.account_delta())?;

    let mut rng = RpoRandomCoin::new([Felt::from(300u32); 4].into());
    let mint_note_old_owner = create_mint_note(
        updated_faucet.id(),
        initial_owner_account_id,
        mint_inputs.clone(),
        NoteAttachment::default(),
        &mut rng,
    )?;

    let tx_context = mock_chain
        .build_tx_context(updated_faucet.id(), &[], &[mint_note_old_owner])?
        .build()?;
    let result = tx_context.execute().await;

    let expected_error = ERR_SENDER_NOT_OWNER;
    assert_transaction_executor_error!(result, expected_error);

    let mut rng = RpoRandomCoin::new([Felt::from(400u32); 4].into());
    let mint_note_new_owner = create_mint_note(
        updated_faucet.id(),
        new_owner_account_id,
        mint_inputs,
        NoteAttachment::default(),
        &mut rng,
    )?;

    let tx_context = mock_chain
        .build_tx_context(updated_faucet.id(), &[], &[mint_note_new_owner])?
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 1);

    Ok(())
}

/// Tests that only the owner can transfer ownership.
#[tokio::test]
async fn test_network_faucet_only_owner_can_transfer() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );
    let non_owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );
    let new_owner_account_id = AccountId::dummy(
        [3; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;
    let mock_chain = builder.build()?;

    let transfer_note_script_code = format!(
        r#"
        use miden::standards::faucets::network_fungible->network_faucet

        begin
            repeat.14 push.0 end
            push.{new_owner_suffix}
            push.{new_owner_prefix}
            call.network_faucet::transfer_ownership
            dropw dropw dropw dropw
        end
        "#,
        new_owner_prefix = new_owner_account_id.prefix().as_felt(),
        new_owner_suffix = Felt::new(new_owner_account_id.suffix().as_int()),
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let transfer_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(transfer_note_script_code.clone())?;

    let mut rng = RpoRandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note = NoteBuilder::new(non_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([10, 20, 30, 40u32]))
        .code(transfer_note_script_code.clone())
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[transfer_note])?
        .add_note_script(transfer_note_script.clone())
        .with_source_manager(source_manager.clone())
        .build()?;
    let result = tx_context.execute().await;

    let expected_error = ERR_SENDER_NOT_OWNER;
    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// Tests that renounce_ownership clears the owner correctly.
#[tokio::test]
async fn test_network_faucet_renounce_ownership() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );
    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;

    let renounce_note_script_code = r#"
        use miden::standards::faucets::network_fungible->network_faucet

        begin
            repeat.16 push.0 end
            call.network_faucet::renounce_ownership
            dropw dropw dropw dropw
        end
        "#;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let renounce_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(renounce_note_script_code)?;

    let mut rng = RpoRandomCoin::new([Felt::from(200u32); 4].into());
    let renounce_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([11, 22, 33, 44u32]))
        .code(renounce_note_script_code)
        .build()?;

    builder.add_output_note(OutputNote::Full(renounce_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[renounce_note.id()], &[])?
        .add_note_script(renounce_note_script.clone())
        .with_source_manager(source_manager.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    let updated_faucet = mock_chain.committed_account(faucet.id())?;
    let stored_owner_after =
        updated_faucet.storage().get_item(NetworkFungibleFaucet::owner_config_slot())?;

    assert_eq!(stored_owner_after, Word::default());

    Ok(())
}
