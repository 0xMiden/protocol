extern crate alloc;

use alloc::sync::Arc;
use core::slice;
use std::collections::BTreeSet;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountIdVersion, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, AssetAmount, AssetCallbackFlag, FungibleAsset, TokenSymbol};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachments,
    NoteDetailsCommitment,
    NoteId,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnAllowAll,
    BurnOwnerOnly,
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyRegistration,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_BURN_POLICY_ROOT_NOT_ALLOWED,
    ERR_FAUCET_BURN_AMOUNT_EXCEEDS_TOKEN_SUPPLY,
    ERR_FUNGIBLE_ASSET_DISTRIBUTE_AMOUNT_EXCEEDS_MAX_SUPPLY,
    ERR_MINT_POLICY_ROOT_NOT_ALLOWED,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::{BurnNote, MintNote, MintNoteStorage, StandardNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::utils::create_p2id_note_exact;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_note_created,
    assert_transaction_executor_error,
};
use rand::Rng;

use crate::{get_note_with_fungible_asset_and_script, prove_and_verify_transaction};

// Shared test utilities for faucet tests
// ================================================================================================

/// Common test parameters for faucet tests
pub struct FaucetTestParams {
    pub recipient: Word,
    pub tag: NoteTag,
    pub note_type: NoteType,
    pub amount: Felt,
}

/// Creates minting script code for fungible asset distribution
pub fn create_mint_script_code(params: &FaucetTestParams, faucet_id: AccountId) -> String {
    format!(
        "
            begin
                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                push.0
                # => [enable_callbacks=0, faucet_id_suffix, faucet_id_prefix, amount, tag, note_type, RECIPIENT, ...]

                exec.::miden::protocol::asset::create_fungible_asset
                # => [ASSET_KEY, ASSET_VALUE, tag, note_type, RECIPIENT, ...]

                call.::miden::standards::faucets::fungible::mint_and_send
                # => [note_idx, pad(15)]

                # truncate the stack
                dropw dropw dropw dropw
            end
            ",
        note_type = params.note_type as u8,
        recipient = params.recipient,
        tag = u32::from(params.tag),
        amount = params.amount,
        faucet_id_suffix = faucet_id.suffix(),
        faucet_id_prefix = faucet_id.prefix().as_felt(),
    )
}

/// Executes a minting transaction with the given faucet and parameters
pub async fn execute_mint_transaction(
    mock_chain: &mut MockChain,
    faucet: Account,
    params: &FaucetTestParams,
) -> anyhow::Result<ExecutedTransaction> {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script_code = create_mint_script_code(params, faucet.id());
    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_tx_script(tx_script_code)?;
    let tx_context = mock_chain
        .build_tx_context(faucet, &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    Ok(tx_context.execute().await?)
}

/// Verifies minted output note matches expectations
pub fn verify_minted_output_note(
    executed_transaction: &ExecutedTransaction,
    faucet: &Account,
    params: &FaucetTestParams,
) -> anyhow::Result<()> {
    let output_note = executed_transaction.output_notes().get_note(0).clone();

    let fungible_asset: Asset = FungibleAsset::new(faucet.id(), params.amount.as_canonical_u64())?
        .with_callbacks(AssetCallbackFlag::Enabled)
        .into();
    let assets = NoteAssets::new(vec![fungible_asset])?;

    let partial_metadata =
        PartialNoteMetadata::new(faucet.id(), params.note_type).with_tag(params.tag);
    let metadata = NoteMetadata::new(partial_metadata, &NoteAttachments::default());
    let details_commitment =
        NoteDetailsCommitment::from_raw_commitments(params.recipient, assets.commitment());

    let id = NoteId::new(details_commitment, &metadata);

    assert_eq!(output_note.id(), id);
    assert_eq!(output_note.metadata().partial_metadata(), &partial_metadata);

    Ok(())
}

fn compile_note_script(code: &str) -> anyhow::Result<NoteScript> {
    Ok(CodeBuilder::default().compile_note_script(code)?)
}

async fn execute_faucet_note_script(
    mock_chain: &MockChain,
    faucet_id: AccountId,
    sender_account_id: AccountId,
    note_script: NoteScript,
    rng_seed: u32,
) -> anyhow::Result<Result<ExecutedTransaction, miden_tx::TransactionExecutorError>> {
    let source_manager = Arc::new(DefaultSourceManager::default());

    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note = NoteBuilder::new(sender_account_id, &mut rng)
        .note_type(NoteType::Private)
        .script(note_script)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet_id, &[], &[note])?
        .with_source_manager(source_manager)
        .build()?;

    Ok(tx_context.execute().await)
}

fn create_set_burn_policy_note_script(policy_root: Word) -> String {
    format!(
        r#"
        use miden::standards::faucets::policies::policy_manager

        @note_script
        pub proc main
            padw padw padw
            push.{policy_root}
            call.policy_manager::set_burn_policy
            dropw dropw dropw dropw
        end
        "#
    )
}

/// Builds a network fungible faucet that opts in to runtime burn policy switching.
///
/// The burn policy manager is constructed with `BurnAllowAll` as the active policy and
/// additionally registers `BurnOwnerOnly::root()` in the allowed-policies map; both
/// `BurnAllowAll` and `BurnOwnerOnly` policy components are installed alongside it. This is
/// the explicit setup required for tests that exercise `set_burn_policy` switching.
fn build_network_faucet_with_burn_switching(
    builder: &mut MockChainBuilder,
    token_symbol: &str,
    max_supply: u64,
    owner: AccountId,
    token_supply: u64,
    mint_policy: MintPolicyConfig,
) -> anyhow::Result<Account> {
    let name = TokenName::new(token_symbol)?;
    let symbol = TokenSymbol::new(token_symbol)?;
    let max_supply = AssetAmount::new(max_supply)?;
    let token_supply = AssetAmount::new(token_supply)?;
    let faucet = FungibleFaucet::builder()
        .name(name)
        .symbol(symbol)
        .decimals(10)
        .max_supply(max_supply)
        .token_supply(token_supply)
        .build()?;

    let token_policy_manager = TokenPolicyManager::new()
        .with_mint_policy(mint_policy, PolicyRegistration::Active)?
        .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)?
        .with_burn_policy(BurnPolicyConfig::OwnerOnly, PolicyRegistration::Reserved)?
        .with_send_policy(TransferPolicy::AllowAll, PolicyRegistration::Active)?
        .with_receive_policy(TransferPolicy::AllowAll, PolicyRegistration::Active)?;

    let account_builder = AccountBuilder::new(builder.rng_mut().random())
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
        .with_components(token_policy_manager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// TESTS MINT FUNGIBLE ASSET
// ================================================================================================

/// Tests that minting assets on an existing faucet succeeds.
#[tokio::test]
async fn minting_fungible_asset_on_existing_faucet_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "TST",
        200,
        None,
    )?;
    let mut mock_chain = builder.build()?;

    let params = FaucetTestParams {
        recipient: Word::from([0, 1, 2, 3u32]),
        tag: NoteTag::default(),
        note_type: NoteType::Private,
        amount: Felt::new_unchecked(100),
    };

    let executed_transaction =
        execute_mint_transaction(&mut mock_chain, faucet.clone(), &params).await?;
    verify_minted_output_note(&executed_transaction, &faucet, &params)?;

    Ok(())
}

/// Tests that mint fails when the minted amount would exceed the max supply.
#[tokio::test]
async fn faucet_contract_mint_fungible_asset_fails_exceeds_max_supply() -> anyhow::Result<()> {
    // CONSTRUCT AND EXECUTE TX (Failure)
    // --------------------------------------------------------------------------------------------
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "TST",
        200,
        None,
    )?;
    let mock_chain = builder.build()?;

    let recipient = Word::from([0, 1, 2, 3u32]);
    let tag = Felt::new_unchecked(4);
    let amount = Felt::new_unchecked(250);

    let tx_script_code = format!(
        "
            begin
                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                push.0
                # => [0, faucet_id_suffix, faucet_id_prefix, amount, tag, note_type, RECIPIENT, ...]

                exec.::miden::protocol::asset::create_fungible_asset
                # => [ASSET_KEY, ASSET_VALUE, tag, note_type, RECIPIENT, ...]

                call.::miden::standards::faucets::fungible::mint_and_send
                # => [note_idx, pad(15)]

                # truncate the stack
                dropw dropw dropw dropw

            end
            ",
        note_type = NoteType::Private as u8,
        recipient = recipient,
        faucet_id_suffix = faucet.id().suffix(),
        faucet_id_prefix = faucet.id().prefix().as_felt(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;
    let tx = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(tx, ERR_FUNGIBLE_ASSET_DISTRIBUTE_AMOUNT_EXCEEDS_MAX_SUPPLY);
    Ok(())
}

// TESTS FOR NEW FAUCET EXECUTION ENVIRONMENT
// ================================================================================================

/// Tests that minting assets on a new faucet succeeds.
#[tokio::test]
async fn minting_fungible_asset_on_new_faucet_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.create_new_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "TST",
        200,
    )?;
    let mut mock_chain = builder.build()?;

    let params = FaucetTestParams {
        recipient: Word::from([0, 1, 2, 3u32]),
        tag: NoteTag::default(),
        note_type: NoteType::Private,
        amount: Felt::new_unchecked(100),
    };

    let executed_transaction =
        execute_mint_transaction(&mut mock_chain, faucet.clone(), &params).await?;
    verify_minted_output_note(&executed_transaction, &faucet, &params)?;

    Ok(())
}

// TESTS BURN FUNGIBLE ASSET
// ================================================================================================

/// Tests that burning a fungible asset on an existing faucet succeeds and proves the transaction.
#[tokio::test]
async fn prove_burning_fungible_asset_on_existing_faucet_succeeds() -> anyhow::Result<()> {
    let max_supply = 200u32;
    let token_supply = 100u32;

    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "TST",
        max_supply.into(),
        Some(token_supply.into()),
    )?;

    let fungible_asset = FungibleAsset::new(faucet.id(), 100).unwrap();

    // need to create a note with the fungible asset to be burned
    let burn_note_script_code = "
        # burn the asset
        @note_script
        pub proc main
            dropw
            # => []

            call.::miden::standards::faucets::fungible::receive_and_burn
            # => [pad(16)]
        end
        ";

    let note = get_note_with_fungible_asset_and_script(fungible_asset, burn_note_script_code);

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mock_chain = builder.build()?;

    let token_metadata = FungibleFaucet::try_from(faucet.storage())?;

    // Check that max_supply at the word's index 0 is 200. The remainder of the word is initialized
    // with the metadata of the faucet which we don't need to check.
    assert_eq!(token_metadata.max_supply(), AssetAmount::from(max_supply));

    // Check that the faucet's token supply has been correctly initialized.
    // The already issued amount should be 100.
    assert_eq!(token_metadata.token_supply(), AssetAmount::from(token_supply));

    // CONSTRUCT AND EXECUTE TX (Success)
    // --------------------------------------------------------------------------------------------
    // Execute the transaction and get the witness
    let executed_transaction = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .build()?
        .execute()
        .await?;

    // Prove, serialize/deserialize and verify the transaction
    prove_and_verify_transaction(executed_transaction.clone()).await?;

    assert_eq!(executed_transaction.account_delta().nonce_delta(), Felt::ONE);
    assert_eq!(executed_transaction.input_notes().get_note(0).id(), note.id());
    Ok(())
}

/// Tests that burning a fungible asset fails when the amount exceeds the token supply.
#[tokio::test]
async fn faucet_burn_fungible_asset_fails_amount_exceeds_token_supply() -> anyhow::Result<()> {
    let max_supply = 200u32;
    let token_supply = 50u32;

    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "TST",
        max_supply.into(),
        Some(token_supply.into()),
    )?;

    // Try to burn 100 tokens when only 50 have been issued
    let burn_amount = 100u64;
    let fungible_asset = FungibleAsset::new(faucet.id(), burn_amount).unwrap();

    let burn_note_script_code = "
        # burn the asset
        @note_script
        pub proc main
            dropw
            # => []

            call.::miden::standards::faucets::fungible::receive_and_burn
            # => [pad(16)]
        end
        ";

    let note = get_note_with_fungible_asset_and_script(fungible_asset, burn_note_script_code);

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mock_chain = builder.build()?;

    let tx = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(tx, ERR_FAUCET_BURN_AMOUNT_EXCEEDS_TOKEN_SUPPLY);
    Ok(())
}

// TEST PUBLIC NOTE CREATION DURING NOTE CONSUMPTION
// ================================================================================================

/// Tests that a public note can be created during note consumption by fetching the note script
/// from the data store. This test verifies the functionality added in issue #1972.
///
/// The test creates a note that calls the faucet's `mint` function to create a PUBLIC
/// P2ID output note. The P2ID script is fetched from the data store during transaction execution.
#[tokio::test]
async fn test_public_note_creation_with_script_from_datastore() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "TST",
        200,
        None,
    )?;

    // Parameters for the PUBLIC note that will be created by the faucet
    let recipient_account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
    let amount = Felt::new_unchecked(75);
    let tag = NoteTag::default();
    let note_type = NoteType::Public;

    // Create a simple output note script
    let output_note_script_code = "@note_script pub proc main push.1 drop end";
    let source_manager = Arc::new(DefaultSourceManager::default());
    let output_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(output_note_script_code)?;

    let serial_num = Word::default();
    let target_account_suffix = recipient_account_id.suffix();
    let target_account_prefix = recipient_account_id.prefix().as_felt();

    // Use a length that is not a multiple of 8 (double word size) to make sure note storage padding
    // is correctly handled
    let note_storage = NoteStorage::new(vec![
        target_account_suffix,
        target_account_prefix,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ONE,
        Felt::ZERO,
    ])?;

    let note_recipient =
        NoteRecipient::new(serial_num, output_note_script.clone(), note_storage.clone());

    let output_script_root = note_recipient.script().root();

    let asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?
        .with_callbacks(AssetCallbackFlag::Enabled);
    let metadata = PartialNoteMetadata::new(faucet.id(), note_type).with_tag(tag);
    let expected_note = Note::new(NoteAssets::new(vec![asset.into()])?, metadata, note_recipient);

    let trigger_note_script_code = format!(
        "
            use miden::protocol::note
            
            @note_script
            pub proc main
                # Build recipient hash from SERIAL_NUM, SCRIPT_ROOT, and STORAGE_COMMITMENT
                push.{script_root}
                # => [SCRIPT_ROOT]

                push.{serial_num}
                # => [SERIAL_NUM, SCRIPT_ROOT]

                # Store note storage in memory
                push.{input0} mem_store.0
                push.{input1} mem_store.1
                push.{input2} mem_store.2
                push.{input3} mem_store.3
                push.{input4} mem_store.4
                push.{input5} mem_store.5
                push.{input6} mem_store.6

                push.7 push.0
                # => [storage_ptr, num_storage_items = 7, SERIAL_NUM, SCRIPT_ROOT]

                exec.note::compute_and_store_recipient
                # => [RECIPIENT]

                # Now call mint with the computed recipient
                push.{note_type}
                push.{tag}
                push.{amount}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                push.0
                # => [0, faucet_id_suffix, faucet_id_prefix, amount, tag, note_type, RECIPIENT]

                exec.::miden::protocol::asset::create_fungible_asset
                # => [ASSET_KEY, ASSET_VALUE, tag, note_type, RECIPIENT]

                call.::miden::standards::faucets::fungible::mint_and_send
                # => [note_idx, pad(15)]

                # Truncate the stack
                dropw dropw dropw dropw
            end
            ",
        note_type = note_type as u8,
        input0 = note_storage.items()[0],
        input1 = note_storage.items()[1],
        input2 = note_storage.items()[2],
        input3 = note_storage.items()[3],
        input4 = note_storage.items()[4],
        input5 = note_storage.items()[5],
        input6 = note_storage.items()[6],
        script_root = output_script_root,
        serial_num = serial_num,
        tag = u32::from(tag),
        amount = amount,
        faucet_id_suffix = faucet.id().suffix(),
        faucet_id_prefix = faucet.id().prefix().as_felt(),
    );

    // Create the trigger note that will call mint
    let mut rng = RandomCoin::new([Felt::from(1u32); 4].into());
    let trigger_note = NoteBuilder::new(faucet.id(), &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([1, 2, 3, 4u32]))
        .code(trigger_note_script_code)
        .build()?;

    builder.add_output_note(RawOutputNote::Full(trigger_note.clone()));
    let mock_chain = builder.build()?;

    // Execute the transaction - this should fetch the output note script from the data store.
    // Note: There is intentionally no call to extend_expected_output_notes here, so the
    // transaction host is forced to request the script from the data store during execution.
    let executed_transaction = mock_chain
        .build_tx_context(faucet.id(), &[trigger_note.id()], &[])?
        .add_note_script(output_note_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    assert_note_created!(
        executed_transaction,
        note_type: NoteType::Public,
        sender: faucet.id(),
        assets: [FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?
            .with_callbacks(AssetCallbackFlag::Enabled)],
    );

    let output_note = executed_transaction.output_notes().get_note(0);
    let full_note = match output_note {
        RawOutputNote::Full(note) => note,
        _ => panic!("Expected OutputNote::Full variant"),
    };

    assert_eq!(
        full_note.recipient().storage().commitment(),
        note_storage.commitment(),
        "Output note storage commitment should match expected storage commitment"
    );
    assert_eq!(
        full_note.recipient().storage().num_items(),
        note_storage.num_items(),
        "Output note number of storage items should match expected number of storage items"
    );

    // Verify the output note ID matches the expected note ID
    assert_eq!(full_note.id(), expected_note.id());

    // Verify nonce was incremented
    assert_eq!(executed_transaction.account_delta().nonce_delta(), Felt::ONE);

    Ok(())
}

// TESTS NETWORK FAUCET
// ================================================================================================

/// Tests minting on network faucet
#[tokio::test]
async fn network_faucet_mint() -> anyhow::Result<()> {
    let max_supply = 1000u64;
    let token_supply = 50u64;

    let mut builder = MockChain::builder();

    let faucet_owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let faucet = builder.add_existing_network_faucet(
        "NET",
        max_supply,
        faucet_owner_account_id,
        Some(token_supply),
        MintPolicyConfig::OwnerOnly,
        [],
    )?;

    // Create a target account to consume the minted note
    let mut target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    // Check the Network Fungible Faucet's max supply.
    let actual_max_supply = FungibleFaucet::try_from(faucet.storage())?.max_supply();
    assert_eq!(actual_max_supply.as_u64(), max_supply);

    // Check that the creator account ID is stored in the ownership slot.
    // Word: [owner_suffix, owner_prefix, nominated_suffix, nominated_prefix]
    let stored_owner_id = faucet.storage().get_item(Ownable2Step::slot_name()).unwrap();
    assert_eq!(
        stored_owner_id[0],
        Felt::new_unchecked(faucet_owner_account_id.suffix().as_canonical_u64())
    );
    assert_eq!(stored_owner_id[1], faucet_owner_account_id.prefix().as_felt());
    assert_eq!(stored_owner_id[2], Felt::ZERO); // no nominated owner
    assert_eq!(stored_owner_id[3], Felt::ZERO);

    // Check that the faucet's token supply has been correctly initialized.
    // The already issued amount should be 50.
    let initial_token_supply = FungibleFaucet::try_from(faucet.storage())?.token_supply();
    assert_eq!(initial_token_supply.as_u64(), token_supply);

    // CREATE MINT NOTE USING STANDARD NOTE
    // --------------------------------------------------------------------------------------------

    let amount = Felt::new_unchecked(75);
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())
        .unwrap()
        .with_callbacks(AssetCallbackFlag::Enabled)
        .into();
    let serial_num = Word::default();

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_mint_output_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset.into()],
        NoteType::Private,
        serial_num,
    )
    .unwrap();
    let recipient = p2id_mint_output_note.recipient().digest();

    // Create the MINT note using the helper function
    let mint_storage = MintNoteStorage::new_private(recipient, mint_asset, output_note_tag.into());

    let mut rng = RandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        faucet_owner_account_id,
        mint_storage,
        NoteAttachments::default(),
        &mut rng,
    )?;

    // Add the MINT note to the mock chain
    builder.add_output_note(RawOutputNote::Full(mint_note.clone()));
    let mut mock_chain = builder.build()?;

    // EXECUTE MINT NOTE AGAINST NETWORK FAUCET
    // --------------------------------------------------------------------------------------------
    let tx_context = mock_chain.build_tx_context(faucet.id(), &[mint_note.id()], &[])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    // Check that a P2ID note was created by the faucet
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    // Verify the output note contains the minted fungible asset
    let expected_asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?
        .with_callbacks(AssetCallbackFlag::Enabled);
    let assets = NoteAssets::new(vec![expected_asset.into()])?;
    let details_commitment =
        NoteDetailsCommitment::from_raw_commitments(recipient, assets.commitment());
    let expected_note_id = NoteId::new(details_commitment, output_note.metadata());

    assert_eq!(output_note.id(), expected_note_id);
    assert_eq!(output_note.metadata().sender(), faucet.id());

    // Apply the transaction to the mock chain
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // CONSUME THE OUTPUT NOTE WITH TARGET ACCOUNT
    // --------------------------------------------------------------------------------------------
    // Execute transaction to consume the output note with the target account
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let consume_tx_context = mock_chain
        .build_tx_context(target_account.id(), &[], slice::from_ref(&p2id_mint_output_note))?
        .foreign_accounts(vec![faucet_inputs])
        .build()?;
    let consume_executed_transaction = consume_tx_context.execute().await?;

    // Apply the delta to the target account and verify the asset was added to the account's vault
    target_account.apply_delta(consume_executed_transaction.account_delta())?;

    // Verify the account's vault now contains the expected fungible asset
    let actual_asset = target_account.vault().get(expected_asset.vault_key()).unwrap();
    assert_eq!(actual_asset, Asset::from(expected_asset));

    Ok(())
}

// TESTS FOR NETWORK FAUCET OWNERSHIP
// ================================================================================================

/// Tests that the owner can mint assets on network faucet.
#[tokio::test]
async fn test_network_faucet_owner_can_mint() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let faucet = builder.add_existing_network_faucet(
        "NET",
        1000,
        owner_account_id,
        Some(50),
        MintPolicyConfig::OwnerOnly,
        [],
    )?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let amount = Felt::new_unchecked(75);
    let mint_asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?;

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset.into()],
        NoteType::Private,
        Word::default(),
    )?;
    let recipient = p2id_note.recipient().digest();

    let mint_inputs = MintNoteStorage::new_private(recipient, mint_asset, output_note_tag.into());

    let mut rng = RandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        owner_account_id,
        mint_inputs,
        NoteAttachments::default(),
        &mut rng,
    )?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[], &[mint_note])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 1);

    Ok(())
}

/// Tests that set_mint_policy rejects policy roots outside the allowed policy roots map.
#[tokio::test]
async fn test_network_faucet_set_policy_rejects_non_allowed_root() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    // This root exists in account code, but is not in the mint policy allowlist.
    let invalid_policy_root = FungibleFaucet::mint_and_send_root().as_word();
    let set_policy_note_script = compile_note_script(&format!(
        r#"
        use miden::standards::faucets::policies::policy_manager

        @note_script
        pub proc main
            repeat.12 push.0 end
            push.{invalid_policy_root}
            call.policy_manager::set_mint_policy
            dropw dropw dropw dropw
        end
        "#
    ))?;

    let faucet = builder.add_existing_network_faucet(
        "NET",
        1000,
        owner_account_id,
        Some(0),
        MintPolicyConfig::OwnerOnly,
        [set_policy_note_script.root()],
    )?;
    let mock_chain = builder.build()?;

    let result = execute_faucet_note_script(
        &mock_chain,
        faucet.id(),
        owner_account_id,
        set_policy_note_script,
        400,
    )
    .await?;

    assert_transaction_executor_error!(result, ERR_MINT_POLICY_ROOT_NOT_ALLOWED);

    Ok(())
}

/// Tests that set_burn_policy rejects policy roots outside the allowed policy roots map.
#[tokio::test]
async fn test_network_faucet_set_burn_policy_rejects_non_allowed_root() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    // This root exists in account code, but is not in the burn policy allowlist.
    let invalid_policy_root = FungibleFaucet::receive_and_burn_root().as_word();
    let set_policy_note_script =
        compile_note_script(&create_set_burn_policy_note_script(invalid_policy_root))?;

    let faucet = builder.add_existing_network_faucet(
        "NET",
        1000,
        owner_account_id,
        Some(0),
        MintPolicyConfig::OwnerOnly,
        [set_policy_note_script.root()],
    )?;
    let mock_chain = builder.build()?;

    let result = execute_faucet_note_script(
        &mock_chain,
        faucet.id(),
        owner_account_id,
        set_policy_note_script,
        401,
    )
    .await?;

    assert_transaction_executor_error!(result, ERR_BURN_POLICY_ROOT_NOT_ALLOWED);

    Ok(())
}

/// Tests that a non-owner cannot mint assets on network faucet.
#[tokio::test]
async fn test_network_faucet_non_owner_cannot_mint() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let non_owner_account_id =
        AccountId::dummy([2; 15], AccountIdVersion::Version1, AccountType::Private);

    let faucet = builder.add_existing_network_faucet(
        "NET",
        1000,
        owner_account_id,
        Some(50),
        MintPolicyConfig::OwnerOnly,
        [],
    )?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let amount = Felt::new_unchecked(75);
    let mint_asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?;

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset.into()],
        NoteType::Private,
        Word::default(),
    )?;
    let recipient = p2id_note.recipient().digest();

    let mint_inputs = MintNoteStorage::new_private(recipient, mint_asset, output_note_tag.into());

    // Create mint note from NON-OWNER
    let mut rng = RandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        non_owner_account_id,
        mint_inputs,
        NoteAttachments::default(),
        &mut rng,
    )?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[], &[mint_note])?.build()?;
    let result = tx_context.execute().await;

    // The mint function uses ERR_ONLY_OWNER, which is "note sender is not the owner"
    let expected_error = ERR_SENDER_NOT_OWNER;
    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// Tests that the owner is correctly stored and can be read from storage.
#[tokio::test]
async fn test_network_faucet_owner_storage() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let faucet = builder.add_existing_network_faucet(
        "NET",
        1000,
        owner_account_id,
        Some(50),
        MintPolicyConfig::OwnerOnly,
        [],
    )?;
    let _mock_chain = builder.build()?;

    // Verify owner is stored correctly
    let stored_owner = faucet.storage().get_item(Ownable2Step::slot_name())?;

    // Word: [owner_suffix, owner_prefix, nominated_suffix, nominated_prefix]
    assert_eq!(
        stored_owner[0],
        Felt::new_unchecked(owner_account_id.suffix().as_canonical_u64())
    );
    assert_eq!(stored_owner[1], owner_account_id.prefix().as_felt());
    assert_eq!(stored_owner[2], Felt::ZERO); // no nominated owner
    assert_eq!(stored_owner[3], Felt::ZERO);

    Ok(())
}

/// Tests that two-step transfer_ownership updates the owner correctly.
/// Step 1: Owner nominates a new owner via transfer_ownership.
/// Step 2: Nominated owner accepts via accept_ownership.
#[tokio::test]
async fn test_network_faucet_transfer_ownership() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Setup: Create initial owner and new owner accounts
    let initial_owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let new_owner_account_id =
        AccountId::dummy([2; 15], AccountIdVersion::Version1, AccountType::Private);

    // Step 1: Create transfer_ownership note script to nominate new owner
    let transfer_note_script_code = format!(
        r#"
        use miden::standards::access::ownable2step

        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{new_owner_prefix}
            push.{new_owner_suffix}
            call.ownable2step::transfer_ownership
            dropw dropw dropw dropw
        end
        "#,
        new_owner_prefix = new_owner_account_id.prefix().as_felt(),
        new_owner_suffix = Felt::new_unchecked(new_owner_account_id.suffix().as_canonical_u64()),
    );

    // Step 2: Accept ownership as the nominated owner
    let accept_note_script_code = r#"
        use miden::standards::access::ownable2step

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.ownable2step::accept_ownership
            dropw dropw dropw dropw
        end
        "#;

    let transfer_script = compile_note_script(&transfer_note_script_code)?;
    let accept_script = compile_note_script(accept_note_script_code)?;

    let faucet = builder.add_existing_network_faucet(
        "NET",
        1000,
        initial_owner_account_id,
        Some(50),
        MintPolicyConfig::OwnerOnly,
        [transfer_script.root(), accept_script.root()],
    )?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let amount = Felt::new_unchecked(75);
    let mint_asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?;

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset.into()],
        NoteType::Private,
        Word::default(),
    )?;
    let recipient = p2id_note.recipient().digest();

    // Sanity Check: Prove that the initial owner can mint assets
    let mint_inputs = MintNoteStorage::new_private(recipient, mint_asset, output_note_tag.into());

    let mut rng = RandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        initial_owner_account_id,
        mint_inputs.clone(),
        NoteAttachments::default(),
        &mut rng,
    )?;

    let source_manager = Arc::new(DefaultSourceManager::default());

    // Create the transfer note and add it to the builder so it exists on-chain
    let mut rng = RandomCoin::new([Felt::from(200u32); 4].into());
    let transfer_note = NoteBuilder::new(initial_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([11, 22, 33, 44u32]))
        .script(transfer_script)
        .build()?;

    // Add the transfer note to the builder before building the chain
    builder.add_output_note(RawOutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;

    // Prove the block to make the transfer note exist on-chain
    mock_chain.prove_next_block()?;

    // Sanity Check: Execute mint transaction to verify initial owner can mint
    let tx_context = mock_chain.build_tx_context(faucet.id(), &[], &[mint_note])?.build()?;
    let executed_transaction = tx_context.execute().await?;
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);

    // Execute transfer_ownership via note script (nominates new owner)
    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[transfer_note.id()], &[])?
        .with_source_manager(source_manager.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // Persistence: Apply the transaction to update the faucet state
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_delta(executed_transaction.account_delta())?;

    let mut rng = RandomCoin::new([Felt::from(400u32); 4].into());
    let accept_note = NoteBuilder::new(new_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([55, 66, 77, 88u32]))
        .script(accept_script)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(updated_faucet.clone(), &[], slice::from_ref(&accept_note))?
        .with_source_manager(source_manager.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    let mut final_faucet = updated_faucet.clone();
    final_faucet.apply_delta(executed_transaction.account_delta())?;

    // Verify that owner changed to new_owner and nominated was cleared
    // Word: [owner_suffix, owner_prefix, nominated_suffix, nominated_prefix]
    let stored_owner = final_faucet.storage().get_item(Ownable2Step::slot_name())?;
    assert_eq!(
        stored_owner[0],
        Felt::new_unchecked(new_owner_account_id.suffix().as_canonical_u64())
    );
    assert_eq!(stored_owner[1], new_owner_account_id.prefix().as_felt());
    assert_eq!(stored_owner[2], Felt::ZERO); // nominated cleared
    assert_eq!(stored_owner[3], Felt::ZERO);

    Ok(())
}

/// Tests that only the owner can transfer ownership.
#[tokio::test]
async fn test_network_faucet_only_owner_can_transfer() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let non_owner_account_id =
        AccountId::dummy([2; 15], AccountIdVersion::Version1, AccountType::Private);

    let new_owner_account_id =
        AccountId::dummy([3; 15], AccountIdVersion::Version1, AccountType::Private);

    // Create transfer ownership note script
    let transfer_note_script_code = format!(
        r#"
        use miden::standards::access::ownable2step

        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{new_owner_prefix}
            push.{new_owner_suffix}
            call.ownable2step::transfer_ownership
            dropw dropw dropw dropw
        end
        "#,
        new_owner_prefix = new_owner_account_id.prefix().as_felt(),
        new_owner_suffix = Felt::new_unchecked(new_owner_account_id.suffix().as_canonical_u64()),
    );

    let transfer_script = compile_note_script(&transfer_note_script_code)?;

    let faucet = builder.add_existing_network_faucet(
        "NET",
        1000,
        owner_account_id,
        Some(50),
        MintPolicyConfig::OwnerOnly,
        [transfer_script.root()],
    )?;
    let mock_chain = builder.build()?;

    let source_manager = Arc::new(DefaultSourceManager::default());

    // Create a note from NON-OWNER that tries to transfer ownership
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note = NoteBuilder::new(non_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([10, 20, 30, 40u32]))
        .script(transfer_script)
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[transfer_note])?
        .with_source_manager(source_manager.clone())
        .build()?;
    let result = tx_context.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

/// Tests that renounce_ownership clears the owner correctly.
#[tokio::test]
async fn test_network_faucet_renounce_ownership() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let new_owner_account_id =
        AccountId::dummy([2; 15], AccountIdVersion::Version1, AccountType::Private);

    // Create renounce_ownership note script
    let renounce_note_script_code = r#"
        use miden::standards::access::ownable2step

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.ownable2step::renounce_ownership
            dropw dropw dropw dropw
        end
        "#;

    // Create transfer note script (will be used after renounce)
    let transfer_note_script_code = format!(
        r#"
        use miden::standards::access::ownable2step

        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{new_owner_prefix}
            push.{new_owner_suffix}
            call.ownable2step::transfer_ownership
            dropw dropw dropw dropw
        end
        "#,
        new_owner_prefix = new_owner_account_id.prefix().as_felt(),
        new_owner_suffix = Felt::new_unchecked(new_owner_account_id.suffix().as_canonical_u64()),
    );

    let renounce_script = compile_note_script(renounce_note_script_code)?;
    let transfer_script = compile_note_script(&transfer_note_script_code)?;

    let faucet = builder.add_existing_network_faucet(
        "NET",
        1000,
        owner_account_id,
        Some(50),
        MintPolicyConfig::OwnerOnly,
        [renounce_script.root(), transfer_script.root()],
    )?;

    // Check stored value before renouncing
    let stored_owner_before = faucet.storage().get_item(Ownable2Step::slot_name())?;
    assert_eq!(stored_owner_before[0], owner_account_id.suffix());
    assert_eq!(stored_owner_before[1], owner_account_id.prefix().as_felt());

    let source_manager = Arc::new(DefaultSourceManager::default());

    let mut rng = RandomCoin::new([Felt::from(200u32); 4].into());
    let renounce_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([11, 22, 33, 44u32]))
        .script(renounce_script)
        .build()?;

    let mut rng = RandomCoin::new([Felt::from(300u32); 4].into());
    let transfer_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([50, 60, 70, 80u32]))
        .script(transfer_script)
        .build()?;

    builder.add_output_note(RawOutputNote::Full(renounce_note.clone()));
    builder.add_output_note(RawOutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Execute renounce_ownership
    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[renounce_note.id()], &[])?
        .with_source_manager(source_manager.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_delta(executed_transaction.account_delta())?;

    // Check stored value after renouncing - should be zero
    let stored_owner_after = updated_faucet.storage().get_item(Ownable2Step::slot_name())?;
    assert_eq!(stored_owner_after[0], Felt::ZERO);
    assert_eq!(stored_owner_after[1], Felt::ZERO);
    assert_eq!(stored_owner_after[2], Felt::ZERO);
    assert_eq!(stored_owner_after[3], Felt::ZERO);

    // Try to transfer ownership - should fail because there's no owner
    mock_chain.prove_next_block()?;

    let tx_context = mock_chain
        .build_tx_context(updated_faucet.id(), &[transfer_note.id()], &[])?
        .with_source_manager(source_manager.clone())
        .build()?;
    let result = tx_context.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

// TESTS FOR FAUCET PROCEDURE COMPATIBILITY
// ================================================================================================

/// Tests that the default network faucet burn policy root is exported by the account code.
#[test]
fn test_network_faucet_contains_default_burn_policy_root() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let faucet = builder.add_existing_network_faucet(
        "NET",
        200,
        owner_account_id,
        Some(100),
        MintPolicyConfig::OwnerOnly,
        [],
    )?;

    let stored_root = faucet.storage().get_item(TokenPolicyManager::active_burn_policy_slot())?;

    assert_eq!(stored_root, BurnAllowAll::root().as_word());
    assert!(faucet.code().has_procedure(stored_root));

    Ok(())
}

/// Tests burning on network faucet
#[tokio::test]
async fn network_faucet_burn() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let faucet_owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let mut faucet = builder.add_existing_network_faucet(
        "NET",
        200,
        faucet_owner_account_id,
        Some(100),
        MintPolicyConfig::OwnerOnly,
        [],
    )?;

    let burn_amount = 100u64;
    let fungible_asset = FungibleAsset::new(faucet.id(), burn_amount).unwrap();

    // CREATE BURN NOTE
    // --------------------------------------------------------------------------------------------
    let mut rng = RandomCoin::new([Felt::from(99u32); 4].into());
    let note = BurnNote::create(
        faucet_owner_account_id,
        faucet.id(),
        fungible_asset.into(),
        NoteAttachments::default(),
        &mut rng,
    )?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Check the initial token issuance before burning
    let initial_token_supply = FungibleFaucet::try_from(faucet.storage())?.token_supply();
    assert_eq!(initial_token_supply, AssetAmount::from(100u32));

    // EXECUTE BURN NOTE AGAINST NETWORK FAUCET
    // --------------------------------------------------------------------------------------------
    let tx_context = mock_chain.build_tx_context(faucet.id(), &[note.id()], &[])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    // Check that the burn was successful - no output notes should be created for burn
    assert_eq!(executed_transaction.output_notes().num_notes(), 0);

    // Verify the transaction was executed successfully
    assert_eq!(executed_transaction.account_delta().nonce_delta(), Felt::ONE);
    assert_eq!(executed_transaction.input_notes().get_note(0).id(), note.id());

    // Apply the delta to the faucet account and verify the token issuance decreased
    faucet.apply_delta(executed_transaction.account_delta())?;
    let final_token_supply = FungibleFaucet::try_from(faucet.storage())?.token_supply();
    assert_eq!(
        final_token_supply,
        AssetAmount::new(initial_token_supply.as_u64() - burn_amount).unwrap()
    );

    Ok(())
}

/// Tests that a non-owner cannot burn assets once burn policy is switched to owner-only.
#[tokio::test]
async fn test_network_faucet_non_owner_cannot_burn_when_owner_only_policy_active()
-> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let non_owner_account_id =
        AccountId::dummy([2; 15], AccountIdVersion::Version1, AccountType::Private);

    let faucet = build_network_faucet_with_burn_switching(
        &mut builder,
        "NET",
        200,
        owner_account_id,
        100,
        MintPolicyConfig::OwnerOnly,
    )?;
    let set_policy_note_script =
        create_set_burn_policy_note_script(BurnOwnerOnly::root().as_word());
    let mut rng = RandomCoin::new([Felt::from(500u32); 4].into());
    let set_policy_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(set_policy_note_script.as_str())
        .build()?;
    let burn_amount = 10u64;
    let fungible_asset = FungibleAsset::new(faucet.id(), burn_amount).unwrap();
    let mut rng = RandomCoin::new([Felt::from(501u32); 4].into());
    let burn_note = BurnNote::create(
        non_owner_account_id,
        faucet.id(),
        fungible_asset.into(),
        NoteAttachments::default(),
        &mut rng,
    )?;
    builder.add_output_note(RawOutputNote::Full(set_policy_note.clone()));
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[set_policy_note.id()], &[])?
        .with_source_manager(source_manager.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[burn_note.id()], &[])?.build()?;
    let result = tx_context.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

/// Tests that the owner can still burn assets once burn policy is switched to owner-only.
#[tokio::test]
async fn test_network_faucet_owner_can_burn_when_owner_only_policy_active() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let faucet = build_network_faucet_with_burn_switching(
        &mut builder,
        "NET",
        200,
        owner_account_id,
        100,
        MintPolicyConfig::OwnerOnly,
    )?;
    let set_policy_note_script =
        create_set_burn_policy_note_script(BurnOwnerOnly::root().as_word());
    let mut rng = RandomCoin::new([Felt::from(510u32); 4].into());
    let set_policy_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(set_policy_note_script.as_str())
        .build()?;
    let burn_amount = 10u64;
    let fungible_asset = FungibleAsset::new(faucet.id(), burn_amount).unwrap();
    let mut rng = RandomCoin::new([Felt::from(511u32); 4].into());
    let burn_note = BurnNote::create(
        owner_account_id,
        faucet.id(),
        fungible_asset.into(),
        NoteAttachments::default(),
        &mut rng,
    )?;
    builder.add_output_note(RawOutputNote::Full(set_policy_note.clone()));
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[set_policy_note.id()], &[])?
        .with_source_manager(source_manager.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[burn_note.id()], &[])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 0);
    assert_eq!(executed_transaction.account_delta().nonce_delta(), Felt::ONE);

    Ok(())
}

// TESTS FOR MINT NOTE WITH PRIVATE AND PUBLIC OUTPUT MODES
// ================================================================================================

/// Tests creating a MINT note with different output note types (private/public)
/// The MINT note can create output notes with variable-length inputs for public notes.
#[rstest::rstest]
#[case::private(NoteType::Private)]
#[case::public(NoteType::Public)]
#[tokio::test]
async fn test_mint_note_output_note_types(#[case] note_type: NoteType) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let faucet_owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let faucet = builder.add_existing_network_faucet(
        "NET",
        1000,
        faucet_owner_account_id,
        Some(50),
        MintPolicyConfig::OwnerOnly,
        [],
    )?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let amount = Felt::new_unchecked(75);
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())
        .unwrap()
        .with_callbacks(AssetCallbackFlag::Enabled)
        .into();
    let serial_num = Word::from([1, 2, 3, 4u32]);

    // Create the expected P2ID output note
    let p2id_mint_output_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset.into()],
        note_type,
        serial_num,
    )
    .unwrap();

    // Create MINT note based on note type
    let mint_storage = match note_type {
        NoteType::Private => {
            let output_note_tag = NoteTag::with_account_target(target_account.id());
            let recipient = p2id_mint_output_note.recipient().digest();
            MintNoteStorage::new_private(recipient, mint_asset, output_note_tag.into())
        },
        NoteType::Public => {
            let output_note_tag = NoteTag::with_account_target(target_account.id());
            let p2id_script = StandardNote::P2ID.script();
            let p2id_storage =
                vec![target_account.id().suffix(), target_account.id().prefix().as_felt()];
            let note_storage = NoteStorage::new(p2id_storage)?;
            let recipient = NoteRecipient::new(serial_num, p2id_script, note_storage);
            MintNoteStorage::new_public(recipient, mint_asset, output_note_tag.into())?
        },
    };

    let mut rng = RandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        faucet_owner_account_id,
        mint_storage.clone(),
        NoteAttachments::default(),
        &mut rng,
    )?;

    builder.add_output_note(RawOutputNote::Full(mint_note.clone()));
    let mut mock_chain = builder.build()?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[mint_note.id()], &[])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    match note_type {
        NoteType::Private => {
            // For private notes, we can only compare basic properties since we get
            // OutputNote::Partial
            assert_eq!(output_note.id(), p2id_mint_output_note.id());
            assert_eq!(output_note.metadata(), p2id_mint_output_note.metadata());
        },
        NoteType::Public => {
            // For public notes, we get OutputNote::Full and can compare key properties
            let created_note = match output_note {
                RawOutputNote::Full(note) => note,
                _ => panic!("Expected OutputNote::Full variant"),
            };

            assert_eq!(created_note, &p2id_mint_output_note);
        },
    }

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // Consume the output note with target account
    let mut target_account_mut = target_account.clone();
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let consume_tx_context = mock_chain
        .build_tx_context(target_account.id(), &[], slice::from_ref(&p2id_mint_output_note))?
        .foreign_accounts(vec![faucet_inputs])
        .build()?;
    let consume_executed_transaction = consume_tx_context.execute().await?;

    target_account_mut.apply_delta(consume_executed_transaction.account_delta())?;

    let expected_asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?
        .with_callbacks(AssetCallbackFlag::Enabled);
    let balance = target_account_mut.vault().get_balance(expected_asset.vault_key())?;
    assert_eq!(balance, expected_asset.amount());

    Ok(())
}

/// Tests that calling mint multiple times in a single transaction produces output notes
/// with the correct individual amounts, not the cumulative vault totals.
#[tokio::test]
async fn multiple_mints_in_single_tx_produce_correct_amounts() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "TST",
        300,
        None,
    )?;
    let mock_chain = builder.build()?;

    let recipient_1 = Word::from([0, 1, 2, 3u32]);
    let recipient_2 = Word::from([4, 5, 6, 7u32]);
    let tag = NoteTag::default();
    let note_type = NoteType::Private;
    let amount_1: u64 = 100;
    let amount_2: u64 = 50;

    let tx_script_code = format!(
        "
            begin
                # --- First mint: mint {amount_1} tokens to recipient_1 ---
                push.{recipient_1}
                push.{note_type}
                push.{tag}
                push.{amount_1}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                push.0
                # => [0, faucet_id_suffix, faucet_id_prefix, amount_1, tag, note_type, RECIPIENT_1]

                exec.::miden::protocol::asset::create_fungible_asset
                # => [ASSET_KEY, ASSET_VALUE, tag, note_type, RECIPIENT_1]

                call.::miden::standards::faucets::fungible::mint_and_send
                # => [note_idx, pad(15)]

                # clean up the stack before the second call
                dropw dropw dropw dropw

                # --- Second mint: mint {amount_2} tokens to recipient_2 ---
                push.{recipient_2}
                push.{note_type}
                push.{tag}
                push.{amount_2}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                push.0
                # => [0, faucet_id_suffix, faucet_id_prefix, amount_2, tag, note_type, RECIPIENT_2]

                exec.::miden::protocol::asset::create_fungible_asset
                # => [ASSET_KEY, ASSET_VALUE, tag, note_type, RECIPIENT_2]

                call.::miden::standards::faucets::fungible::mint_and_send
                # => [note_idx, pad(15)]

                # truncate the stack
                dropw dropw dropw dropw
            end
            ",
        note_type = note_type as u8,
        tag = u32::from(tag),
        faucet_id_suffix = faucet.id().suffix(),
        faucet_id_prefix = faucet.id().prefix().as_felt(),
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_tx_script(tx_script_code)?;
    let tx_context = mock_chain
        .build_tx_context(faucet.clone(), &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify two output notes were created
    assert_eq!(executed_transaction.output_notes().num_notes(), 2);

    // Verify first note has exactly amount_1 tokens.
    let expected_asset_1: Asset = FungibleAsset::new(faucet.id(), amount_1)?
        .with_callbacks(AssetCallbackFlag::Enabled)
        .into();
    let output_note_1 = executed_transaction.output_notes().get_note(0);
    let assets_1 = NoteAssets::new(vec![expected_asset_1])?;
    let details_commitment_1 =
        NoteDetailsCommitment::from_raw_commitments(recipient_1, assets_1.commitment());
    let expected_id_1 = NoteId::new(details_commitment_1, output_note_1.metadata());
    assert_eq!(output_note_1.id(), expected_id_1);

    // Verify second note has exactly amount_2 tokens.
    let expected_asset_2: Asset = FungibleAsset::new(faucet.id(), amount_2)?
        .with_callbacks(AssetCallbackFlag::Enabled)
        .into();
    let output_note_2 = executed_transaction.output_notes().get_note(1);
    let assets_2 = NoteAssets::new(vec![expected_asset_2])?;
    let details_commitment_2 =
        NoteDetailsCommitment::from_raw_commitments(recipient_2, assets_2.commitment());
    let expected_id_2 = NoteId::new(details_commitment_2, output_note_2.metadata());
    assert_eq!(output_note_2.id(), expected_id_2);

    Ok(())
}

// NetworkFungibleFaucet + TransferPolicy::Blocklist (post-#2879 happy path)
// ================================================================================================

/// Builds a network faucet with [`TransferPolicy::Blocklist`] on both send and receive,
/// so the manager populates the asset-callback slots and callbacks dispatch to the
/// basic blocklist predicate.
fn build_network_faucet_with_blocklist_transfer(
    builder: &mut MockChainBuilder,
    token_symbol: &str,
    max_supply: u64,
    owner: AccountId,
    token_supply: u64,
) -> anyhow::Result<Account> {
    let name = TokenName::new(token_symbol)?;
    let symbol = TokenSymbol::new(token_symbol)?;
    let max_supply = AssetAmount::new(max_supply)?;
    let token_supply = AssetAmount::new(token_supply)?;
    let faucet = FungibleFaucet::builder()
        .name(name)
        .symbol(symbol)
        .decimals(10)
        .max_supply(max_supply)
        .token_supply(token_supply)
        .build()?;

    let token_policy_manager = TokenPolicyManager::new()
        .with_mint_policy(MintPolicyConfig::OwnerOnly, PolicyRegistration::Active)?
        .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)?
        .with_send_policy(TransferPolicy::Blocklist, PolicyRegistration::Active)?
        .with_receive_policy(TransferPolicy::Blocklist, PolicyRegistration::Active)?;

    let account_builder = AccountBuilder::new(builder.rng_mut().random())
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
        .with_components(token_policy_manager);

    builder.add_account_from_builder(
        Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::from([MintNote::script_root()]),
        },
        account_builder,
        AccountState::Exists,
    )
}

/// Verifies that the network-faucet mint pattern works when `TokenPolicyManager` installs
/// asset-callback slots (here via [`TransferPolicy::Blocklist`]).
///
/// Before the protocol fix in 0xMiden/protocol#2879 the kernel rejected this with
/// `ERR_FOREIGN_ACCOUNT_CONTEXT_AGAINST_NATIVE_ACCOUNT` because the issuing faucet was also
/// the native account during the mint-note flow. The fix short-circuits callback dispatch
/// when the issuer equals the native account, so this test now succeeds.
#[tokio::test]
async fn network_faucet_mint_with_blocklist() -> anyhow::Result<()> {
    let max_supply = 1000u64;
    let token_supply = 50u64;

    let mut builder = MockChain::builder();

    let faucet_owner_account_id =
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Private);

    let faucet = build_network_faucet_with_blocklist_transfer(
        &mut builder,
        "NET",
        max_supply,
        faucet_owner_account_id,
        token_supply,
    )?;

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let amount = Felt::new_unchecked(75);
    // The blocklist faucet has asset callbacks enabled, so the asset embedded in the MINT
    // note must carry the matching callback flag: `mint_and_send` binds the mint to the
    // full ASSET_KEY derived for the faucet, which encodes that flag.
    let mint_asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())
        .unwrap()
        .with_callbacks(AssetCallbackFlag::Enabled);
    let serial_num = Word::default();

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_mint_output_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset.into()],
        NoteType::Private,
        serial_num,
    )
    .unwrap();
    let recipient = p2id_mint_output_note.recipient().digest();

    let mint_storage = MintNoteStorage::new_private(recipient, mint_asset, output_note_tag.into());

    let mut rng = RandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        faucet_owner_account_id,
        mint_storage,
        NoteAttachments::default(),
        &mut rng,
    )?;

    builder.add_output_note(RawOutputNote::Full(mint_note.clone()));
    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_tx_context(faucet.id(), &[mint_note.id()], &[])?
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    Ok(())
}
