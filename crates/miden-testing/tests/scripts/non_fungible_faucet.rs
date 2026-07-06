extern crate alloc;

use alloc::sync::Arc;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, AssetCallbackFlag};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, NonFungibleAsset, TokenSymbol};
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step, Pausable};
use miden_standards::account::faucets::{AssetStatus, NonFungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BlocklistOwnerControlled,
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_ACCOUNT_IS_BLOCKED,
    ERR_NFT_ALREADY_ISSUED,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::{BurnNote, MintNote, MintNoteStorage};
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
use rand::RngExt;

/// Builds an existing non-fungible faucet with allow-all policies (so a tx-script mint is gated
/// only by the test auth) and an owner-controlled authority.
fn build_nft_faucet(
    builder: &mut MockChainBuilder,
    symbol: &str,
    owner: AccountId,
    mint_policy: MintPolicy,
) -> anyhow::Result<Account> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new(symbol)?)
        .symbol(TokenSymbol::new(symbol)?)
        .build();

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(mint_policy)
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build();

    let account_builder = AccountBuilder::new(builder.rng_mut().random())
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
        .with_components(token_policy_manager)
        .with_component(Pausable::unpaused());

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// A single mint invocation (push args, call mint_and_send, truncate result).
fn nft_mint_body(commitment: Word, recipient: Word) -> String {
    format!(
        "
            push.{recipient}
            push.{note_type}
            push.{tag}
            push.{commitment}
            # => [COMMITMENT, tag, note_type, RECIPIENT]
            call.::miden::standards::faucets::non_fungible::mint_and_send
            # => [note_idx, pad(15)]
            dropw dropw dropw dropw
        ",
        note_type = NoteType::Private as u8,
        tag = 0u32,
    )
}

/// Builds a tx script that mints an NFT for `commitment` and sends it to `recipient`.
fn nft_mint_script(commitment: Word, recipient: Word) -> String {
    format!(
        "@transaction_script\npub proc main\n{}\nend",
        nft_mint_body(commitment, recipient)
    )
}

async fn execute_nft_mint(
    mock_chain: &mut MockChain,
    faucet: Account,
    commitment: Word,
    recipient: Word,
) -> anyhow::Result<miden_protocol::transaction::ExecutedTransaction> {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let code = nft_mint_script(commitment, recipient);
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(code)?;
    let tx_context = mock_chain
        .build_tx_context(faucet, &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;
    Ok(tx_context.execute().await?)
}

/// Minting an NFT for a fresh commitment produces exactly one output note.
#[tokio::test]
async fn nft_mint_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = AccountId::builder()
        .account_type(AccountType::Private)
        .asset_callbacks(AssetCallbackFlag::Enabled)
        .build_with_seed([1; 32]);
    let faucet = build_nft_faucet(&mut builder, "EC", owner, MintPolicy::allow_all())?;
    let mut mock_chain = builder.build()?;

    let commitment = NonFungibleFaucet::compute_asset_commitment(
        b"token #1 metadata",
        Word::from([7, 8, 9, 10u32]),
    );
    let recipient = Word::from([1, 2, 3, 4u32]);

    let executed = execute_nft_mint(&mut mock_chain, faucet.clone(), commitment, recipient).await?;

    // exactly one output note, addressed to the requested recipient, carrying exactly the minted
    // NFT (the commitment, issued by this faucet, with callbacks enabled)
    assert_eq!(executed.output_notes().num_notes(), 1);
    let note = executed.output_notes().get_note(0);
    assert_eq!(note.recipient_digest(), recipient);
    let expected_asset: Asset = NonFungibleAsset::from_parts(faucet.id(), commitment).into();
    assert_eq!(note.assets().num_assets(), 1);
    assert_eq!(note.assets().iter().next(), Some(&expected_asset));

    Ok(())
}

/// Minting the same commitment twice is rejected: the status registry marks the first as ISSUED,
/// so the second mint fails with `ERR_NFT_ALREADY_ISSUED`. This proves on-chain uniqueness.
#[tokio::test]
async fn nft_mint_duplicate_commitment_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = AccountId::builder().account_type(AccountType::Private).build_with_seed([2; 32]);
    let faucet = build_nft_faucet(&mut builder, "EC", owner, MintPolicy::allow_all())?;
    let mock_chain = builder.build()?;

    let commitment = NonFungibleFaucet::compute_asset_commitment(
        b"duplicate token",
        Word::from([3, 3, 3, 3u32]),
    );
    let recipient = Word::from([4, 4, 4, 4u32]);

    // mint the same commitment twice in one transaction; the second call must fail
    let body = nft_mint_body(commitment, recipient);
    let code = format!("@transaction_script\npub proc main\n{body}\n{body}\nend");

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(code)?;
    let tx = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(tx, ERR_NFT_ALREADY_ISSUED);

    Ok(())
}

/// Full mint -> burn flow: mint an NFT (status ISSUED), then consume a BURN note carrying that
/// NFT against the faucet. A successful burn proves the status transitioned ISSUED -> BURNED,
/// since `receive_and_burn` asserts the prior status was ISSUED. Uses the production
/// `BurnNote` script.
#[tokio::test]
async fn nft_burn_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = AccountId::builder().account_type(AccountType::Private).build_with_seed([5; 32]);
    let faucet = build_nft_faucet(&mut builder, "EC", owner, MintPolicy::allow_all())?;
    let mut mock_chain = builder.build()?;

    let commitment =
        NonFungibleFaucet::compute_asset_commitment(b"burnable token", Word::from([5, 6, 7, 8u32]));
    let recipient = Word::from([9, 9, 9, 9u32]);

    // before minting, the commitment has never been issued
    assert_eq!(
        NonFungibleFaucet::asset_status(faucet.storage(), commitment)?,
        AssetStatus::NotIssued,
    );

    // 1. mint and apply the patch so the faucet records the commitment as ISSUED (required for the
    //    burn below to find the asset in the issued state)
    let minted = execute_nft_mint(&mut mock_chain, faucet.clone(), commitment, recipient).await?;
    let mut faucet = faucet;
    faucet.apply_patch(minted.account_patch())?;

    // after minting, the status API reports the commitment as ISSUED
    assert_eq!(
        NonFungibleFaucet::asset_status(faucet.storage(), commitment)?,
        AssetStatus::Issued,
    );

    // 2. consume a BURN note carrying the minted NFT against the faucet
    let asset: Asset = NonFungibleAsset::from_parts(faucet.id(), commitment).into();
    let sender = AccountId::builder().account_type(AccountType::Private).build_with_seed([6; 32]);
    let mut rng = RandomCoin::new([Felt::from(11u32); 4].into());
    let burn_note: Note = BurnNote::builder()
        .sender(sender)
        .asset(asset)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    // the burn transaction succeeding is part of the assertion: receive_and_burn would abort with
    // ERR_NFT_NOT_ISSUED if the commitment were not in the issued state.
    let burned = mock_chain
        .build_tx_context(faucet.clone(), &[], &[burn_note])?
        .build()?
        .execute()
        .await?;

    // after burning, the status API reports the commitment as BURNED
    faucet.apply_patch(burned.account_patch())?;
    assert_eq!(
        NonFungibleFaucet::asset_status(faucet.storage(), commitment)?,
        AssetStatus::Burned,
    );

    Ok(())
}

/// Minting via the production MINT note (private mode) succeeds: the note's storage carries the
/// recipient, commitment and tag, and the `mint` script calls `mint_and_send`, producing one
/// output note. This exercises the MINT note script end-to-end.
#[tokio::test]
async fn nft_mint_via_note_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = AccountId::builder().account_type(AccountType::Private).build_with_seed([8; 32]);
    let faucet = build_nft_faucet(&mut builder, "EC", owner, MintPolicy::allow_all())?;
    let mock_chain = builder.build()?;

    let commitment = NonFungibleFaucet::compute_asset_commitment(
        b"note-minted token",
        Word::from([1, 2, 3, 4u32]),
    );
    let recipient_digest = Word::from([5, 5, 5, 5u32]);
    let sender = AccountId::builder().account_type(AccountType::Private).build_with_seed([9; 32]);

    let storage = MintNoteStorage::new_non_fungible_private(
        faucet.id(),
        recipient_digest,
        commitment,
        NoteTag::default(),
    );
    let mut rng = RandomCoin::new([Felt::from(33u32); 4].into());
    let mint_note: Note = MintNote::builder()
        .sender(sender)
        .mint_storage(storage)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    let executed = mock_chain
        .build_tx_context(faucet.clone(), &[], &[mint_note])?
        .build()?
        .execute()
        .await?;

    // exactly one output note, addressed to the recipient digest carried by the MINT note,
    // carrying exactly the minted NFT issued by this faucet (with callbacks enabled)
    assert_eq!(executed.output_notes().num_notes(), 1);
    let note = executed.output_notes().get_note(0);
    assert_eq!(note.recipient_digest(), recipient_digest);
    let expected_asset: Asset = NonFungibleAsset::from_parts(faucet.id(), commitment).into();
    assert_eq!(note.assets().num_assets(), 1);
    assert_eq!(note.assets().iter().next(), Some(&expected_asset));

    Ok(())
}

/// The active mint policy is enforced: with an owner-only mint policy, a MINT note whose sender is
/// not the owner is rejected with `ERR_SENDER_NOT_OWNER`.
#[tokio::test]
async fn nft_mint_owner_only_policy_rejects_non_owner() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = AccountId::builder()
        .account_type(AccountType::Private)
        .build_with_seed([10; 32]);
    let faucet = build_nft_faucet(&mut builder, "EC", owner, MintPolicy::owner_only())?;
    let mock_chain = builder.build()?;

    let commitment = NonFungibleFaucet::compute_asset_commitment(
        b"unauthorized mint",
        Word::from([6, 6, 6, 6u32]),
    );
    let recipient_digest = Word::from([7, 7, 7, 7u32]);
    // sender is NOT the owner
    let non_owner = AccountId::builder()
        .account_type(AccountType::Private)
        .build_with_seed([11; 32]);

    let storage = MintNoteStorage::new_non_fungible_private(
        faucet.id(),
        recipient_digest,
        commitment,
        NoteTag::default(),
    );
    let mut rng = RandomCoin::new([Felt::from(44u32); 4].into());
    let mint_note: Note = MintNote::builder()
        .sender(non_owner)
        .mint_storage(storage)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    let tx = mock_chain
        .build_tx_context(faucet.id(), &[], &[mint_note])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(tx, ERR_SENDER_NOT_OWNER);

    Ok(())
}

/// Builds an NFT faucet with a basic-blocklist transfer policy on send and receive, seeding the
/// blocked-accounts set, plus the owner-controlled blocklist admin component.
fn build_nft_faucet_with_blocklist(
    builder: &mut MockChainBuilder,
    owner: AccountId,
    initial_blocked: impl IntoIterator<Item = AccountId>,
) -> anyhow::Result<Account> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("EC")?)
        .symbol(TokenSymbol::new("EC")?)
        .build();

    let account_builder = AccountBuilder::new([55u8; 32])
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(TransferPolicy::with_basic_blocklist(initial_blocked))
                .active_receive_policy(TransferPolicy::empty_basic_blocklist())
                .build(),
        )
        .with_component(Pausable::unpaused())
        .with_component(BlocklistOwnerControlled);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Transferring a faucet NFT to a blocked account is rejected: the receive transfer policy
/// (the faucet's `on_before_asset_added_to_account` callback) fires when the blocked account
/// consumes the P2ID note and fails with `ERR_ACCOUNT_IS_BLOCKED`.
#[tokio::test]
async fn nft_transfer_to_blocked_account_fails() -> anyhow::Result<()> {
    let owner = AccountId::builder()
        .account_type(AccountType::Private)
        .build_with_seed([12; 32]);
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = build_nft_faucet_with_blocklist(&mut builder, owner, [target_account.id()])?;

    // a faucet NFT with callbacks enabled so the transfer policy callback fires on receipt
    let commitment = NonFungibleFaucet::compute_asset_commitment(
        b"blocked transfer",
        Word::from([1, 2, 3, 4u32]),
    );
    let asset: Asset = NonFungibleAsset::from_parts(faucet.id(), commitment).into();
    let p2id_note =
        builder.add_p2id_note(faucet.id(), target_account.id(), &[asset], NoteType::Public)?;

    let mock_chain = builder.build()?;
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[p2id_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);

    Ok(())
}

/// Calls every public read-only accessor against a fresh faucet and asserts the expected values
/// on-chain. This keeps the accessors' stack handling continuously covered (a wrong stack shape
/// would trip one of the in-script asserts and fail the transaction).
#[tokio::test]
async fn nft_public_getters() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let owner = AccountId::builder()
        .account_type(AccountType::Private)
        .build_with_seed([13; 32]);
    let faucet = build_nft_faucet(&mut builder, "EC", owner, MintPolicy::allow_all())?;
    let mock_chain = builder.build()?;

    let expected_symbol: Felt = TokenSymbol::new("EC")?.into();
    let code = format!(
        "
        @transaction_script
        pub proc main
            # status of an unissued asset class is 0 (not issued)
            push.42.123
            call.::miden::standards::faucets::non_fungible::get_asset_status
            eq.0 assert.err=\"expected asset status to be unissued\"

            # get_symbol returns the configured token symbol
            call.::miden::standards::faucets::non_fungible::get_symbol
            push.{expected_symbol}
            assert_eq.err=\"expected token symbol to be EC\"
        end
    "
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script =
        CodeBuilder::with_source_manager(source_manager.clone()).compile_tx_script(code)?;
    mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    Ok(())
}
