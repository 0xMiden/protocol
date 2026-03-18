use anyhow::Result;
use miden_agglayer::claim_note::{Keccak256Output, ProofData, SmtNode};
use miden_agglayer::{
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    EthAddressFormat,
    EthAmount,
    ExitRoot,
    GlobalIndex,
    LeafData,
    MetadataHash,
    UpdateGerNote,
    create_claim_note,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, FieldElement, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain, TransactionContext};
use miden_tx::utils::hex_to_bytes;
use rand::Rng;
use serde::Deserialize;

// EMBEDDED TEST VECTOR JSON FILES
// ================================================================================================

/// Bridge asset test vectors JSON — contains test data for an L1 bridgeAsset transaction.
const BRIDGE_ASSET_VECTORS_JSON: &str = include_str!(
    "../../../crates/miden-agglayer/solidity-compat/test-vectors/claim_asset_vectors_local_tx.json"
);

/// Rollup deposit test vectors JSON — contains test data for a rollup deposit with two-level
/// Merkle proofs.
const ROLLUP_ASSET_VECTORS_JSON: &str = include_str!(
    "../../../crates/miden-agglayer/solidity-compat/test-vectors/claim_asset_vectors_rollup_tx.json"
);

// TEST VECTOR TYPES
// ================================================================================================

/// Deserializes a JSON value that may be either a number or a string into a `String`.
fn deserialize_uint_to_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        _ => Err(serde::de::Error::custom("expected a number or string for amount")),
    }
}

/// Deserialized leaf value test vector from Solidity-generated JSON.
#[derive(Debug, Deserialize)]
struct LeafValueVector {
    origin_network: u32,
    origin_token_address: String,
    #[allow(dead_code)]
    destination_network: u32,
    destination_address: String,
    #[serde(deserialize_with = "deserialize_uint_to_string")]
    amount: String,
    metadata_hash: String,
}

impl LeafValueVector {
    fn to_leaf_data(&self) -> LeafData {
        LeafData {
            origin_network: self.origin_network,
            origin_token_address: EthAddressFormat::from_hex(&self.origin_token_address)
                .expect("valid origin token address hex"),
            destination_network: self.destination_network,
            destination_address: EthAddressFormat::from_hex(&self.destination_address)
                .expect("valid destination address hex"),
            amount: EthAmount::from_uint_str(&self.amount).expect("valid amount uint string"),
            metadata_hash: MetadataHash::new(
                hex_to_bytes(&self.metadata_hash).expect("valid metadata hash hex"),
            ),
        }
    }
}

/// Deserialized proof value test vector from Solidity-generated JSON.
#[derive(Debug, Deserialize)]
struct ProofValueVector {
    smt_proof_local_exit_root: Vec<String>,
    smt_proof_rollup_exit_root: Vec<String>,
    global_index: String,
    mainnet_exit_root: String,
    rollup_exit_root: String,
    global_exit_root: String,
    claimed_global_index_hash_chain: String,
}

impl ProofValueVector {
    fn to_proof_data(&self) -> ProofData {
        let smt_proof_local: [SmtNode; 32] = self
            .smt_proof_local_exit_root
            .iter()
            .map(|s| SmtNode::new(hex_to_bytes(s).expect("valid smt proof hex")))
            .collect::<Vec<_>>()
            .try_into()
            .expect("expected 32 SMT proof nodes for local exit root");

        let smt_proof_rollup: [SmtNode; 32] = self
            .smt_proof_rollup_exit_root
            .iter()
            .map(|s| SmtNode::new(hex_to_bytes(s).expect("valid smt proof hex")))
            .collect::<Vec<_>>()
            .try_into()
            .expect("expected 32 SMT proof nodes for rollup exit root");

        ProofData {
            smt_proof_local_exit_root: smt_proof_local,
            smt_proof_rollup_exit_root: smt_proof_rollup,
            global_index: GlobalIndex::from_hex(&self.global_index)
                .expect("valid global index hex"),
            mainnet_exit_root: Keccak256Output::new(
                hex_to_bytes(&self.mainnet_exit_root).expect("valid mainnet exit root hex"),
            ),
            rollup_exit_root: Keccak256Output::new(
                hex_to_bytes(&self.rollup_exit_root).expect("valid rollup exit root hex"),
            ),
        }
    }
}

/// Deserialized claim asset test vector from Solidity-generated JSON.
#[derive(Debug, Deserialize)]
struct ClaimAssetVector {
    #[serde(flatten)]
    proof: ProofValueVector,
    #[serde(flatten)]
    leaf: LeafValueVector,
}

/// Identifies the source of claim data used in CLAIM note benchmarks.
#[derive(Debug, Clone, Copy)]
pub enum ClaimDataSource {
    /// Locally simulated bridgeAsset data (L1 to Miden bridging).
    L1ToMiden,
    /// Rollup deposit data (L2 to Miden bridging).
    L2ToMiden,
}

impl ClaimDataSource {
    fn get_data(self) -> (ProofData, LeafData, ExitRoot, Keccak256Output) {
        let json = match self {
            ClaimDataSource::L1ToMiden => BRIDGE_ASSET_VECTORS_JSON,
            ClaimDataSource::L2ToMiden => ROLLUP_ASSET_VECTORS_JSON,
        };
        let vector: ClaimAssetVector =
            serde_json::from_str(json).expect("failed to parse claim asset vectors JSON");
        let ger = ExitRoot::new(
            hex_to_bytes(&vector.proof.global_exit_root).expect("valid global exit root hex"),
        );
        let cgi_chain_hash = Keccak256Output::new(
            hex_to_bytes(&vector.proof.claimed_global_index_hash_chain)
                .expect("invalid CGI chain hash"),
        );
        (vector.proof.to_proof_data(), vector.leaf.to_leaf_data(), ger, cgi_chain_hash)
    }
}

// P2ID NOTE SETUPS
// ================================================================================================

/// Returns the transaction context which could be used to run the transaction which creates a
/// single P2ID note.
pub fn tx_create_single_p2id_note() -> Result<TransactionContext> {
    let mut builder = MockChain::builder();
    let fungible_asset = FungibleAsset::mock(150);
    let account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Rpo },
        [fungible_asset],
    )?;

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
    let target_account =
        builder.create_new_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Rpo })?;

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

    let account =
        builder.add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Rpo })?;
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

// CLAIM NOTE SETUPS
// ================================================================================================

/// Sets up and returns the transaction context for executing a CLAIM note against the bridge
/// account.
///
/// This requires executing prerequisite transactions (CONFIG_AGG_BRIDGE and UPDATE_GER) before
/// the CLAIM transaction context can be built. The returned context is ready to execute the
/// CLAIM note consumption.
///
/// The `data_source` parameter selects between L1-to-Miden and L2-to-Miden test vectors.
pub async fn tx_consume_claim_note(data_source: ClaimDataSource) -> Result<TransactionContext> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT (sends CONFIG_AGG_BRIDGE notes)
    let bridge_admin =
        builder.add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Rpo })?;

    // CREATE GER MANAGER ACCOUNT (sends the UPDATE_GER note)
    let ger_manager =
        builder.add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Rpo })?;

    // CREATE BRIDGE ACCOUNT
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin.id(), ger_manager.id());
    builder.add_account(bridge_account.clone())?;

    // GET CLAIM DATA FROM JSON
    let (proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();

    // CREATE AGGLAYER FAUCET ACCOUNT
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT);
    let agglayer_faucet_seed = builder.rng_mut().draw_word();

    let origin_token_address = leaf_data.origin_token_address;
    let origin_network = leaf_data.origin_network;
    let scale = 10u8;

    let agglayer_faucet = create_existing_agglayer_faucet(
        agglayer_faucet_seed,
        token_symbol,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account.id(),
        &origin_token_address,
        origin_network,
        scale,
    );
    builder.add_account(agglayer_faucet.clone())?;

    // CREATE SENDER ACCOUNT (for creating the claim note)
    let sender_account_builder =
        miden_protocol::account::Account::builder(builder.rng_mut().random())
            .with_component(miden_standards::account::wallets::BasicWallet);
    let sender_account = builder.add_account_from_builder(
        Auth::IncrNonce,
        sender_account_builder,
        miden_testing::AccountState::Exists,
    )?;

    // CREATE CLAIM NOTE
    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

    let claim_inputs = ClaimNoteStorage {
        proof_data,
        leaf_data,
        miden_claim_amount,
    };

    let claim_note = create_claim_note(
        claim_inputs,
        bridge_account.id(),
        sender_account.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(OutputNote::Full(claim_note.clone()));

    // CREATE CONFIG_AGG_BRIDGE NOTE
    let config_note = ConfigAggBridgeNote::create(
        agglayer_faucet.id(),
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(OutputNote::Full(config_note.clone()));

    // CREATE UPDATE_GER NOTE
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(OutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN
    let mut mock_chain = builder.build()?;

    // TX0: EXECUTE CONFIG_AGG_BRIDGE NOTE TO REGISTER FAUCET IN BRIDGE
    let config_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let config_executed = config_tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: EXECUTE UPDATE_GER NOTE TO STORE GER IN BRIDGE ACCOUNT
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: BUILD CLAIM NOTE TRANSACTION CONTEXT (ready to execute)
    let faucet_foreign_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note])?
        .foreign_accounts(vec![faucet_foreign_inputs])
        .disable_debug_mode()
        .build()?;

    Ok(claim_tx_context)
}
