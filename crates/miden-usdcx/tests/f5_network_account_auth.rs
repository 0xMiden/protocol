//! Production transaction authorization for the Miden network-account faucet.
//!
//! The faucet has no signing key. Network-account authorization checks its script allowlists;
//! individual procedures also enforce their own rules, such as ADMIN authorization.
//!
//! A new faucet allows twelve note scripts, including `UpgradeNote` and `NetworkAccountConfigNote`.
//! Both require ADMIN. `NetworkAccountConfigNote` can change the script and fee-policy allowlists.
//! `RbacConfigNote` handles role membership and administration.
//!
//! Its initial transaction-script allowlist contains only the expiration script.
//! Other transaction scripts are rejected unless ADMIN changes that allowlist.
//!
//! The remaining tests check mint and burn note attachments, including the faucet target.
//!
//! Sibling suites cover per-operation admin authorization in `f5_admin_notes.rs` and mint transport
//! failures such as missing attachments and tampered attestations in
//! `mint_policy_e2e.rs`.

mod support;

use core::num::NonZeroU16;
use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountComponent};
use miden_protocol::crypto::SequentialCommit;
use miden_protocol::note::{NoteAttachmentScheme, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{
    AuthNetworkAccount,
    NetworkAccount,
    NetworkAccountNoteAllowlist,
    NetworkAccountTxScriptAllowlist,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
    ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_standards::note::{MintNote, NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::{MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_usdcx::account::xreserve::XReserveStablecoinBuilder;
use miden_usdcx::note::xreserve_burn::XReserveBurnNote;
use miden_usdcx::note::xreserve_mint::{
    DepositAttestation,
    XUSDC_MINT_ATTESTATION_NUM_WORDS,
    XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME,
    XUSDC_MINT_TRANSPORT_PAYLOAD_WORD_OFF,
};
use miden_usdcx::xreserve::encoding::{
    CircleDomain,
    DepositIntent,
    ForeignChainAddress,
    MintIntent,
    Signature,
    XReserveBurnItems,
};
use support::*;

// HELPERS
// ================================================================================================

/// A repeatable RNG for note serial numbers.
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A sample burn payload for encoding checks.
fn sample_burn_items() -> XReserveBurnItems {
    XReserveBurnItems {
        dest_domain: CircleDomain::new(9),
        dest_recipient: ForeignChainAddress::new([0xabu8; 32]),
    }
}

/// Byte offset of the 32-byte `remoteRecipient` field in a DepositIntent (felt 19, 4 bytes/felt).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// First byte of the 32-byte `remoteToken` field (felt 11 x 4 bytes of the fixed header).
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;

/// The deposit amount used to build the mint note.
const MINT_AMOUNT: u64 = 5_000;

/// Builds a valid deposit payload for the given recipient from an existing test vector.
/// It must pass decoding so the tests reach the attachment checks, rather than failing to build.
fn attested_deposit_intent_payload(
    recipient: miden_protocol::account::AccountId,
    faucet_id: miden_protocol::account::AccountId,
) -> Vec<u8> {
    let v = miden_usdcx::vectors::load();
    let mut payload = v
        .families
        .mi
        .iter()
        .find(|d| d.kind == "accept")
        .expect("at least one accepted mint-payload vector")
        .payload();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(MINT_AMOUNT));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(1));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(recipient).to_bytes32());
    // Replace the sample token with the target faucet's account ID.
    payload[REMOTE_TOKEN_BYTE_OFF..REMOTE_TOKEN_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32());
    payload
}

/// Builds and commits a faucet with the production components.
fn production_faucet() -> Result<(MockChain, Account)> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("fetching the committed faucet account")?
        .clone();
    Ok((pf.mock_chain, account))
}

/// Gets the standard network-account auth procedure's root.
/// Its root does not depend on the allowlist entries stored in the component.
fn stock_network_auth_proc_root() -> Word {
    let component: AccountComponent = AuthNetworkAccount::custom(
        BTreeSet::from_iter([MintNote::script_root()]),
        test_fee_policy_manager(),
    )
    .expect("non-empty allowlist constructs")
    .into_iter()
    .next()
    .expect("the auth component is yielded first");
    let (root, _is_auth) = component
        .procedures()
        .find(|(_, is_auth)| *is_auth)
        .expect("AuthNetworkAccount exposes an auth procedure");
    Word::from(root)
}

// NETWORK-ACCOUNT AUTHORIZATION
// ================================================================================================

/// The faucet is a public network account with a note-script allowlist.
#[test]
fn production_faucet_is_a_network_account() -> Result<()> {
    let (_chain, account) = production_faucet()?;
    let result = NetworkAccount::new(account);
    assert!(
        result.is_ok(),
        "the production faucet is not a network account (no AuthNetworkAccount / no allowlist \
         slot); F5 must compose AuthNetworkAccount as the sole auth component. Got: {:?}",
        result.err()
    );
    Ok(())
}

/// The faucet uses the standard network-account auth procedure.
#[test]
fn production_faucet_auth_component_is_stock_network_account() -> Result<()> {
    let (_chain, account) = production_faucet()?;
    let auth_root = stock_network_auth_proc_root();
    let account_roots: BTreeSet<Word> = account.code().procedure_roots().collect();
    assert!(
        account_roots.contains(&auth_root),
        "the production faucet does not carry the stock AuthNetworkAccount auth procedure — the \
         auth component is not AuthNetworkAccount (F5 must compose the stock component, not a \
         custom auth)",
    );
    Ok(())
}

// INITIAL SCRIPT ALLOWLISTS
// ================================================================================================

/// The built account stores all twelve note scripts allowed by the builder.
#[test]
fn production_faucet_note_allowlist_contains_the_twelve_expected_roots() -> Result<()> {
    let (_chain, account) = production_faucet()?;
    let expected = XReserveStablecoinBuilder::allowed_note_scripts();
    assert_eq!(expected.len(), 12, "the expected allowlist contains exactly 12 distinct roots");

    // The built account stores the builder's allowlist.
    let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry a note-script allowlist slot: {e}"))?;
    assert_eq!(
        allowlist.allowed_script_roots(),
        &expected,
        "the built faucet's allowlist map must equal the builder's 12 roots",
    );
    Ok(())
}

/// The built account allows only the expiration transaction script.
#[test]
fn production_faucet_tx_script_allowlist_is_exactly_the_expiration_root() -> Result<()> {
    let (_chain, account) = production_faucet()?;
    let tx_allowlist = NetworkAccountTxScriptAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry a tx-script allowlist slot: {e}"))?;
    let expected = BTreeSet::from([ExpirationTransactionScript::script_root()]);
    assert_eq!(
        tx_allowlist.allowed_script_roots(),
        &expected,
        "the tx-script allowlist must equal EXACTLY {{ ExpirationTransactionScript::script_root() }} \
         (S12 sole-mint-surface); found {} root(s)",
        tx_allowlist.allowed_script_roots().len(),
    );
    Ok(())
}

// REJECTING UNLISTED SCRIPTS
// ================================================================================================

/// Consuming an unlisted note script fails with the allowlist error.
#[tokio::test]
async fn non_allowlisted_note_is_rejected_by_auth() -> Result<()> {
    let (chain, account) = production_faucet()?;
    let bogus_script = CodeBuilder::new()
        .compile_note_script("@note_script\npub proc main\n    dropw\nend")
        .context("compiling the non-allowlisted probe note script")?;
    let bogus = NoteBuilder::new(test_account_id(9), &mut note_rng(99))
        .note_type(NoteType::Public)
        .script(bogus_script)
        .build()
        .context("building the non-allowlisted probe note")?;

    let result = chain
        .build_transaction(account.id())
        .unauthenticated_input_note(bogus.clone())
        .build()
        .context("building the consume tx")?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);
    Ok(())
}

/// The expiration script passes the allowlist check; an unlisted no-op script does not.
#[tokio::test]
async fn non_expiration_tx_script_is_rejected_and_expiration_is_admitted() -> Result<()> {
    let (chain, account) = production_faucet()?;

    // A no-op script is not allowlisted.
    let bogus = CodeBuilder::new()
        .compile_tx_script("@transaction_script\npub proc main\n    nop\nend\n")
        .context("compiling the probe tx script")?;
    let rejected = chain
        .build_transaction(account.id())
        .tx_script(bogus)
        .build()
        .context("building the tx-script tx")?
        .execute()
        .await;
    assert_transaction_executor_error!(rejected, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    // The expiration script must pass the allowlist check. The transaction may still fail
    // because it consumes no notes and changes no state.
    let expiration = ExpirationTransactionScript::new(NonZeroU16::new(64).expect("64 is non-zero"));
    let admitted = chain
        .build_transaction(account.id())
        .tx_script(expiration.into())
        .tx_script_args(expiration.tx_script_args())
        .build()
        .context("building the expiration tx-script tx")?
        .execute()
        .await;
    match admitted {
        Ok(_) => {},
        Err(TransactionExecutorError::TransactionProgramExecutionFailed(actual)) => assert!(
            !ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED.matches_execution_error(&actual),
            "the canonical ExpirationTransactionScript must be ADMITTED by the S12 allowlist, but \
             it was rejected by the tx-script allowlist: {actual}",
        ),
        Err(other) => {
            panic!("the expiration tx failed with an unexpected non-execution error: {other}")
        },
    }
    Ok(())
}

// NOTE ATTACHMENTS
// ================================================================================================

/// The mint note carries two attachments: the scheme-4 attestation and deposit payload,
/// and the scheme-2 faucet target with `NoteExecutionHint::Always`.
///
/// The fixed-size attestation comes first, so the deposit payload starts at a fixed offset.
#[test]
fn mint_note_carries_the_merged_transport_and_the_routing_target() -> Result<()> {
    let (_chain, faucet) = production_faucet()?;
    let faucet_id = faucet.id();
    let payload = attested_deposit_intent_payload(test_account_id(3), faucet_id);
    let att = gen_attester(1, &payload);
    let note = mint_note_from_payload(
        test_account_id(3),
        faucet_id,
        &payload,
        DepositAttestation::new(Signature::new(att.sig_bytes), att.pubkey.clone()),
        &mut note_rng(1),
    )?;

    assert_eq!(
        note.attachments().num_attachments(),
        2,
        "the mint note must carry exactly two attachments: the merged transport + the routing \
         target",
    );
    let transport_scheme = NoteAttachmentScheme::new(XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME)
        .expect("scheme 4 is a valid attachment scheme");
    let count_of = |scheme: NoteAttachmentScheme| {
        note.attachments().iter().filter(|a| a.attachment_scheme() == scheme).count()
    };
    assert_eq!(
        count_of(transport_scheme),
        1,
        "exactly one scheme-4 merged transport attachment"
    );
    assert_eq!(
        count_of(NetworkAccountTarget::ATTACHMENT_SCHEME),
        1,
        "exactly one scheme-2 routing attachment"
    );

    // Check the attestation and deposit payload at their expected offsets.
    let transport = note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == transport_scheme)
        .context("the scheme-4 merged transport attachment is present")?
        .content()
        .to_elements();
    let carried = MintIntent::from_deposit_intent(
        &DepositIntent::try_from(payload.as_slice())?,
        faucet_id,
        TEST_DOMAIN,
    )
    .map_err(|e| anyhow::anyhow!("the attested payload compresses: {e}"))?;
    let mut expected: Vec<Felt> = Vec::new();
    expected.extend(att.pubkey.to_elements());
    expected.extend(Signature::new(att.sig_bytes).to_elements());
    expected.extend([Felt::from(0u32); 3]);
    assert_eq!(
        expected.len(),
        XUSDC_MINT_TRANSPORT_PAYLOAD_WORD_OFF * 4,
        "the attestation section ({XUSDC_MINT_ATTESTATION_NUM_WORDS} words) precedes the payload"
    );
    expected.extend(carried.to_elements());
    assert_eq!(
        transport, expected,
        "the transport attachment is attestation(36) || the carried mint payload",
    );
    assert_eq!(
        usize::from(
            note.attachments()
                .iter()
                .find(|a| a.attachment_scheme() == transport_scheme)
                .expect("present")
                .num_words()
        ),
        expected.len() / 4,
        "the committed word count is exactly attestation + padded intent",
    );

    let target = NetworkAccountTarget::try_from(note.attachments())
        .map_err(|e| anyhow::anyhow!("the mint note must carry a scheme-2 routing target: {e}"))?;
    assert_eq!(target.target_id(), faucet_id, "the routing target must be the faucet account");
    assert_eq!(
        target.execution_hint(),
        NoteExecutionHint::Always,
        "the routing target's execution hint must be Always",
    );
    Ok(())
}

/// The burn note must carry the scheme-2 `NetworkAccountTarget` routing attachment addressed to the
/// faucet with `NoteExecutionHint::Always` (alongside the scheme-tagged withdrawal payload).
#[test]
fn burn_note_carries_scheme2_target_to_faucet() -> Result<()> {
    let (_chain, faucet) = production_faucet()?;
    let faucet_id = faucet.id();
    let note = XReserveBurnNote::create(
        test_account_id(3),
        faucet_id,
        miden_protocol::asset::AssetAmount::new(5_000)?,
        sample_burn_items(),
        &mut note_rng(2),
    )
    .map_err(|e| anyhow::anyhow!("constructing the burn note: {e}"))?;

    assert_eq!(
        note.attachments().num_attachments(),
        2,
        "the burn note must carry exactly two attachments: the scheme-2 routing target and the \
         scheme-tagged withdrawal payload",
    );
    let target = NetworkAccountTarget::try_from(note.attachments())
        .map_err(|e| anyhow::anyhow!("the burn note must carry a scheme-2 routing target: {e}"))?;
    assert_eq!(target.target_id(), faucet_id, "the routing target must be the faucet account");
    assert_eq!(
        target.execution_hint(),
        NoteExecutionHint::Always,
        "the routing target's execution hint must be Always",
    );
    Ok(())
}
