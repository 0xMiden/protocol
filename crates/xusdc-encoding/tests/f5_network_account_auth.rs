//! Production transaction authorization for the Miden network-account faucet.
//!
//! The standard network-account auth component is the faucet's only authorization surface.
//!
//! The account is keyless, so transactions are authorized by their accepted note and transaction
//! scripts rather than a signature.
//!
//! The note-script allowlist contains two supply notes, six administration and configuration notes,
//! the fee configuration note, and the sponsorship note. The general network-account configuration
//! note is excluded, so accepted notes cannot modify the note or transaction allowlists. The
//! `RbacConfigNote` supports role grants, revocations, administration changes, and renunciation.
//!
//! Its transaction-script allowlist contains exactly one entry, the canonical expiration script.
//! Any other transaction script is rejected. This is what stops an arbitrary script from being run
//! against the faucet's own procedures.
//!
//! The remaining tests cover the routing attachments that make a network account reachable: a mint
//! note carries two attachments — the merged transport (the attestation followed by the deposit
//! intent) and the target routing the note to the faucet with an
//! always-execute hint — and a burn note carries the routing attachment. Both the wire form and
//! the semantics are checked.
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
    AuthNetworkAccount, NetworkAccount, NetworkAccountNoteAllowlist,
    NetworkAccountTxScriptAllowlist,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_standards::note::{MintNote, NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::note::xreserve_mint::{
    DepositAttestation, XUSDC_MINT_ATTESTATION_NUM_WORDS, XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME,
    XUSDC_MINT_TRANSPORT_PAYLOAD_WORD_OFF,
};
use xusdc_encoding::xreserve::encoding::{
    CircleDomain, DepositIntent, ForeignChainAddress, MintIntent, Signature, XReserveBurnItems,
};

// HELPERS
// ================================================================================================

/// A deterministic standalone note rng (only the serial number depends on it, never the gate).
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A representative burn payload with arbitrary destination fields that round-trip.
fn sample_burn_items() -> XReserveBurnItems {
    XReserveBurnItems {
        dest_domain: CircleDomain::new(9),
        dest_recipient: ForeignChainAddress::new([0xABu8; 32]),
    }
}

/// Byte offset of the 32-byte `remoteRecipient` field in a DepositIntent (felt 19, 4 bytes/felt).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// First byte of the 32-byte `remoteToken` field (felt 11 x 4 bytes of the fixed header).
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;

/// The attested wire amount spliced into the payload (any in-range value; the factory re-derives
/// the note storage from it).
const MINT_AMOUNT: u64 = 5_000;

/// Builds a deposit-intent payload that a real mint note can be constructed from.
///
/// It starts from the canonical accept vector and splices in an in-range amount and maxFee plus a
/// `remoteRecipient` holding the given account id in its bytes32 form. Those fields have to be
/// genuinely valid, because the note factory decodes them to derive the mint note's storage — a
/// payload that merely looks well-formed would fail at construction, not at the check under test.
fn attested_deposit_intent_payload(
    recipient: miden_protocol::account::AccountId,
    faucet_id: miden_protocol::account::AccountId,
) -> Vec<u8> {
    let v = xusdc_encoding::vectors::load();
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
    // the transport can only be built for the faucet the intent names, so the vector's synthetic
    // token has to become this faucet's id
    payload[REMOTE_TOKEN_BYTE_OFF..REMOTE_TOKEN_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32());
    payload
}

/// Builds the current PRODUCTION faucet and returns its MockChain + committed faucet account object.
/// The faucet id (`account.id()`) is PUBLIC — usable as a `NetworkAccountTarget` target.
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

/// The auth-procedure MAST root of the stock `AuthNetworkAccount` component (independent of the
/// allowlist storage contents; a dummy non-empty allowlist is used only to construct it).
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

// PROOF #6 — the production faucet is a network account, authed by the stock AuthNetworkAccount
// ================================================================================================

/// The production faucet must be a network account (public + the standardized note-script allowlist
/// slot).
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

/// The production faucet's dedicated auth component must be the STOCK `AuthNetworkAccount` (not a
/// custom / mutable-allowlist component): its auth-procedure MAST root must appear in the account
/// code.
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

// PROOF #5 — the frozen note-script allowlist + a tx-script allowlist of EXACTLY the expiration root
// ================================================================================================

/// The note-script allowlist contains exactly ten roots: two supply notes, six administration and
/// configuration notes, and two fee notes. The builder defines the set
/// ([`XReserveStablecoinBuilder::allowed_note_scripts`]); the built account must store it.
#[test]
fn production_faucet_note_allowlist_contains_the_ten_expected_roots() -> Result<()> {
    let (_chain, account) = production_faucet()?;
    let expected = XReserveStablecoinBuilder::allowed_note_scripts();
    assert_eq!(
        expected.len(),
        10,
        "the expected allowlist contains exactly 10 distinct roots"
    );

    // The built account stores the builder's allowlist.
    let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry a note-script allowlist slot: {e}"))?;
    assert_eq!(
        allowlist.allowed_script_roots(),
        &expected,
        "the built faucet's allowlist map must equal the builder's 10 roots",
    );
    Ok(())
}

/// The tx-script allowlist must exist and equal EXACTLY the one canonical
/// `ExpirationTransactionScript::script_root()` — the sole-mint-surface
/// posture, expressed as a ONE-root allowlist that admits only the protocol-standard
/// expiration bounder rather than an empty set. Extra/missing = RED.
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

// PROOF #1 — the auth boundary is real (non-allowlisted note + any tx script rejected)
// ================================================================================================

/// Consuming a note whose script root is NOT in the allowlist must be rejected by the network-auth
/// component with the exact allowlist error.
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

/// Any transaction script OTHER than the canonical `ExpirationTransactionScript` must be rejected
/// by the one-root tx-script allowlist, AND that canonical expiration script must be ADMITTED
/// the `nop` probe still trips `ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED`, while the
/// expiration script clears the allowlist gate and executes.
#[tokio::test]
async fn non_expiration_tx_script_is_rejected_and_expiration_is_admitted() -> Result<()> {
    let (chain, account) = production_faucet()?;

    // NEGATIVE — an arbitrary (nop) tx script is NOT the expiration root, so the allowlist rejects it.
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

    // POSITIVE — the canonical expiration script IS allowlisted, so it CLEARS the allowlist gate.
    // An expiration-only tx changes no account state and consumes no notes, so the kernel rejects it
    // with the empty-tx epilogue assertion — downstream of, and orthogonal to, the allowlist gate.
    // The precise invariant: the expiration script is NOT rejected by the tx-script allowlist (a
    // mutation dropping the expiration root flips this back to the allowlist error — RED — caught here).
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
        Ok(_) => {}
        Err(TransactionExecutorError::TransactionProgramExecutionFailed(actual)) => assert!(
            !ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED.matches_execution_error(&actual),
            "the canonical ExpirationTransactionScript must be ADMITTED by the S12 allowlist, but \
             it was rejected by the tx-script allowlist: {actual}",
        ),
        Err(other) => {
            panic!("the expiration tx failed with an unexpected non-execution error: {other}")
        }
    }
    Ok(())
}

// PROOF #2 / #3 — exact routing-attachment wire form + NetworkAccountTarget semantics
// ================================================================================================

/// The mint note (the STOCK `MintNote` built by `XUsdcMintNote::create`) must carry EXACTLY TWO
/// attachments — the merged scheme-4 transport (the 11-word attestation
/// `[feeAmount(8), pubkey(16), signature(17), pad(3)]`, then the packed DepositIntent preimage)
/// and the scheme-2 `NetworkAccountTarget` routing attachment
/// addressed to the faucet with `NoteExecutionHint::Always`.
///
/// The attestation section comes FIRST because it is fixed-width: that is what keeps the intent's
/// starting offset a constant instead of a function of `hookDataLen`.
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
        note.attachments()
            .iter()
            .filter(|a| a.attachment_scheme() == scheme)
            .count()
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

    // the merged content, at the documented offsets: attestation, carried payload
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
    assert_eq!(
        target.target_id(),
        faucet_id,
        "the routing target must be the faucet account"
    );
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
    assert_eq!(
        target.target_id(),
        faucet_id,
        "the routing target must be the faucet account"
    );
    assert_eq!(
        target.execution_hint(),
        NoteExecutionHint::Always,
        "the routing target's execution hint must be Always",
    );
    Ok(())
}
