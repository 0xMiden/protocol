//! End-to-end mint binding: what the attestation says must be what actually gets minted.
//!
//! The companion to `mint_policy_e2e.rs`, sharing the same production transport harness. Where
//! that file asks whether a deposit is allowed at all, this one asks whether the note the faucet
//! acts on is faithfully bound to the attested deposit — a mint that passed every check but paid
//! out a different amount, or to a different account, would be just as much a loss of funds.
//!
//! It covers:
//!
//! - The binding checks themselves: a mint note whose amount, tag, or note type does not match
//!   what the attestation committed to is rejected. (The recipient binding is tested alongside the
//!   replay and fee cases in the recomposition end-to-end suite.)
//! - Recipient extraction: the attested `remoteRecipient` is a 32-byte field carrying a Miden
//!   account id in its low bytes, so the leading pad must be zero and each id half must be below
//!   the field modulus. Both guards get their own reject cases — a non-canonical value must fail,
//!   never be silently reduced into a different, valid account id.
//! - Transport shape: the merged scheme-4 attachment's layout (attestation section, deposit
//!   intent) and every way it can be wrong — an attachment missing, doubled or extra, a truncated
//!   attachment, a length that disagrees with the payload, and each sub-region tampered with
//!   independently.
//! - The pause halt, the routing proof on a MockChain, and the restatement that a mint path with
//!   no policy installed cannot mint at all.
//!
//! Every negative asserts its exact error rather than merely failing, and the payload-driven
//! rejects also assert fail-closure — nothing minted, no nonce consumed.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::errors::tx_kernel::{
    ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO,
    ERR_ACCOUNT_ID_VERSION_MUST_BE_NONZERO,
};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteAttachmentScheme, NoteTag, NoteType};
use miden_standards::note::{NetworkAccountTarget, P2idNote, P2idNoteStorage};
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_encoding::note::xreserve_mint::DepositAttestation;
use xusdc_encoding::xreserve::encoding::{DepositIntent, MintIntent, Signature};

use miden_protocol::{Felt, Word};

// ASSERT-MATCH — the note-supplied values must EQUAL their attested derivations
// ================================================================================================

/// A note amount diverging from the attested one rejects at the SIGNATURE.
///
/// The amount is no longer compared against anything: the faucet writes the note's own asset
/// amount into the preimage it rebuilds, so a divergent note simply reconstructs a different
/// message and Circle's signature stops verifying. The binding is structural rather than checked,
/// which is why both directions land on the same error — `build_preimage_places_each_carried_field`
/// is what keeps the placement itself honest.
#[rstest]
#[case::over_claim(1i64, 17, 86)]
#[case::under_claim(-1i64, 40, 109)]
#[tokio::test]
async fn mint_rejects_an_amount_mismatch(
    #[case] delta: i64,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT.checked_add_signed(delta).expect("in range"),
            tag: None,
            public: true,
        },
        1,
        None,
        &AttachmentPlan::default(),
        rng_seed,
    )?;
    expect_ecdsa_reject(&mut pf, note, &payload).await
}

/// A note whose output tag does not target the attested recipient rejects with the tag binding
/// error — the policy derives the expected tag with the standards helper and compares.
#[tokio::test]
async fn mint_rejects_a_tag_mismatch() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 18);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: Some(NoteTag::with_account_target(pf.producer_id)), // mis-targeted
            public: true,
        },
        1,
        None,
        &AttachmentPlan::default(),
        87,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_TAG_MISMATCH"),
    )
    .await
}

/// A PRIVATE-mode mint note (opaque recipient digest, private output note) rejects: the attested
/// output note is always public.
#[tokio::test]
async fn mint_rejects_a_private_output_note() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 19);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: false, // the 13-item private layout — note_type PRIVATE
        },
        1,
        None,
        &AttachmentPlan::default(),
        88,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TYPE_NOT_PUBLIC"),
    )
    .await
}

// EXTRACTING THE RECIPIENT FROM THE ATTESTED PAYLOAD — the layout guards, run through the policy
// ================================================================================================

// The bytes32 pad and non-canonical-limb families are no longer on-chain rejects, and cannot be.
// The recipient does not travel as a bytes32 any more — it travels as the two account-id felts the
// protocol's own procedures consume — so a dirty 16-byte pad and an out-of-field u64 limb are both
// unrepresentable on the wire. Their rejects moved to compress time, where
// `MintIntent::from_deposit_intent` refuses them with `AccountIdOutOfRange` and
// `NonCanonicalAccountId`; the `mp-rej-remote-token-malformed` and `mp-rej-recipient-non-canonical`
// vectors drive them in `mint_intent.rs`.
//
// What DOES remain on-chain is the validation of the two carried felts, because those are
// attacker-supplied and the policy uses them to address the output note.

/// A carried recipient that is not a valid account id is refused before the faucet writes it into
/// the preimage.
#[rstest]
// the low byte of an account id's suffix is reserved and must be zero
#[case::reserved_suffix_byte(
    MintIntent::REMOTE_RECIPIENT_SUFFIX_FELT_OFF,
    |id: AccountId| id.suffix().as_canonical_u64() | 1,
    ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO,
    38,
    107
)]
// the prefix's low nibble is the account id version, and version zero stays invalid
#[case::zero_version(
    MintIntent::REMOTE_RECIPIENT_FELT_OFF,
    |id: AccountId| id.prefix().as_felt().as_canonical_u64() & !0xf,
    ERR_ACCOUNT_ID_VERSION_MUST_BE_NONZERO,
    39,
    108
)]
#[tokio::test]
async fn mint_rejects_an_invalid_carried_recipient(
    #[case] felt_off: usize,
    #[case] corrupt: fn(AccountId) -> u64,
    #[case] expected_err: MasmError,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    let carried = MintIntent::from_deposit_intent(
        &DepositIntent::try_from(payload.as_slice())?,
        pf.faucet_id,
        TEST_DOMAIN,
    )
    .map_err(|e| anyhow::anyhow!("the base payload compresses: {e}"))?;
    let dirty_half = Felt::new(corrupt(carried.remote_recipient()))
        .expect("corrupting the half stays inside the field");
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        1,
        None,
        &AttachmentPlan {
            payload_felt_tamper: Some((felt_off, dirty_half)),
            ..AttachmentPlan::default()
        },
        rng_seed,
    )?;
    expect_reject(&mut pf, note, &payload, &expected_err).await
}

// TRANSPORT SHAPE — what happens when the note's two attachments are wrong
// ================================================================================================
//
// The mint note carries ONE merged transport attachment (scheme 4: the 11-word attestation
// section, then the packed deposit intent) plus the scheme-2 routing target. Every case below
// corrupts exactly one thing and names the EXACT error it must produce — which is also how the
// merged offsets get proven: a sub-region read at the wrong offset would surface a different
// error, or none.

/// The honest note's attachment SHAPE: exactly two, one scheme-4 merged transport and one
/// scheme-2 routing target, and the transport's felts are the documented
/// `attestation(44) ‖ intent(word-padded)` concatenation.
#[tokio::test]
async fn the_honest_note_carries_the_merged_transport_and_the_routing_target() -> Result<()> {
    let pf = fixture()?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 21);
    let note = honest_note(&pf, &payload, 90)?;

    let transport_scheme =
        NoteAttachmentScheme::new(TRANSPORT_SCHEME).expect("scheme 4 is a valid attachment scheme");
    let schemes: Vec<NoteAttachmentScheme> = note
        .attachments()
        .iter()
        .map(|a| a.attachment_scheme())
        .collect();
    assert_eq!(
        schemes.len(),
        2,
        "the mint note carries exactly two attachments: the merged transport + the routing target"
    );
    assert!(
        schemes.contains(&transport_scheme),
        "one of them is the scheme-{TRANSPORT_SCHEME} merged transport (schemes = {schemes:?})"
    );
    assert!(
        schemes.contains(&NetworkAccountTarget::ATTACHMENT_SCHEME),
        "the other is the stock scheme-2 routing target (schemes = {schemes:?})"
    );

    let transport = note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == transport_scheme)
        .context("the merged transport attachment is present")?
        .content()
        .to_elements();

    // the attestation section sits FIRST (fixed width), which is what makes every offset below a
    // constant rather than a function of hookDataLen
    let attester = gen_attester(1, &payload);
    let attestation = &transport[..TRANSPORT_PAYLOAD_WORD_OFF * 4];
    assert_eq!(
        attestation.len(),
        ATTESTATION_FELTS,
        "the attestation section is {ATTESTATION_WORDS} words"
    );
    assert_eq!(
        &attestation[ATTESTATION_PUBKEY_FELT_OFF..ATTESTATION_PUBKEY_FELT_OFF + 16],
        attester.pubkey_felts.as_slice(),
        "the 16 affine pubkey felts sit at the documented offset"
    );
    assert_eq!(
        &attestation[ATTESTATION_SIGNATURE_FELT_OFF..ATTESTATION_SIGNATURE_FELT_OFF + 17],
        attester.sig_felts.as_slice(),
        "the 17 signature felts sit at the documented offset"
    );

    // the intent itself does NOT travel. What follows the attestation is the carried payload —
    // only the fields the faucet cannot derive — and the faucet rebuilds the signed message from
    // it. That the two agree is TV-DUAL-6's job; here we only pin that the note carries exactly
    // what the codec says it should.
    let carried = MintIntent::from_deposit_intent(
        &DepositIntent::try_from(payload.as_slice())?,
        pf.faucet_id,
        TEST_DOMAIN,
    )
    .map_err(|e| anyhow::anyhow!("the payload compresses: {e}"))?;
    assert_eq!(
        &transport[TRANSPORT_PAYLOAD_WORD_OFF * 4..],
        carried.to_elements().as_slice(),
        "the payload sub-region is exactly the carried mint payload"
    );
    assert!(
        transport.len() < ATTESTATION_FELTS + payload.len().div_ceil(4),
        "the transport is smaller than carrying the intent verbatim would have been"
    );

    // and the harness builds the PRODUCTION wire, not a look-alike: the same transport the
    // `XUsdcMintNote` factory emits for the same payload and attestation. Without this, every
    // tamper case below would only be proving things about the harness.
    let factory_note = mint_note_from_payload(
        pf.producer_id,
        pf.faucet_id,
        &payload,
        DepositAttestation::new(Signature::new(attester.sig_bytes), attester.pubkey.clone()),
        &mut note_rng(90),
    )?;
    let factory_transport = factory_note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == transport_scheme)
        .context("the factory note carries the merged transport attachment")?
        .content()
        .to_elements();
    assert_eq!(
        transport, factory_transport,
        "the harness's transport attachment is byte-for-byte the production factory's"
    );
    Ok(())
}

/// Dropping the scheme-4 merged transport attachment rejects.
#[tokio::test]
async fn mint_rejects_a_missing_transport_attachment() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 22);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        1,
        None,
        &AttachmentPlan {
            transport: false,
            ..AttachmentPlan::default()
        },
        91,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TRANSPORT_MISSING"),
    )
    .await
}

/// Dropping the scheme-2 routing target rejects (the routing bind stays part of the shape, and its
/// reject identity is unchanged by the merge).
#[tokio::test]
async fn mint_rejects_a_missing_routing_target() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 23);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        1,
        None,
        &AttachmentPlan {
            target: false,
            ..AttachmentPlan::default()
        },
        92,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TARGET_MISSING"),
    )
    .await
}

/// A THIRD attachment rejects — either a foreign scheme riding along, or the merged transport
/// attached twice (which `find_attachment` would happily resolve to the first copy).
#[rstest]
#[case::foreign_scheme(AttachmentPlan { extra_scheme: Some(6), ..AttachmentPlan::default() }, 24, 93)]
#[case::doubled_transport(AttachmentPlan { duplicate_transport: true, ..AttachmentPlan::default() }, 25, 94)]
#[tokio::test]
async fn mint_rejects_a_third_attachment(
    #[case] plan: AttachmentPlan,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        1,
        None,
        &plan,
        rng_seed,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT"),
    )
    .await
}

/// A merged attachment shorter than the attestation + the 15-word intent header rejects at the
/// transport floor — below it, no sub-region offset can be trusted.
#[tokio::test]
async fn mint_rejects_a_truncated_transport() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 30);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        1,
        None,
        &AttachmentPlan {
            transport_truncate_words: Some(TRANSPORT_FLOOR_WORDS - 1),
            ..AttachmentPlan::default()
        },
        97,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TRANSPORT_TOO_SHORT"),
    )
    .await
}

/// The committed word count must equal attestation + ⌈len_felts/4⌉, and the equality is EXACT, so
/// it closes three things at once: a trailing padding word makes the attachment longer than the
/// embedded `hookDataLen` claims; a whole extra attestation section smuggled in behind the intent
/// does the same at eleven words, with every constant sub-offset still reading the right bytes, so
/// this binding — nothing else — is what refuses it; and a `hookDataLen` claiming extra hookData
/// makes the claim longer than the attachment. None is admissible: the padding must not be able to
/// hide data, no second section may ride along, and the length claim must not be able to reach
/// past the committed bytes.
#[rstest]
#[case::an_extra_padding_word(
    AttachmentPlan { transport_extra_words: 1, ..AttachmentPlan::default() },
    31,
    98
)]
#[case::a_smuggled_second_attestation_section(
    AttachmentPlan { trailing_attestation_section: true, ..AttachmentPlan::default() },
    26,
    95
)]
#[case::a_hook_data_len_lie(
    AttachmentPlan {
        payload_hook_data_len_felt: Some(Felt::from(4u32)),
        ..AttachmentPlan::default()
    },
    32,
    99
)]
#[tokio::test]
async fn mint_rejects_a_transport_length_mismatch(
    #[case] plan: AttachmentPlan,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        1,
        None,
        &plan,
        rng_seed,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_INTENT_WORDS"),
    )
    .await
}

/// A `hookDataLen` limb above the u32 range rejects BEFORE the byte-swap that derives the length —
/// the guard that keeps a hash-committed but out-of-range limb out of the length arithmetic.
#[tokio::test]
async fn mint_rejects_a_non_u32_hook_data_len_limb() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 33);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        1,
        None,
        &AttachmentPlan {
            payload_hook_data_len_felt: Some(
                Felt::new(1u64 << 32).expect("2^32 is inside the field"),
            ),
            ..AttachmentPlan::default()
        },
        100,
    )?;
    expect_reject_u32_assert(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_HOOK_LEN_LIMB"),
    )
    .await
}

/// SUB-REGION ISOLATION: corrupting one region of the merged attachment surfaces THAT region's
/// reject, never another's. The pubkey sub-region is read by the allowlist gate, the signature
/// sub-region by the ECDSA verify, and the intent sub-region by the keccak — so a merge that
/// mis-derived any offset would either mis-attribute the failure or, worse, verify the wrong
/// bytes. Each case's error identity is exactly the one it had when these were separate
/// attachments.
async fn tampered_sub_region_note(
    felt_off: usize,
    nonce_variant: u8,
    rng_seed: u64,
) -> Result<(ProductionFaucet, Note, Vec<u8>)> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        1,
        None,
        &AttachmentPlan {
            attestation_felt_tamper: Some((felt_off, Felt::from(0xdead_beefu32))),
            ..AttachmentPlan::default()
        },
        rng_seed,
    )?;
    Ok((pf, note, payload))
}

#[tokio::test]
async fn mint_rejects_a_tampered_attestation_pubkey() -> Result<()> {
    let (mut pf, note, payload) =
        tampered_sub_region_note(ATTESTATION_PUBKEY_FELT_OFF, 34, 101).await?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_DISALLOWED_PUB_KEY"),
    )
    .await
}

#[tokio::test]
async fn mint_rejects_a_tampered_attestation_signature() -> Result<()> {
    let (mut pf, note, payload) =
        tampered_sub_region_note(ATTESTATION_SIGNATURE_FELT_OFF, 35, 102).await?;
    expect_ecdsa_reject(&mut pf, note, &payload).await
}

/// A signature limb above `u32::MAX` is refused by name, before the verifier sees it: the
/// limb rewrite into the verifier's order is u32 arithmetic.
#[tokio::test]
async fn mint_rejects_a_non_u32_signature_limb() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 93);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        1,
        None,
        &AttachmentPlan {
            // a felt at 2^32 is a valid field element but NOT a valid u32 limb
            attestation_felt_tamper: Some((
                ATTESTATION_SIGNATURE_FELT_OFF,
                Felt::try_from(1u64 << 32).expect("2^32 is within the field"),
            )),
            ..AttachmentPlan::default()
        },
        193,
    )?;
    expect_reject_u32_assert(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_SIG_LIMB"),
    )
    .await
}

/// The other half of the isolation proof: a tampered INTENT byte — the attestation section left
/// untouched and the signature still over the original payload — rejects at the signature check,
/// because the keccak'd extent is the intent sub-region and nothing else. A merge that hashed the
/// attestation along with the intent would not reproduce this identity.
#[tokio::test]
async fn mint_rejects_a_tampered_intent_byte() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let signed = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 36);
    // the last maxFee byte: 1 -> 2, which every structural and amount check still admits (the
    // attested amount stays far above the fee), so the ONLY thing that changes is the digest.
    let mut carried = signed.clone();
    carried[MAX_FEE_BYTE_OFF + 31] = 2;
    let note = tampered_mint_note(
        &pf,
        &carried,
        &honest_storage(&pf),
        1,
        Some(&signed),
        &AttachmentPlan::default(),
        103,
    )?;
    expect_ecdsa_reject(&mut pf, note, &carried).await
}

// PAUSE HALT — the dispatcher gate (execute_mint_policy runs assert_not_paused FIRST)
// ================================================================================================

/// A DOM_PAUSER pause halts the attested mint at the policy dispatcher's stock pause gate.
#[tokio::test]
async fn mint_halts_while_paused() -> Result<()> {
    let mut pf = fixture_with(0, |_, faucet_id| {
        vec![stock_pause_note(dom_pauser(), faucet_id, 953)
            .expect("building the DOM_PAUSER pause note")]
    })?;
    bring_up(&mut pf, 2).await?; // set_attester + pause
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 28);
    let note = honest_note(&pf, &payload, 97)?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        &MasmError::from_static_str("the contract is paused"),
    )
    .await
}

// WITHOUT THE ATTESTED TRANSPORT THERE IS NO ACCEPTABLE MINT
// ================================================================================================

/// A tx-script `mint_and_send` (no active note, no attachments) CANNOT mint: the attestation
/// policy's first transport read (`active_note::find_attachment`) runs outside note processing,
/// so it traps the EXACT kernel input-note bound assert — there is no input note to read — and
/// the former deny-guard posture is preserved structurally: every supply increase must ride the
/// attested note transport. Asserts the exact kernel error + zero supply.
#[tokio::test]
async fn tx_script_mint_and_send_cannot_mint() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let recipient_recipe =
        P2idNoteStorage::new(pf.recipient_id).into_recipient(Word::from([9u32, 9, 9, 9]));
    let src = format!(
        "
            @transaction_script
            pub proc main
                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                exec.::miden::standards::assets::fungible_asset::create
                call.::miden::standards::faucets::fungible::mint_and_send
                dropw dropw dropw dropw
            end
            ",
        recipient = recipient_recipe.digest(),
        note_type = Felt::from(NoteType::Public),
        tag = u32::from(NoteTag::with_account_target(pf.recipient_id)),
        amount = MINT_AMOUNT,
        faucet_id_prefix = pf.faucet_id.prefix().as_felt(),
        faucet_id_suffix = pf.faucet_id.suffix(),
    );
    let tx_script = miden_standards::code_builder::CodeBuilder::new()
        .compile_tx_script(&src)
        .map_err(|e| anyhow::anyhow!("mint_and_send tx script: {e}"))?;
    let result = pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .tx_script(tx_script)
        .build()
        .context("tx build")?
        .execute()
        .await;
    // the EXACT trap: the kernel's input-note index bound (the policy asks for the active note's
    // attachments; the tx has zero input notes) — a stable pinned-kernel assertion, so the
    // fail-closure is attributable, not a generic `is_err()`
    assert_transaction_executor_error!(
        result,
        &MasmError::from_static_str(
            "requested input note index should be less than the total number of input notes"
        )
    );
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(0)?,
        "no supply may be created outside the attested transport"
    );
    Ok(())
}

// ROUTING — the MockChain-expressible half of the network-routing proof
// ================================================================================================

/// The constructed mint note is addressed for network execution at the faucet — the note's own
/// tag is the faucet account target, the scheme-2 attachment binds the faucet id — and the
/// faucet (a network account under the stock `AuthNetworkAccount` allowlist) consumes it through
/// the STOCK script end to end. The tag-based DISCOVERY itself is ntx-builder (node service)
/// behavior outside MockChain's model — recorded as a live-validation caveat for the deploy
/// task.
#[tokio::test]
async fn mint_note_routes_to_the_faucet_network_account() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 29);
    let note = honest_note(&pf, &payload, 98)?;

    // the network-routing identity: the note itself targets the FAUCET (the output-note tag
    // inside the storage targets the recipient — two different tags, both asserted).
    assert_eq!(
        note.metadata().tag(),
        NoteTag::with_account_target(pf.faucet_id),
        "the mint note's own tag is the faucet account target (stock MintNote conversion)"
    );
    assert_eq!(
        note.metadata().note_type(),
        NoteType::Public,
        "network notes are public"
    );
    let target = note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == NetworkAccountTarget::ATTACHMENT_SCHEME)
        .context("the scheme-2 routing attachment is present")?;
    let bound = NetworkAccountTarget::try_from(target)
        .map_err(|e| anyhow::anyhow!("decoding the routing attachment: {e}"))?;
    assert_eq!(
        bound.target_id(),
        pf.faucet_id,
        "the routing attachment binds THIS faucet's network account"
    );

    // the consumption proof: the network faucet consumes the committed note via the STOCK script.
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the routed mint must succeed: {e}"))?;
    assert_eq!(tx.output_notes().num_notes(), 1);
    let out = tx.output_notes().get_note(0);
    assert_eq!(
        out.recipient().map(|r| r.script().root()),
        Some(P2idNote::script_root()),
        "the attested output note is the canonical P2ID"
    );
    let mut chain = pf.mock_chain;
    commit(&mut chain, &tx)?;
    let faucet = committed(&chain, pf.faucet_id)?;
    assert_eq!(
        read_map_word(
            &faucet,
            XReserveFaucetExtension::used_nonces_slot(),
            nonce_key_of_payload(&payload)
        )?,
        marker(),
        "the consumed nonce is marked"
    );
    Ok(())
}

// ADVICE INDEPENDENCE — the host cannot influence a mint
// ================================================================================================

/// Junk staged on the advice stack in advance does not change the mint: `verify_signature`
/// pushes the note's own bytes last and `push_mapval` prepends, so the junk stays below the
/// elements the verifier reads.
#[tokio::test]
async fn mint_ignores_a_hostile_advice_stack() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 23);
    let note = honest_note(&pf, &payload, 83)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;

    // enough junk to satisfy every read the pre-hardening pipeline made (8 fee limbs + 16 pubkey
    // felts + 17 signature felts), so a surviving advice read would consume it and diverge rather
    // than trap on an empty stack
    let hostile: Vec<Felt> = (1u32..=41).map(Felt::from).collect();
    let tx = consume_note_with_advice(&pf.mock_chain, pf.faucet_id, note.id(), Some(hostile))
        .await
        .map_err(|e| anyhow::anyhow!("a hostile advice stack must not affect the mint: {e}"))?;

    assert_eq!(
        tx.output_notes().num_notes(),
        1,
        "the mint still emits exactly one recipient note"
    );
    let out = tx.output_notes().get_note(0);
    let asset = out
        .assets()
        .iter_fungible()
        .next()
        .ok_or_else(|| anyhow::anyhow!("the recipient note carries a fungible asset"))?;
    assert_eq!(
        u64::from(asset.amount()),
        MINT_AMOUNT,
        "the minted amount is the attested one, not anything the advice stack suggested"
    );

    let mut chain = pf.mock_chain;
    commit(&mut chain, &tx)?;
    let faucet = committed(&chain, pf.faucet_id)?;
    assert_eq!(
        read_map_word(
            &faucet,
            XReserveFaucetExtension::used_nonces_slot(),
            nonce_key_of_payload(&payload)
        )?,
        marker(),
        "the attested nonce is marked used"
    );
    Ok(())
}

/// The note carries a signature for a different payload. Minting must fail even when the host
/// supplies a valid signature for the actual payload through the advice stack.
#[tokio::test]
async fn mint_rejects_a_forged_signature_the_host_tries_to_rescue() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let carried = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 91);
    let signed_instead = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 92);
    let note = tampered_mint_note(
        &pf,
        &carried,
        &honest_storage(&pf),
        1,
        Some(&signed_instead),
        &AttachmentPlan::default(),
        191,
    )?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;

    let rescue = ecdsa_advice_witness(&gen_attester(1, &carried));
    assert_eq!(
        rescue.len(),
        32,
        "the verifier consumes exactly 32 elements"
    );
    let result =
        consume_note_with_advice(&pf.mock_chain, pf.faucet_id, note.id(), Some(rescue)).await;
    assert_ecdsa_verify_reject(result);

    assert_no_effects(&pf, &carried)
}
