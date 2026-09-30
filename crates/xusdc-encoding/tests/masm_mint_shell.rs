//! Faucet mint-precondition suite: every behavior test executes the faucet-owned
//! `xreserve::deposit_intent_parser::validate` on a MockChain, entered by `call` from a small
//! driver component. The `call` matters: `validate` reads the faucet's own domain configuration
//! with `active_account::get_item` and its own account id with `native_account::get_id`, which the
//! kernel only honors when the caller runs in account context.
//!
//! `validate` is the parser's single entry and runs every stage in order, so a case reaches the
//! stage it targets by being valid for the stages before it. That is why cases aimed past the
//! amount stage splice a coherent `amount`/`maxFee` pair into their preimage: the canonical
//! vectors carry a `maxFee` above their `amount`, which that stage refuses.
//!
//! The DepositIntent payloads come from the canonical golden-vector artifact shared with the
//! Rust codec, so an accept here and an accept in the Rust parser are driven by the same bytes.
//!
//! The reject rows split into two groups by who owns the check. Five of them — bad magic, bad
//! version, and a zero `amount` / `localToken` / `localDepositor` — are enforced by the shared
//! encoding parser and surface as its `ERR_DI_*` errors travelling back out through the call.
//! The other two are the faucet's own compares: the intent's `remoteDomain` must equal the
//! configured domain, and its `remoteToken` must decode — out of the frozen bytes32 packaging, pad
//! and all — to the faucet's own account id, read from the kernel rather than from a slot.
//!
//! The file is organized by the stages the mint pipeline runs in, and the section headers and
//! test names use the short stage labels the faucet's own comments use. The sequence, defined
//! here so nothing outside this file has to be consulted:
//!
//! - `d5a` — parse the DepositIntent and assert its fields against the faucet configuration
//!   (the first two sections below).
//! - `d5b` — reduce `amount` / `maxFee` / `feeAmount` from uint256 to asset amounts and assert
//!   the relations between them.
//! - `d5c` — assert the intent's nonce has not been spent (read-only; the marker write is a
//!   later stage).
//! - `d5d` — verify the depositor's ECDSA attestation against the attester allowlist.
//! - `d5e` — the state-changing tail (mint, write the nonce marker); driven end to end in
//!   `mint_policy_e2e.rs`, not here.

mod support;

use anyhow::Result;
use miden_processor::operation::OperationError;
use miden_processor::ExecutionError;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::*;
use xusdc_encoding::vectors::{load, MiVector};
use xusdc_encoding::xreserve::encoding::{CircleDomain, DepositIntent, MintIntent};

/// The faucet's domain configuration word: the remote domain id in element 0, zeros elsewhere.
///
/// There is no identifier counterpart, and under DC-14 there is no domain compare either — the
/// faucet WRITES both into the preimage it rebuilds. The slot still has to hold the right value,
/// because that is what the writer stamps.
fn domain_word(domain: CircleDomain) -> Word {
    Word::new([
        Felt::from(domain),
        miden_protocol::ZERO,
        miden_protocol::ZERO,
        miden_protocol::ZERO,
    ])
}

// PROBES — harness mechanics, not faucet behavior
// ================================================================================================
// These tests do not exercise the mint preconditions at all. They pin the assumptions the
// behavior tests are built on: that the library exports each proc under the fully-qualified path
// the drivers call it by, and that named storage slots read back what they were seeded with.
// Keeping them separate means an assembler or naming regression fails as itself rather than
// masquerading as a mint-policy reject.

/// The assembled library exports the nonce guard under its fully-qualified path.
///
/// The drivers in this file invoke it by that exact path, and so does the faucet component, so a
/// module move or rename would silently break both. Comparing against the assembler's own export
/// list is what catches it.
#[test]
fn probe_shell_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::mint_intent::hash_nonce";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical shell proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

/// Pins the plumbing the other tests depend on: that a named storage slot really resolves to the
/// word it was seeded with.
///
/// A minimal probe component reads the named value slot by name and compares it against the
/// fixture word. It deliberately does not touch the deposit-intent code, so if the slot naming
/// or the call-context read path ever breaks on a toolchain bump, this fails on its own instead
/// of showing up as a confusing wrong-domain reject elsewhere in the file.
#[tokio::test]
async fn probe_slot_binding() -> Result<()> {
    let domain = Word::from([7u32, 0, 0, 0]);
    let probe_src = slot_probe_src(domain);
    let h = setup_shell_account(domain, &probe_src, SLOT_PROBE_PATH)?;
    run_call_driver(&h, "read_slots")
        .await
        .unwrap_or_else(|e| panic!("slot-binding probe must execute green: {e}"));
    Ok(())
}

// D5C — NONCE REPLAY GUARD
// ================================================================================================
// Executes `xreserve::mint_intent::assert_nonce_unused` on a MockChain. The guard reads
// `usedNonces[key]` from account storage and requires it to still be the empty Word; anything else
// means this deposit has already been minted and it traps. It only READS — writing the spent
// marker belongs to the mint tail, so the tests here also assert that no storage was written.
//
// The key arrives already derived, because the policy needs the same Word twice: once to key the
// registry and once as the attested output note's serial. Deriving it there rather than here is
// what lets this guard be three instructions.

/// A stand-in "this nonce is spent" marker used to seed `usedNonces`. Any non-empty Word does:
/// the guard's whole test is empty vs non-empty, and the value the mint tail actually writes is
/// not what this section exercises.
const NONCE_MARKER: [u32; 4] = [1, 0, 0, 0];

/// The `usedNonces` key a carried payload's nonce lands on, through the Rust half of the shared
/// bytes32→Word codec — the same derivation the policy performs, rather than a hand-pinned Word.
fn nonce_key(vector_id: &str) -> Result<Word> {
    let carried = MintIntent::from_elements(&mi(vector_id).carried_values())?;
    Ok(Word::from(carried.nonce().to_storage_map_key()))
}

// HAPPY PATH FIRST — an unused nonce (empty map) passes the guard
// ------------------------------------------------------------------------------------------------

#[rstest]
#[case::empty_hookdata("mi-pos-empty-hookdata")]
#[case::hookdata("mi-pos-hookdata")]
#[tokio::test]
async fn unused_nonce_passes_replay_protection(#[case] vector_id: &str) -> Result<()> {
    let key = nonce_key(vector_id)?;
    let h = setup_shell_account(
        domain_word(TEST_DOMAIN),
        &nonce_guard_driver_src(key),
        SHELL_DRIVER_PATH,
    )?;
    let executed = run_call_driver(&h, "drive").await.unwrap_or_else(|e| {
        panic!("vector {vector_id}: an unused nonce must pass the replay guard: {e}")
    });
    assert!(
        executed.account_patch().storage().is_empty(),
        "replay protection is assert-zero only: it must not write account storage (no nonce SET)"
    );
    Ok(())
}

// REPLAY REJECT — a nonce already recorded as spent traps with the exact replay error
// ------------------------------------------------------------------------------------------------

#[rstest]
#[case::empty_hookdata("mi-pos-empty-hookdata")]
#[case::hookdata("mi-pos-hookdata")]
#[tokio::test]
async fn used_nonce_fails_replay_protection(#[case] vector_id: &str) -> Result<()> {
    let key = nonce_key(vector_id)?;
    let h = setup_shell_account_with_nonce_seed(
        domain_word(TEST_DOMAIN),
        Some((key, Word::from(NONCE_MARKER))),
        &nonce_guard_driver_src(key),
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_NONCE_REPLAY"));
    Ok(())
}

// KEY-SCOPING (strengthening) — a non-empty map must not reject an UNRELATED nonce
// ------------------------------------------------------------------------------------------------

/// A spent entry for one nonce must not shadow another. Without this, a guard that keyed on
/// something coarser than the nonce — or that tested "the map is non-empty" — would still pass
/// both cases above.
#[tokio::test]
async fn unrelated_nonce_passes_replay_protection() -> Result<()> {
    let spent = nonce_key("mi-pos-hookdata")?;
    let fresh = nonce_key("mi-pos-empty-hookdata")?;
    assert_ne!(spent, fresh, "the two vectors must key on distinct nonces");
    let h = setup_shell_account_with_nonce_seed(
        domain_word(TEST_DOMAIN),
        Some((spent, Word::from(NONCE_MARKER))),
        &nonce_guard_driver_src(fresh),
        SHELL_DRIVER_PATH,
    )?;
    run_call_driver(&h, "drive")
        .await
        .map_err(|e| anyhow::anyhow!("an unrelated spent nonce must not reject this one: {e}"))?;
    Ok(())
}

// D5D — ATTESTATION VERIFY
// ================================================================================================
// Executes the faucet-owned `xreserve::attestation_verify::verify_attestation` on a MockChain.
// The proc does two things in order: check that the candidate public key is an enabled attester
// (its Poseidon2 commitment must have a non-empty entry in the `xReserveAttesters` map), then
// ECDSA-verify the supplied signature over keccak256 of the DepositIntent payload for that key.
// Only a deposit Circle actually signed can pass.
//
// The security property these cases exist for: the pubkey is read out of ONE caller-owned memory
// region, and that same region feeds both the allowlist lookup and the signature check. If the two
// steps could read different keys, an attacker could present an allowlisted attester's key for the
// lookup and their own signature for the verification.
//
// Keypairs and signatures are generated inside the test (k256 + sha3 + miden-crypto) rather than
// baked into the shared vector artifact, because the tests need two attesters signing the SAME
// payload: key A and key B, with distinct commitments, so a signature by one can be offered
// under the identity of the other.
//
// Every case runs the real proc — real keccak, real Poseidon2 commitment, real map read, the real
// core-library ECDSA verifier — and pins the exact outcome: an accepted attestation stops at the
// supply-write boundary having written nothing; a rejected one traps with the specific error for
// the check that failed; and an attestation with nothing staged in memory fails closed rather than
// proceeding with garbage.

/// The DepositIntent whose bytes the attestation cases hash and sign: the 240-byte accept vector
/// with no hookData, so the payload is exactly the fixed header.
const ATTESTATION_VECTOR: &str = "mi-pos-empty-hookdata";

/// The value stored under an attester's commitment to mark it enabled. Any non-empty Word does —
/// the allowlist check is presence, and an absent key reads back as the empty Word.
const ATTESTER_MARKER: [u32; 4] = [1, 0, 0, 0];

/// Returns the attestation payload three ways: as the felts staged into the driver, as the raw
/// bytes the attester signs, and as its byte length.
///
/// The bytes and the felts must describe the same payload — the felts are the u32-little-endian
/// packing of those bytes — because the signature is made over the bytes while the on-chain
/// keccak runs over what the felts reconstruct. If they diverged, every case would fail closed.
fn attestation_payload() -> (Vec<Felt>, Vec<u8>, u64) {
    let bytes = mi(ATTESTATION_VECTOR).payload();
    let len_bytes = bytes.len() as u64;
    let felts = DepositIntent::try_from(bytes.as_slice())
        .expect("the vector payload decodes")
        .to_preimage_felts();
    (felts, bytes, len_bytes)
}

/// Generates the two attesters the reject cases need: key A, which the tests allowlist, and key
/// B, the foreign key. Both sign keccak256 of the same payload, and the assertion pins that their
/// commitments differ — otherwise "allowlist A, present B" would not actually be a mismatch.
fn seam_keys(payload: &[u8]) -> (AttesterVector, AttesterVector) {
    let a = gen_attester(1, payload);
    let b = gen_attester(2, payload);
    assert_ne!(
        a.commitment, b.commitment,
        "seam keys A and B must have distinct commitments"
    );
    (a, b)
}

/// Builds a driver that stages one attester's public key together with a different attester's
/// signature — the mix-and-match input an attacker would try.
fn paired_driver_src(
    preimage: &[Felt],
    len_bytes: u64,
    pubkey_of: &AttesterVector,
    sig_of: &AttesterVector,
) -> String {
    attestation_driver_src(
        preimage,
        len_bytes,
        &pubkey_of.pubkey_felts,
        &sig_of.sig_felts,
    )
}

// HAPPY PATH FIRST — an allowlisted attester with its own valid signature
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn valid_attestation_passes() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, _b) = seam_keys(&bytes);
    let driver_src = paired_driver_src(&preimage, len_bytes, &a, &a);
    // seed the allowlist with A's commitment -> A is an enabled attester
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let executed = run_call_driver(&h, "drive").await.unwrap_or_else(|e| {
        panic!("an allowlisted attester + valid signature must pass attestation verification: {e}")
    });
    // the verify shell is read-only: the only account mutation is the auth nonce increment
    assert_eq!(
        (executed.final_account().nonce() - executed.initial_account().nonce()),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_patch().storage().is_empty(),
        "the attestation verification verify shell must not write account storage"
    );
    Ok(())
}

// REJECTS — each pins the EXACT expected error (no is_err())
// ------------------------------------------------------------------------------------------------

/// A signature that does not belong to the presented key is rejected.
///
/// The driver stages allowlisted key A together with B's signature. B's signature is
/// perfectly well-formed — this is a genuine ECDSA verification failure, not a decode abort on
/// junk bytes — so the case proves the signature check itself, not input validation.
#[tokio::test]
async fn forged_signature_rejects() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, b) = seam_keys(&bytes);
    let driver_src = paired_driver_src(&preimage, len_bytes, &a, &b);
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver(&h, "drive").await;
    assert_ecdsa_verify_reject(result);
    Ok(())
}

/// A key the faucet does not know is rejected even with a perfectly valid signature.
///
/// Key B signs the payload correctly, but only A's commitment was seeded into the allowlist, so
/// the map lookup on B's commitment reads back the empty Word and the proc traps before it ever
/// gets to the signature. A valid signature by a stranger is not an attestation.
#[tokio::test]
async fn non_allowlisted_attester_rejects() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, b) = seam_keys(&bytes);
    let driver_src = paired_driver_src(&preimage, len_bytes, &b, &b);
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_DISALLOWED_PUB_KEY")
    );
    Ok(())
}

// THE SEAM (the catastrophic case) — BOTH attacker arrangements must reject
// ------------------------------------------------------------------------------------------------

/// Neither way of splitting "who is allowlisted" from "who signed" gets through.
///
/// An attacker holding a valid signature by an unknown key B has two moves, and this test runs
/// both for real: the allowlisted key A presented with B's signature (the allowlist check passes,
/// the ECDSA verify then fails) and B's own key presented with it (the ECDSA verify would pass,
/// but the allowlist check comes first and refuses). There is no third arrangement, because the
/// proc reads the candidate key exactly once and both checks consume that one copy.
#[tokio::test]
async fn mismatched_attestation_arrangements_reject() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, b) = seam_keys(&bytes);
    let allowlist_a = Some((a.commitment, Word::from(ATTESTER_MARKER)));

    // arrangement 1: allowlisted key A carries the allowlist check, B's signature fails the verify
    let mixed_src = paired_driver_src(&preimage, len_bytes, &a, &b);
    let h1 = setup_attestation_account(allowlist_a, &mixed_src, SHELL_DRIVER_PATH)?;
    let r1 = run_call_driver(&h1, "drive").await;
    assert_ecdsa_verify_reject(r1);

    // arrangement 2: B's key and B's own valid signature, but B was never allowlisted
    let b_only_src = paired_driver_src(&preimage, len_bytes, &b, &b);
    let h2 = setup_attestation_account(allowlist_a, &b_only_src, SHELL_DRIVER_PATH)?;
    let r2 = run_call_driver(&h2, "drive").await;
    assert_transaction_executor_error!(r2, shell_error_by_name("ERR_XRESERVE_DISALLOWED_PUB_KEY"));
    Ok(())
}

// UNSTAGED OPERANDS — an all-zero pubkey region must fail closed
// ------------------------------------------------------------------------------------------------

/// A caller that stages no key and no signature must be rejected, not waved through.
///
/// Miden memory reads back as zero, so "nothing staged" is not a read error here — it is sixteen
/// zero felts that could be mistaken for a key. The allowlist gate is what refuses it: the zero
/// pubkey's commitment was never enabled, so the lookup reads the empty Word and the proc traps
/// before the signature check.
#[tokio::test]
async fn unstaged_pubkey_rejects() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, _b) = seam_keys(&bytes);
    let driver_src = attestation_driver_src(&preimage, len_bytes, &[], &[]);
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_DISALLOWED_PUB_KEY")
    );
    Ok(())
}

// PROBE (export check for the new proc)
// ------------------------------------------------------------------------------------------------

/// The assembled library exports `verify_attestation` under its fully-qualified path — the same
/// rename guard as the other export probes, for the attestation stage.
#[test]
fn probe_attestation_verify_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::attestation_verify::verify_attestation";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical attestation verification proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// D5F — DC-14 PREIMAGE RECONSTRUCTION (TV-DUAL-6, the MASM half)
// ================================================================================================

/// Looks up a canonical mint-payload vector by id (by-reference loading).
fn mi(id: &str) -> &'static MiVector {
    load()
        .families
        .mi
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing mp vector {id}"))
}

/// Runs `rebuild` for one vector against a fresh shell account.
///
/// The vector's own faucet id is synthetic, so it is NOT reused here: the mint intent is
/// faucet-independent by construction, and the reconstruction is checked against the id the shell
/// account actually got. That is precisely the field the faucet supplies rather than reads.
async fn run_rebuild(vector_id: &str) -> Result<()> {
    let v = mi(vector_id);
    let carried = MintIntent::from_elements(&v.carried_values())?;
    let felts = carried.to_elements();
    let num_expected_felts =
        DepositIntent::HEADER_NUM_FELTS + carried.hook_data().as_bytes().len().div_ceil(4);

    let driver_src = rebuild_driver_src(
        &felts,
        felts.len().div_ceil(4) as u64,
        u64::from(v.amount()),
        num_expected_felts,
    );
    let h = setup_shell_account(domain_word(TEST_DOMAIN), &driver_src, SHELL_DRIVER_PATH)?;

    // the account exists now, so the Rust mirror can rebuild the message for ITS id
    let expected = carried
        .to_deposit_intent(v.amount(), TEST_DOMAIN, h.account_id)
        .to_preimage_felts();
    assert_eq!(
        expected.len(),
        num_expected_felts,
        "vector {vector_id}: the mirror and the driver must agree on the felt count"
    );

    run_call_driver_with_advice(&h, "drive", Some(expected))
        .await
        .map_err(|e| anyhow::anyhow!("vector {vector_id}: MASM must match the Rust mirror: {e}"))?;
    Ok(())
}

/// TV-DUAL-6 (happy path, written first): the MASM writer produces exactly the message the Rust
/// mirror does, felt for felt.
///
/// This is the highest-value assertion in the mint suite. Everything the policy no longer compares,
/// it enforces by rebuilding these felts and letting the attestation verify over them — so a writer
/// that is off by one field, one limb, or one offset makes every mint fail, and nothing else in the
/// suite would say why.
#[rstest]
#[case::empty_hookdata("mi-pos-empty-hookdata")]
#[case::hookdata("mi-pos-hookdata")]
#[tokio::test]
async fn rebuild_matches_the_canonical_deposit_intent(#[case] vector_id: &str) -> Result<()> {
    run_rebuild(vector_id).await
}

/// Perturbing one carried field moves exactly that field's felts and nothing else.
///
/// This is what replaces the per-field rejects the compare-based pipeline used to have. On-chain
/// every one of those now fails identically as an invalid signature, so the attributability has to
/// live here: the placement of each field is pinned individually, against the same mirror the
/// happy path uses.
#[rstest]
#[case::nonce(MintIntent::NONCE_FELT_OFF)]
#[case::local_token(MintIntent::LOCAL_TOKEN_FELT_OFF)]
#[case::local_depositor(MintIntent::LOCAL_DEPOSITOR_FELT_OFF)]
#[tokio::test]
async fn rebuild_places_each_carried_field(#[case] carried_felt_off: usize) -> Result<()> {
    let v = mi("mi-pos-empty-hookdata");
    let mut felts = v.carried_values();
    felts[carried_felt_off] = Felt::from(0x1234_5678u32);
    let carried = MintIntent::from_elements(&felts)?;

    let driver_src = rebuild_driver_src(
        &felts,
        felts.len().div_ceil(4) as u64,
        u64::from(v.amount()),
        DepositIntent::HEADER_NUM_FELTS,
    );
    let h = setup_shell_account(domain_word(TEST_DOMAIN), &driver_src, SHELL_DRIVER_PATH)?;
    let expected = carried
        .to_deposit_intent(v.amount(), TEST_DOMAIN, h.account_id)
        .to_preimage_felts();

    run_call_driver_with_advice(&h, "drive", Some(expected))
        .await
        .unwrap_or_else(|e| {
            panic!("perturbing carried felt {carried_felt_off} must move only that field: {e}")
        });
    Ok(())
}

/// A carried limb above u32 is refused by name.
///
/// keccak's byte reader would refuse it too, but as an anonymous host failure. The guard exists so
/// the fault is attributable, which matters most on the one path where every other failure looks
/// like a bad signature.
#[tokio::test]
async fn rebuild_rejects_a_non_u32_carried_limb() -> Result<()> {
    let v = mi("mi-pos-empty-hookdata");
    let mut felts = v.carried_values();
    // a felt at 2^32 is a valid field element but NOT a valid u32 limb
    felts[MintIntent::NONCE_FELT_OFF] =
        Felt::try_from(1u64 << 32).expect("2^32 is within the field");

    let driver_src = rebuild_driver_src(
        &felts,
        felts.len().div_ceil(4) as u64,
        u64::from(v.amount()),
        DepositIntent::HEADER_NUM_FELTS,
    );
    let h = setup_shell_account(domain_word(TEST_DOMAIN), &driver_src, SHELL_DRIVER_PATH)?;
    let result = run_call_driver_with_advice(&h, "drive", Some(vec![])).await;
    let expected = shell_error_by_name("ERR_XRESERVE_MINT_INTENT_LIMB");
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { ref err_code, ref err_msg, .. },
            ..
        } if *err_code == expected.code() && err_msg.as_deref() == Some(expected.message())
    );
    Ok(())
}

/// The assembled library exports the writer under its canonical path (`NS-3`).
#[test]
fn probe_deposit_intent_builder_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::deposit_intent::rebuild";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical preimage-writer path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}
