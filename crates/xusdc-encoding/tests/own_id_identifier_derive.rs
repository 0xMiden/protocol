//! The faucet checks a deposit intent against its own account id instead of a stored identifier —
//! proven against the Rust encoding, over a spread of ids.
//!
//! The mint path stamps its own account id into every deposit intent's `remoteToken`, read on
//! chain from `native_account::get_id` rather than from a slot somebody had to seed (`DC-14`).
//! There is no compare any more — a deposit addressed elsewhere rebuilds a different message and
//! dies at the signature — but the PACKAGING is now something the faucet emits, so it has to be
//! exactly the packaging Circle reads. This suite runs the standards decode
//! (`eth::bytes32_to_account_id`) over the bytes the Rust encoder produces, in account context,
//! and requires the result to be the emitting account.
//!
//! The whole design rests on one claim: the bytes `EthEmbeddedAccountId::to_bytes32` produces off chain
//! decode, on chain, back to exactly the account they were produced for — for every account id, not
//! just the one a fixture happened to pick. If the two ever disagreed, the faucet would reject
//! deposits Circle addressed to it, or — worse — accept deposits addressed elsewhere.
//!
//! So every assertion here is made on the result of EXECUTING the MASM inside a transaction, over
//! bytes the RUST encoder produced and the caller pushes across the `call` boundary. The comparison
//! itself happens in MASM (`account_id::eq` + `assert`), so a disagreement traps and the test fails
//! with the driver's own error message; nothing is ever compared against itself.
//!
//! The spread is deliberate. One account id proves little about the byte swapping: an id whose
//! limbs happened to be palindromic, or whose prefix and suffix happened to coincide, would pass a
//! broken implementation. The suite therefore runs the decode over a dozen freshly generated ids
//! spanning both account types, and then over the account id of a faucet composed by the production
//! builder — the id that actually ships.
//!
//! Three controls keep the assertions honest: the same driver run against a DIFFERENT account's
//! encoding must trap (so the compare really discriminates), a corrupted zero pad must trap (so the
//! pad is asserted rather than ignored, which is what stops a `remoteToken` carrying the right id
//! inside the wrong packaging), and two accounts must encode differently (so the encoding really
//! reads the id).

mod support;

use anyhow::{Context, Result};
use miden_processor::advice::AdviceInputs;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{Account, AccountComponent, AccountId, AccountType};
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_testing::{
    assert_transaction_executor_error, AccountState, Auth, MockChain, MockTransactionInput,
};
use miden_tx::TransactionExecutorError;
use rstest::rstest;
use support::*;
use xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts;

/// How many generated account ids the parity spread covers, over and above the production faucet.
/// The floor this suite has to clear is eight; twelve costs little and spans both account types
/// evenly.
const SPREAD_SIZE: usize = 12;

/// Module path the standalone derive driver component is compiled under (the production leg reuses
/// the guarded fixture's own driver path).
const DERIVE_DRIVER_PATH: &str = "xusdc::test_fixtures::own_id_derive_driver";

const MAX_SUPPLY: u64 = 1_000_000;

/// The driver component: two `call`-invoked procedures that read the faucet's own id and run the
/// production bytes32 account-id decode over bytes the caller pushes across the `call` boundary.
///
/// The staged bytes arrive through the advice provider rather than being compiled into the source,
/// and that is not a style choice. An account id is a hash over the account's own code and storage
/// commitments, so a driver that embedded the expected id would change the very id it is trying to
/// predict. Taking them as transaction inputs keeps the component's code — and therefore every
/// account id derived from it — independent of what is being asserted.
///
/// Reading them from advice does not weaken anything: advice is host-controlled, so a hostile host
/// could only make an assertion FAIL, never pass a wrong decode. Each procedure is stack-neutral
/// across its `call` window, the shape the production note scripts use.
const DERIVE_DRIVER_SRC: &str = r#"use miden::protocol::account_id
use miden::protocol::native_account
use miden::standards::interop::eth
use miden::standards::utils

# The scratch address the staged bytes32 is written to before the decode reads it.
const STAGED_BYTES32_PTR = 1024

#! Asserts the native account id's two felts equal the pair the caller staged in advice.
#!
#! Inputs:  [pad(16)]
#! Outputs: [pad(16)]
#!
#! Advice stack: [expected_suffix, expected_prefix].
#!
#! Panics if:
#! - either felt differs from what the kernel reports for the native account.
#!
#! Invocation: call
@account_procedure
pub proc assert_native_id
    exec.native_account::get_id
    # => [suffix, prefix, pad(16)]

    adv_push
    # => [expected_suffix, suffix, prefix, pad(16)]

    assert_eq.err="canary: native account id suffix mismatch"
    # => [prefix, pad(16)]

    adv_push
    # => [expected_prefix, prefix, pad(16)]

    assert_eq.err="canary: native account id prefix mismatch"
    # => [pad(16)]
end

#! Asserts the caller's staged bytes32 decodes to the native account's own id.
#!
#! Under DC-14 the faucet WRITES `remoteToken` rather than decoding it, so this is no longer a
#! compare the mint path performs — it is the inverse of the packaging the mint path now EMITS.
#! The claim is unchanged and still load-bearing: the bytes the Rust encoder produces for an
#! account id must decode back to that account, or a third party could not verify a mint note and
#! the faucet's own emitted identifier would name someone else.
#!
#! Inputs:  [pad(16)]
#! Outputs: [pad(16)]
#!
#! Advice stack: the eight u32-LE-packed limbs of the Rust `to_bytes32` form, limb 0
#! first — the orientation the mint path stages a `remoteToken` in.
#!
#! Panics if:
#! - the staged bytes32 is not a well-formed packaged account id (the standards decode's guards).
#! - the account id it carries is not the native account's.
#!
#! Invocation: call
@account_procedure
pub proc assert_bytes32_decodes_to_own_id
    adv_push mem_store.1024
    adv_push mem_store.1025
    adv_push mem_store.1026
    adv_push mem_store.1027
    adv_push mem_store.1028
    adv_push mem_store.1029
    adv_push mem_store.1030
    adv_push mem_store.1031
    # => [pad(16)]

    push.STAGED_BYTES32_PTR exec.utils::mem_load_double_word_unaligned
    # => [B_LOWER, B_UPPER, pad(16)]

    exec.eth::bytes32_to_account_id
    # => [staged_suffix, staged_prefix, pad(16)]

    exec.native_account::get_id
    # => [own_suffix, own_prefix, staged_suffix, staged_prefix, pad(16)]

    exec.account_id::eq
    # => [is_own_id, pad(16)]

    assert.err="parity: the staged bytes32 does not decode to the account's own id"
    # => [pad(16)]
end
"#;

// HARNESS
// ================================================================================================

/// One account carrying the xreserve library plus the derive driver, and the chain it lives on.
struct DeriveHarness {
    mock_chain: MockChain,
    account_id: AccountId,
    /// How the transaction names the account. Private accounts are not committed to the chain in
    /// full, so they have to be passed by value rather than by id.
    tx_input: MockTransactionInput,
    driver_code: AccountComponentCode,
    driver_path: &'static str,
}

/// Builds one account of the requested type carrying the xreserve library + the derive driver. The
/// account seed is random per call, so successive calls produce genuinely different account ids.
fn setup_derive_account(account_type: AccountType) -> Result<DeriveHarness> {
    let library = assemble_xreserve_lib()?;
    let driver_code = CodeBuilder::new()
        .with_dynamically_linked_package(&library)
        .context("linking the xreserve library into the derive driver")?
        .compile_component_code(DERIVE_DRIVER_PATH, DERIVE_DRIVER_SRC)
        .context("the derive driver component failed to compile")?;

    let xreserve_component = AccountComponent::new(
        library,
        vec![],
        AccountComponentMetadata::new("xusdc-own-id-derive-harness"),
    )
    .context("binding the xreserve library as a component")?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-own-id-derive-driver"),
    )
    .context("binding the derive driver component")?;

    let account_builder = Account::builder(rand::random())
        .account_type(account_type)
        .with_component(xreserve_component)
        .with_component(driver_component);

    let mut builder = MockChain::builder();
    let account = builder
        .add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
        .context("adding the derive harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(DeriveHarness {
        mock_chain,
        account_id: account.id(),
        tx_input: MockTransactionInput::Account(account),
        driver_code,
        driver_path: DERIVE_DRIVER_PATH,
    })
}

/// The production-composed faucet, carrying the same derive driver as its fixture driver so the
/// derivation can be executed inside the real component set.
fn setup_production_derive_faucet() -> Result<DeriveHarness> {
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        MAX_SUPPLY,
        0,
        Word::from([TEST_DOMAIN.as_u32(), 0, 0, 0]),
        None,
        None,
        DERIVE_DRIVER_SRC,
        &composition_supply_probe_src(0),
        true,
    )?;
    Ok(DeriveHarness {
        mock_chain: gm.harness.mock_chain,
        account_id: gm.harness.account_id,
        tx_input: MockTransactionInput::AccountId(gm.harness.account_id),
        driver_code: gm.harness.driver_code,
        driver_path: GUARDED_DRIVER_PATH,
    })
}

/// Calls `proc_name` on the harness account with `advice` staged as the transaction's advice stack
/// — the values the driver compares its derivation against.
async fn call_driver(
    h: &DeriveHarness,
    proc_name: &str,
    advice: Vec<Felt>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!(
        "use {path} as driver\n\
         @transaction_script\n\
         pub proc main\n\
             call.driver::{proc_name}\n\
         end\n",
        path = h.driver_path
    );
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(&h.driver_code)
        .expect("linking the driver component into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| {
            panic!("driver call script failed to compile: {e}\n--- src ---\n{src}")
        });
    h.mock_chain
        .build_transaction(h.tx_input.clone())
        .tx_script(tx_script)
        .extend_advice_inputs(AdviceInputs::default().with_stack(advice.into()))
        .build()
        .expect("building the transaction")
        .execute()
        .await
}

/// The Rust side of the packaging: the eight u32-LE-packed limbs of `EthEmbeddedAccountId::from_account_id(id).to_bytes32()`,
/// limb 0 first — the order `adv_push` pops them off the advice stack and the driver stages them in.
fn encoded_bytes32_limbs(id: AccountId) -> Vec<Felt> {
    bytes32_to_packed_felts(&EthEmbeddedAccountId::from_account_id(id).to_bytes32()).to_vec()
}

/// The account ids the parity spread covers: `SPREAD_SIZE` freshly generated accounts, alternating
/// account type, each carrying the real xreserve library.
fn spread() -> Result<Vec<DeriveHarness>> {
    (0..SPREAD_SIZE)
        .map(|i| {
            setup_derive_account(if i % 2 == 0 {
                AccountType::Public
            } else {
                AccountType::Private
            })
        })
        .collect()
}

// THE CANARY — the kernel really hands the faucet its own id in account context
// ================================================================================================

/// `native_account::get_id`, read from inside a `call`-invoked account procedure, reports exactly
/// the felts Rust reads off the same `AccountId`.
///
/// Everything downstream is arithmetic on those two felts, so this pins the single value the whole
/// derivation is a function of, independently of the packaging that consumes it.
#[tokio::test]
async fn native_account_id_matches_the_rust_felts_in_account_context() -> Result<()> {
    let mut harnesses = spread()?;
    harnesses.push(setup_production_derive_faucet()?);
    for h in &harnesses {
        let (prefix, suffix) = (h.account_id.prefix().as_felt(), h.account_id.suffix());
        call_driver(h, "assert_native_id", vec![suffix, prefix])
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "account {}: get_id must report the Rust felts: {e}",
                    h.account_id
                )
            });
    }
    Ok(())
}

// PARITY — the decode, over the whole spread
// ================================================================================================

/// The bytes `EthEmbeddedAccountId::to_bytes32` produces for an account decode, on chain, back to that exact
/// account — for every id in the spread and for the production faucet.
///
/// This is the layer Circle's wire format actually fixes: sixteen zero bytes, then the prefix as a
/// u64 big endian, then the suffix as a u64 big endian. It is also exactly what the mint path does
/// with a deposit intent's `remoteToken`, so a disagreement here is a disagreement about which
/// deposits the faucet accepts.
#[tokio::test]
async fn own_id_bytes32_packaging_matches_the_rust_encoding() -> Result<()> {
    let mut harnesses = spread()?;
    harnesses.push(setup_production_derive_faucet()?);
    for h in &harnesses {
        call_driver(
            h,
            "assert_bytes32_decodes_to_own_id",
            encoded_bytes32_limbs(h.account_id),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "account {}: to_bytes32 must decode back to the account on chain: {e}",
                h.account_id
            )
        });
    }
    Ok(())
}

// CONTROLS — the assertions above cannot pass vacuously
// ================================================================================================

/// Feeding one account the OTHER account's bytes32 encoding traps.
///
/// Without this, an identity compare that had been dropped — or one that compared the decode
/// against itself — would sail through the parity test above.
#[tokio::test]
async fn foreign_expected_bytes32_limbs_trap() -> Result<()> {
    let a = setup_derive_account(AccountType::Public)?;
    let b = setup_derive_account(AccountType::Private)?;
    assert_ne!(
        a.account_id, b.account_id,
        "the two harness accounts must have different ids"
    );
    let result = call_driver(
        &a,
        "assert_bytes32_decodes_to_own_id",
        encoded_bytes32_limbs(b.account_id),
    )
    .await;
    // b's encoding is perfectly well formed — its pad is zero and its id is structurally valid — so
    // the decode succeeds and the IDENTITY compare is what has to fire.
    assert_transaction_executor_error!(
        result,
        &MasmError::from_static_str(
            "parity: the staged bytes32 does not decode to the account's own id"
        )
    );
    Ok(())
}

/// A NON-ZERO pad traps — the sixteen pad bytes are asserted, not ignored.
///
/// The foreign-account control above can never reach this: the pad is sixteen zero bytes for every
/// account, so no other id can make it differ. Dirtying it is the only way to prove it is checked —
/// and it is what stops a `remoteToken` that carries the right account id inside the wrong
/// packaging, which is precisely what a compare over the id felts alone would let through. Both
/// halves of the standards pad check get a case: limb 0 (wire bytes 0..4) and limb 3 (wire bytes
/// 12..16) are asserted by different procedures and surface different errors.
#[rstest]
#[case::leading_twelve(0, "leading 12 bytes must be zero for a bytes32-embedded address")]
#[case::bytes_twelve_to_sixteen(3, "most-significant 4 bytes must be zero for AccountId")]
#[tokio::test]
async fn a_nonzero_expected_pad_traps(
    #[case] dirty_limb: usize,
    #[case] expected_err: &'static str,
) -> Result<()> {
    let a = setup_derive_account(AccountType::Public)?;
    let mut limbs = encoded_bytes32_limbs(a.account_id);
    assert_eq!(
        &limbs[0..4],
        &[miden_protocol::ZERO; 4],
        "the frozen packaging pads wire bytes 0..16 with zeros"
    );
    limbs[dirty_limb] = miden_protocol::ONE;
    let result = call_driver(&a, "assert_bytes32_decodes_to_own_id", limbs).await;
    assert_transaction_executor_error!(result, &MasmError::from_static_str(expected_err));
    Ok(())
}

/// Two accounts encode to DIFFERENT bytes32 forms — the encoding reads the id rather than
/// returning a constant, which is what makes the mint compare an identity check at all.
#[test]
fn distinct_accounts_derive_distinct_bytes32() -> Result<()> {
    let a = setup_derive_account(AccountType::Public)?;
    let b = setup_derive_account(AccountType::Private)?;
    assert_ne!(a.account_id, b.account_id, "distinct harness accounts");
    assert_ne!(
        encoded_bytes32_limbs(a.account_id),
        encoded_bytes32_limbs(b.account_id),
        "distinct accounts must encode to distinct bytes32 packagings"
    );
    Ok(())
}
