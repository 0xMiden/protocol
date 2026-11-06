//! Tests the load of the code patch by the transaction kernel.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use anyhow::Context;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountCode,
    AccountComponent,
    AccountId,
    AccountType,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::code::ProcedureRoot;
use miden_protocol::errors::tx_kernel::ERR_CODE_PATCH_AUTH_NOTE_SCRIPT_ABSENT;
use miden_protocol::note::{Note, NoteType, PartialNote};
use miden_protocol::testing::account_id::{ACCOUNT_ID_PRIVATE_SENDER, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, ProtocolLib, Word};
use miden_standards::StandardsLib;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::mock_account_code::MockAccountCodeExt;
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_tx::LocalTransactionProver;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::mock_transaction::{MockTransaction, TestTransactionBuilder};
use crate::{AccountState, Auth, MockChain, assert_transaction_executor_error};

// TESTS
// ================================================================================================

/// Absent note scripts go into the created procedures, together with the procedures they reference.
/// Present note scripts are not in the code patch. Repeated roots do not change the code patch.
#[tokio::test]
async fn note_scripts_are_put_into_code_patch() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account =
        builder.add_existing_wallet_with_assets(Auth::IncrNonce, [FungibleAsset::mock(20)])?;
    let mock_chain = builder.build()?;

    let p2id_note = create_p2id_note(account.id(), 1)?;
    let custom_note = create_custom_note(account.id(), ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 2)?;
    let notes = [
        p2id_note.clone(),
        custom_note.clone(),
        create_p2id_note(account.id(), 3)?,
        create_custom_note(account.id(), ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 4)?,
    ];
    let script = SendNotesTransactionScript::new(
        &account.code_interface(),
        &notes.iter().cloned().map(PartialNote::from).collect::<Vec<_>>(),
    )?;

    let executed_tx = mock_chain
        .build_transaction(account.id())
        .send_notes_script(&script)
        .expected_output_notes(notes.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?
        .execute()
        .await?;

    let code_patch = executed_tx.code_patch();
    assert_eq!(
        code_patch.created_procedures().collect::<Vec<_>>(),
        [custom_note.script().root().into()]
    );
    assert_eq!(
        code_patch.dependencies().collect::<Vec<_>>(),
        [ProtocolLib::procedure_root("miden::protocol::active_account::get_id")]
    );

    Ok(())
}

/// A present top-level root that an absent note script references is a dependency.
#[tokio::test]
async fn referenced_present_top_level_root_is_a_dependency() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account =
        builder.add_existing_wallet_with_assets(Auth::IncrNonce, [FungibleAsset::mock(10)])?;
    let mock_chain = builder.build()?;

    let p2id_note = create_p2id_note(account.id(), 1)?;
    let custom_note =
        create_custom_note(account.id(), P2ID_REFERENCING_SCRIPT, NoteType::Public, 2)?;
    let notes = [custom_note.clone(), p2id_note.clone()];
    let script = SendNotesTransactionScript::new(
        &account.code_interface(),
        &notes.iter().cloned().map(PartialNote::from).collect::<Vec<_>>(),
    )?;

    let executed_tx = mock_chain
        .build_transaction(account.id())
        .send_notes_script(&script)
        .expected_output_notes(notes.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?
        .execute()
        .await?;

    let code_patch = executed_tx.code_patch();
    assert_eq!(
        code_patch.created_procedures().collect::<Vec<_>>(),
        [custom_note.script().root().into()]
    );
    assert_eq!(
        code_patch.dependencies().collect::<Vec<_>>(),
        [p2id_note.script().root().into()]
    );

    Ok(())
}

/// An absent procedure that an absent note script references is a created procedure, and the
/// procedures that it references are also part of the code patch.
#[tokio::test]
async fn referenced_absent_procedure_is_a_created_procedure() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    // The mock account procedure is absent from the genesis code tree, so the transaction must
    // register its library.
    let mock_procedure = ProcedureRoot::from_raw(
        AccountCode::mock_account_package()
            .get_procedure_root_by_path("mock::account::get_nonce")
            .context("mock account package should export get_nonce")?,
    );
    let note = NoteBuilder::new(account.id(), SmallRng::seed_from_u64(1))
        .code(MOCK_PROCEDURE_REFERENCING_SCRIPT)
        .dynamically_linked_packages(CodeBuilder::mock_packages())
        .build()?;
    let script = SendNotesTransactionScript::new(
        &account.code_interface(),
        &[PartialNote::from(note.clone())],
    )?;

    let executed_tx = mock_chain
        .build_transaction(account.id())
        .send_notes_script(&script)
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .register_library(Arc::clone(AccountCode::mock_account_package().mast_forest()))
        .build()?
        .execute()
        .await?;

    let code_patch = executed_tx.code_patch();
    assert_eq!(
        code_patch.created_procedures().collect::<BTreeSet<_>>(),
        BTreeSet::from([note.script().root().into(), mock_procedure])
    );
    let dependencies = code_patch.dependencies().collect::<Vec<_>>();
    assert!(
        dependencies
            .contains(&ProtocolLib::procedure_root("miden::protocol::active_account::get_nonce"))
    );
    for dependency in dependencies {
        assert!(mock_chain.code_tree().contains(&dependency));
    }

    Ok(())
}

/// The procedures of a new public account are top-level roots, while those of a new private
/// account are not. The mock account component is absent from the genesis code tree, so the
/// procedures of a new public account are created.
#[rstest::rstest]
#[case::public(AccountType::Public)]
#[case::private(AccountType::Private)]
#[tokio::test]
async fn new_account_procedures_are_top_level_roots_if_public(
    #[case] account_type: AccountType,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_account_from_builder(
        Auth::IncrNonce,
        Account::builder([5; 32])
            .account_type(account_type)
            .with_component(MockAccountComponent::with_empty_slots()),
        AccountState::New,
    )?;
    let mock_chain = builder.build()?;

    let executed_tx = mock_chain.build_transaction(account.clone()).build()?.execute().await?;
    let code_patch = executed_tx.code_patch();

    if account_type.is_public() {
        let absent_procedures = account
            .code()
            .procedure_roots()
            .map(ProcedureRoot::from_raw)
            .filter(|procedure_root| !mock_chain.code_tree().contains(procedure_root))
            .collect::<BTreeSet<_>>();
        assert!(!absent_procedures.is_empty());
        assert!(
            code_patch
                .created_procedures()
                .collect::<BTreeSet<_>>()
                .is_superset(&absent_procedures)
        );
    } else {
        assert!(code_patch.is_empty());
    }

    Ok(())
}

/// A note that the authentication procedure creates and that the host does not know at the load
/// needs a witness that proves its script present. The code patch does not change.
#[tokio::test]
async fn unknown_auth_note_with_present_script_is_verified_with_witness() -> anyhow::Result<()> {
    let note = create_p2id_note(ACCOUNT_ID_SENDER.try_into()?, 1)?;

    let executed_tx = auth_procedure_creating_note_tx(&note, false)?.execute().await?;

    assert!(executed_tx.code_patch().is_empty());

    Ok(())
}

/// A note that the authentication procedure creates and that the host does not know at the load
/// must not have an absent script, because the lists do not change after the load.
#[tokio::test]
async fn unknown_auth_note_with_absent_script_is_rejected() -> anyhow::Result<()> {
    let note = create_custom_note(
        ACCOUNT_ID_SENDER.try_into()?,
        ACTIVE_ACCOUNT_SCRIPT,
        NoteType::Public,
        1,
    )?;

    let result = auth_procedure_creating_note_tx(&note, false)?.execute().await;

    assert_transaction_executor_error!(result, ERR_CODE_PATCH_AUTH_NOTE_SCRIPT_ABSENT);

    Ok(())
}

/// A private note that the authentication procedure creates needs no check, so its absent script
/// does not make the transaction fail.
#[tokio::test]
async fn private_auth_note_is_not_verified() -> anyhow::Result<()> {
    let note = create_custom_note(
        ACCOUNT_ID_SENDER.try_into()?,
        ACTIVE_ACCOUNT_SCRIPT,
        NoteType::Private,
        1,
    )?;

    auth_procedure_creating_note_tx(&note, false)?.execute().await?;

    Ok(())
}

/// The host loads the script of an expected note before the authentication procedure creates the
/// note. Thus, the host has the witness of a present script and puts an absent script into the
/// created procedures. The executor gets the MAST of an absent script from the recipient.
#[rstest::rstest]
#[case::present(true)]
#[case::absent(false)]
#[tokio::test]
async fn expected_auth_note_is_loaded_with_the_code_patch(
    #[case] is_present: bool,
) -> anyhow::Result<()> {
    let note = if is_present {
        create_p2id_note(ACCOUNT_ID_SENDER.try_into()?, 1)?
    } else {
        create_custom_note(
            ACCOUNT_ID_SENDER.try_into()?,
            ACTIVE_ACCOUNT_SCRIPT,
            NoteType::Public,
            1,
        )?
    };

    let executed_tx = auth_procedure_creating_note_tx(&note, true)?.execute().await?;

    let is_created = executed_tx
        .code_patch()
        .created_procedures()
        .any(|root| root == note.script().root().into());
    assert_eq!(is_created, !is_present);

    Ok(())
}

/// The prover loads the same lists as the executor for a note that the authentication procedure
/// creates. It gets the MAST of the script from the recipient.
#[tokio::test]
async fn prove_auth_procedure_creates_expected_note_with_absent_script() -> anyhow::Result<()> {
    let note = create_custom_note(
        ACCOUNT_ID_SENDER.try_into()?,
        ACTIVE_ACCOUNT_SCRIPT,
        NoteType::Public,
        1,
    )?;
    let executed_tx = auth_procedure_creating_note_tx(&note, true)?.execute().await?;

    LocalTransactionProver::default().prove(executed_tx)?;

    Ok(())
}

// HELPERS
// ================================================================================================

/// A note script that references a procedure of the protocol library.
const ACTIVE_ACCOUNT_SCRIPT: &str = "
    use miden::protocol::active_account

    @note_script
    pub proc main
        exec.active_account::get_id drop drop
    end
";

/// A note script that references the script of the P2ID note. The script also contains its own
/// code, so that its root differs from the root of the P2ID script.
const P2ID_REFERENCING_SCRIPT: &str = "
    use miden::standards::notes::p2id

    @note_script
    pub proc main
        push.1 drop
        exec.p2id::main
    end
";

/// A note script that references a procedure of the mock account, which in turn references a
/// procedure of the protocol library.
const MOCK_PROCEDURE_REFERENCING_SCRIPT: &str = "
    @note_script
    pub proc main
        call.::mock::account::get_nonce dropw dropw dropw dropw
    end
";

/// Returns a transaction whose authentication procedure creates the note.
///
/// If `is_expected` is `true`, the note is an expected output note, so the host knows its script
/// at the load. Otherwise, only the preimage of its recipient is in the advice map.
fn auth_procedure_creating_note_tx(
    note: &Note,
    is_expected: bool,
) -> anyhow::Result<MockTransaction> {
    let auth_source = format!(
        "
        use miden::protocol::native_account
        use miden::protocol::output_note

        @auth_script
        pub proc auth
            push.{recipient} push.{note_type} push.{tag}
            exec.output_note::create drop

            exec.native_account::incr_nonce drop
            dropw dropw dropw dropw
        end
        ",
        recipient = note.recipient().digest(),
        note_type = Felt::from(note.metadata().note_type()),
        tag = Felt::from(note.metadata().tag()),
    );
    let auth_code =
        CodeBuilder::default().compile_component_code("mock::note_creating_auth", &auth_source)?;
    let auth_component = AccountComponent::new(
        auth_code,
        vec![],
        AccountComponentMetadata::mock("mock::note_creating_auth"),
    )?;
    let account = AccountBuilder::new([43; 32])
        .with_component(auth_component)
        .with_component(BasicWallet)
        .build_existing()?;

    let builder = TestTransactionBuilder::new(account);
    let builder = if is_expected {
        builder.expected_output_note(RawOutputNote::Full(note.clone()))
    } else {
        with_recipient_preimage(builder, note)
    };

    builder.build()
}

/// Returns a public P2ID note, whose script is present in the genesis code tree.
fn create_p2id_note(sender: AccountId, seed: u32) -> anyhow::Result<Note> {
    Ok(Note::from(
        P2idNote::builder()
            .sender(sender)
            .target(ACCOUNT_ID_PRIVATE_SENDER.try_into()?)
            .serial_number(Word::from([seed, 0, 0, 0]))
            .asset(FungibleAsset::mock(10))
            .note_type(NoteType::Public)
            .build()?,
    ))
}

/// Returns a note with the provided script, which is absent from the genesis code tree.
fn create_custom_note(
    sender: AccountId,
    code: &str,
    note_type: NoteType,
    seed: u64,
) -> anyhow::Result<Note> {
    Ok(NoteBuilder::new(sender, SmallRng::seed_from_u64(seed))
        .note_type(note_type)
        .code(code)
        .dynamically_linked_packages([StandardsLib::default().package().as_ref().clone()])
        .build()?)
}

/// Adds the preimage of the recipient of the note to the advice map, without making the note an
/// expected output note. The kernel needs the preimage to read the script root.
fn with_recipient_preimage(builder: TestTransactionBuilder, note: &Note) -> TestTransactionBuilder {
    note.recipient()
        .to_advice_map_entries()
        .into_iter()
        .fold(builder, |builder, (key, elements)| builder.add_advice_map_entry(key, elements))
}
