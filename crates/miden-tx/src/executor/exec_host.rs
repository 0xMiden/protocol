use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::{
    AdviceMutation,
    AsyncHost,
    BaseHost,
    EventError,
    FutureMaybeSend,
    MastForest,
    ProcessState,
};
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::{
    AccountCode,
    AccountDelta,
    AccountId,
    PartialAccount,
    StorageSlotId,
    StorageSlotName,
};
use miden_protocol::assembly::debuginfo::Location;
use miden_protocol::assembly::{SourceFile, SourceManagerSync, SourceSpan};
use miden_protocol::asset::{AssetVaultKey, AssetWitness, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::smt::SmtProof;
use miden_protocol::note::{NoteMetadata, NoteRecipient, NoteStorage};
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    OutputNote,
    TransactionAdviceInputs,
    TransactionSummary,
};
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word};

use crate::auth::{SigningInputs, TransactionAuthenticator};
use crate::errors::TransactionKernelError;
use crate::host::{
    RecipientData,
    ScriptMastForestStore,
    TransactionBaseHost,
    TransactionEvent,
    TransactionProgress,
    TransactionProgressEvent,
};
use crate::{AccountProcedureIndexMap, DataStore};

// TRANSACTION EXECUTOR HOST
// ================================================================================================

/// The transaction executor host is responsible for handling [`FutureMaybeSend`] requests made by
/// the transaction kernel during execution. In particular, it responds to signature generation
/// requests by forwarding the request to the contained [`TransactionAuthenticator`].
///
/// Transaction hosts are created on a per-transaction basis. That is, a transaction host is meant
/// to support execution of a single transaction and is discarded after the transaction finishes
/// execution.
pub struct TransactionExecutorHost<'store, 'auth, STORE, AUTH>
where
    STORE: DataStore,
    AUTH: TransactionAuthenticator,
{
    /// The underlying base transaction host.
    base_host: TransactionBaseHost<'store, STORE>,

    /// Tracks the number of cycles for each of the transaction execution stages.
    ///
    /// The progress is updated event handlers.
    tx_progress: TransactionProgress,

    /// Serves signature generation requests from the transaction runtime for signatures which are
    /// not present in the `generated_signatures` field.
    authenticator: Option<&'auth AUTH>,

    /// The reference block of the transaction.
    ref_block: BlockNumber,

    /// The foreign account code that was lazy loaded during transaction execution.
    ///
    /// This is required for re-executing the transaction, e.g. as part of transaction proving.
    accessed_foreign_account_code: Vec<AccountCode>,

    /// Storage slot names for foreign accounts accessed during transaction execution.
    foreign_account_slot_names: BTreeMap<StorageSlotId, StorageSlotName>,

    /// Contains generated signatures (as a message |-> signature map) required for transaction
    /// execution. Once a signature was created for a given message, it is inserted into this map.
    /// After transaction execution, these can be inserted into the advice inputs to re-execute the
    /// transaction without having to regenerate the signature or requiring access to the
    /// authenticator that produced it.
    generated_signatures: BTreeMap<Word, Vec<Felt>>,

    /// The initial balance of the fee asset in the native account's vault.
    initial_fee_asset_balance: u64,

    /// The source manager to track source code file span information, improving any MASM related
    /// error messages.
    source_manager: Arc<dyn SourceManagerSync>,
}

impl<'store, 'auth, STORE, AUTH> TransactionExecutorHost<'store, 'auth, STORE, AUTH>
where
    STORE: DataStore + Sync,
    AUTH: TransactionAuthenticator + Sync,
{
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionExecutorHost`] instance from the provided inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: &PartialAccount,
        input_notes: InputNotes<InputNote>,
        mast_store: &'store STORE,
        scripts_mast_store: ScriptMastForestStore,
        acct_procedure_index_map: AccountProcedureIndexMap,
        authenticator: Option<&'auth AUTH>,
        ref_block: BlockNumber,
        initial_fee_asset_balance: u64,
        source_manager: Arc<dyn SourceManagerSync>,
    ) -> Self {
        let base_host = TransactionBaseHost::new(
            account,
            input_notes,
            mast_store,
            scripts_mast_store,
            acct_procedure_index_map,
        );

        Self {
            base_host,
            tx_progress: TransactionProgress::default(),
            authenticator,
            ref_block,
            accessed_foreign_account_code: Vec::new(),
            foreign_account_slot_names: BTreeMap::new(),
            generated_signatures: BTreeMap::new(),
            initial_fee_asset_balance,
            source_manager,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the `tx_progress` field of this transaction host.
    pub fn tx_progress(&self) -> &TransactionProgress {
        &self.tx_progress
    }

    /// Returns a reference to the foreign account slot names collected during execution.
    pub fn foreign_account_slot_names(&self) -> &BTreeMap<StorageSlotId, StorageSlotName> {
        &self.foreign_account_slot_names
    }

    // EVENT HANDLERS
    // --------------------------------------------------------------------------------------------

    /// Handles a request for a foreign account by querying the data store for its account inputs.
    async fn on_foreign_account_requested(
        &mut self,
        foreign_account_id: AccountId,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let foreign_account_inputs = self
            .base_host
            .store()
            .get_foreign_account_inputs(foreign_account_id, self.ref_block)
            .await
            .map_err(|err| TransactionKernelError::GetForeignAccountInputs {
                foreign_account_id,
                ref_block: self.ref_block,
                source: err,
            })?;

        let mut tx_advice_inputs = TransactionAdviceInputs::default();
        tx_advice_inputs.add_foreign_accounts([&foreign_account_inputs]);

        // Extract and store slot names for this foreign account and store.
        foreign_account_inputs.storage().header().slots().for_each(|slot| {
            self.foreign_account_slot_names.insert(slot.id(), slot.name().clone());
        });

        self.base_host.load_foreign_account_code(foreign_account_inputs.code());

        // Add the foreign account's code to the list of accessed code.
        self.accessed_foreign_account_code.push(foreign_account_inputs.code().clone());

        Ok(tx_advice_inputs.into_advice_mutations().collect())
    }

    /// Pushes a signature to the advice stack as a response to the `AuthRequest` event.
    ///
    /// The signature is requested from the host's authenticator.
    pub async fn on_auth_requested(
        &mut self,
        pub_key_hash: Word,
        tx_summary: TransactionSummary,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let signing_inputs = SigningInputs::TransactionSummary(Box::new(tx_summary));

        let authenticator =
            self.authenticator.ok_or(TransactionKernelError::MissingAuthenticator)?;

        // get the message that will be signed by the authenticator
        let message = signing_inputs.to_commitment();

        let signature: Vec<Felt> = authenticator
            .get_signature(PublicKeyCommitment::from(pub_key_hash), &signing_inputs)
            .await
            .map_err(TransactionKernelError::SignatureGenerationFailed)?
            .to_prepared_signature(message);

        let signature_key = Hasher::merge(&[pub_key_hash, message]);
        self.generated_signatures.insert(signature_key, signature.clone());

        Ok(vec![AdviceMutation::extend_stack(signature)])
    }

    /// Handles the [`TransactionEvent::EpilogueBeforeTxFeeRemovedFromAccount`] and returns an error
    /// if the account cannot pay the fee.
    async fn on_before_tx_fee_removed_from_account(
        &self,
        fee_asset: FungibleAsset,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        // Construct initial fee asset.
        let initial_fee_asset =
            FungibleAsset::new(fee_asset.faucet_id(), self.initial_fee_asset_balance)
                .expect("fungible asset created from fee asset should be valid");

        // Compute the current balance of the native asset in the account based on the initial value
        // and the delta.
        let current_fee_asset = {
            let fee_asset_amount_delta = self
                .base_host
                .account_delta_tracker()
                .vault_delta()
                .fungible()
                .amount(&initial_fee_asset.faucet_id())
                .unwrap_or(0);

            // SAFETY: Initial native asset faucet ID should be a fungible faucet and amount should
            // be less than MAX_AMOUNT as checked by the account delta.
            let fee_asset_delta = FungibleAsset::new(
                initial_fee_asset.faucet_id(),
                fee_asset_amount_delta.unsigned_abs(),
            )
            .expect("faucet ID and amount should be valid");

            // SAFETY: These computations are essentially the same as the ones executed by the
            // transaction kernel, which should have aborted if they weren't valid.
            if fee_asset_amount_delta > 0 {
                initial_fee_asset
                    .add(fee_asset_delta)
                    .expect("transaction kernel should ensure amounts do not exceed MAX_AMOUNT")
            } else {
                initial_fee_asset
                    .sub(fee_asset_delta)
                    .expect("transaction kernel should ensure amount is not negative")
            }
        };

        // Return an error if the balance in the account does not cover the fee.
        if current_fee_asset.amount() < fee_asset.amount() {
            return Err(TransactionKernelError::InsufficientFee {
                account_balance: current_fee_asset.amount(),
                tx_fee: fee_asset.amount(),
            });
        }

        Ok(Vec::new())
    }

    /// Handles a request for a storage map witness by querying the data store for a merkle path.
    ///
    /// Note that we request witnesses against the _initial_ map root of the accounts. See also
    /// [`Self::on_account_vault_asset_witness_requested`] for more on this topic.
    async fn on_account_storage_map_witness_requested(
        &self,
        active_account_id: AccountId,
        map_root: Word,
        map_key: Word,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let storage_map_witness = self
            .base_host
            .store()
            .get_storage_map_witness(active_account_id, map_root, map_key)
            .await
            .map_err(|err| TransactionKernelError::GetStorageMapWitness {
                map_root,
                map_key,
                source: err,
            })?;

        // Get the nodes in the proof and insert them into the merkle store.
        let merkle_store_ext =
            AdviceMutation::extend_merkle_store(storage_map_witness.authenticated_nodes());

        let smt_proof = SmtProof::from(storage_map_witness);
        let map_ext = AdviceMutation::extend_map(AdviceMap::from_iter([(
            smt_proof.leaf().hash(),
            smt_proof.leaf().to_elements(),
        )]));

        Ok(vec![merkle_store_ext, map_ext])
    }

    /// Handles a request to an asset witness by querying the data store for a merkle path.
    ///
    /// ## Native Account
    ///
    /// For the native account we always request witnesses for the initial vault root, because the
    /// data store only has the state of the account vault at the beginning of the transaction.
    /// Since the vault root can change as the transaction progresses, this means the witnesses
    /// may become _partially_ or fully outdated. To see why they can only be _partially_ outdated,
    /// consider the following example:
    ///
    /// ```text
    ///      A               A'
    ///     / \             /  \
    ///    B   C    ->    B'    C
    ///   / \  / \       /  \  / \
    ///  D  E F   G     D   E' F  G
    /// ```
    ///
    /// Leaf E was updated to E', in turn updating nodes B and A. If we now request the merkle path
    /// to G against root A (the initial vault root), we'll get nodes F and B. F is a node in the
    /// updated tree, while B is not. We insert both into the merkle store anyway. Now, if the
    /// transaction attempts to verify the merkle path to G, it can do so because F and B' are in
    /// the merkle store. Note that B' is in the store because the transaction inserted it into the
    /// merkle store as part of updating E, not because we inserted it. B is present in the store,
    /// but is simply ignored for the purpose of verifying G's inclusion.
    ///
    /// ## Foreign Accounts
    ///
    /// Foreign accounts are read-only and so they cannot change throughout transaction execution.
    /// This means their _current_ vault root is always equivalent to their _initial_ vault root.
    /// So, for foreign accounts, just like for the native account, we also always request
    /// witnesses for the initial vault root.
    async fn on_account_vault_asset_witness_requested(
        &self,
        active_account_id: AccountId,
        vault_root: Word,
        asset_key: AssetVaultKey,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let asset_witnesses = self
            .base_host
            .store()
            .get_vault_asset_witnesses(
                active_account_id,
                vault_root,
                BTreeSet::from_iter([asset_key]),
            )
            .await
            .map_err(|err| TransactionKernelError::GetVaultAssetWitness {
                vault_root,
                asset_key,
                source: err,
            })?;

        Ok(asset_witnesses.into_iter().flat_map(asset_witness_to_advice_mutation).collect())
    }

    /// Handles a request for a [`NoteScript`] by querying the [`DataStore`].
    ///
    /// The script is fetched from the data store and used to build a [`NoteRecipient`], which is
    /// then used to create an [`OutputNoteBuilder`]. This function is only called for public notes
    /// where the script is not already available in the advice provider.
    async fn on_note_script_requested(
        &mut self,
        note_idx: usize,
        recipient_digest: Word,
        script_root: Word,
        metadata: NoteMetadata,
        note_storage: NoteStorage,
        serial_num: Word,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let note_script_result = self.base_host.store().get_note_script(script_root).await;

        match note_script_result {
            Ok(Some(note_script)) => {
                let script_felts: Vec<Felt> = (&note_script).into();
                let recipient = NoteRecipient::new(serial_num, note_script, note_storage);

                if recipient.digest() != recipient_digest {
                    return Err(TransactionKernelError::other(format!(
                        "recipient digest is {recipient_digest}, but recipient constructed from raw inputs has digest {}",
                        recipient.digest()
                    )));
                }

                self.base_host.output_note_from_recipient(note_idx, metadata, recipient)?;

                Ok(vec![AdviceMutation::extend_map(AdviceMap::from_iter([(
                    script_root,
                    script_felts,
                )]))])
            },
            Ok(None) if metadata.is_private() => {
                self.base_host.output_note_from_recipient_digest(
                    note_idx,
                    metadata,
                    recipient_digest,
                )?;

                Ok(Vec::new())
            },
            Ok(None) => Err(TransactionKernelError::other(format!(
                "note script with root {script_root} not found in data store for public note"
            ))),
            Err(err) => Err(TransactionKernelError::other_with_source(
                "failed to retrieve note script from data store",
                err,
            )),
        }
    }

    /// Consumes `self` and returns the account delta, output notes, generated signatures and
    /// transaction progress.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        AccountDelta,
        InputNotes<InputNote>,
        Vec<OutputNote>,
        Vec<AccountCode>,
        BTreeMap<Word, Vec<Felt>>,
        TransactionProgress,
        BTreeMap<StorageSlotId, StorageSlotName>,
    ) {
        let (account_delta, input_notes, output_notes) = self.base_host.into_parts();

        (
            account_delta,
            input_notes,
            output_notes,
            self.accessed_foreign_account_code,
            self.generated_signatures,
            self.tx_progress,
            self.foreign_account_slot_names,
        )
    }
}

// HOST IMPLEMENTATION
// ================================================================================================

impl<STORE, AUTH> BaseHost for TransactionExecutorHost<'_, '_, STORE, AUTH>
where
    STORE: DataStore,
    AUTH: TransactionAuthenticator,
{
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let source_manager = self.source_manager.as_ref();
        let maybe_file = source_manager.get_by_uri(location.uri());
        let span = source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }
}

impl<STORE, AUTH> AsyncHost for TransactionExecutorHost<'_, '_, STORE, AUTH>
where
    STORE: DataStore + Sync,
    AUTH: TransactionAuthenticator + Sync,
{
    fn get_mast_forest(&self, node_digest: &Word) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
        let mast_forest = self.base_host.get_mast_forest(node_digest);
        async move { mast_forest }
    }

    fn on_event(
        &mut self,
        process: &ProcessState,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let core_lib_event_result = self.base_host.handle_core_lib_events(process);

        // If the event was handled by a core lib handler (Ok(Some)), we will return the result from
        // within the async block below. So, we only need to extract th tx event if the event was
        // not yet handled (Ok(None)).
        let tx_event_result = match core_lib_event_result {
            Ok(None) => Some(TransactionEvent::extract(&self.base_host, process)),
            _ => None,
        };

        async move {
            if let Some(mutations) = core_lib_event_result? {
                return Ok(mutations);
            }

            // The outer None means the event was handled by core lib handlers.
            let Some(tx_event_result) = tx_event_result else {
                return Ok(Vec::new());
            };
            // The inner None means the transaction event ID does not need to be handled.
            let Some(tx_event) = tx_event_result? else {
                return Ok(Vec::new());
            };

            let result = match tx_event {
                TransactionEvent::AccountBeforeForeignLoad { foreign_account_id: account_id } => {
                    self.on_foreign_account_requested(account_id).await
                },

                TransactionEvent::AccountVaultAfterRemoveAsset { asset } => {
                    self.base_host.on_account_vault_after_remove_asset(asset)
                },
                TransactionEvent::AccountVaultAfterAddAsset { asset } => {
                    self.base_host.on_account_vault_after_add_asset(asset)
                },

                TransactionEvent::AccountStorageAfterSetItem { slot_name, new_value } => {
                    self.base_host.on_account_storage_after_set_item(slot_name, new_value)
                },

                TransactionEvent::AccountStorageAfterSetMapItem {
                    slot_name,
                    key,
                    old_value: prev_map_value,
                    new_value,
                } => self.base_host.on_account_storage_after_set_map_item(
                    slot_name,
                    key,
                    prev_map_value,
                    new_value,
                ),

                TransactionEvent::AccountVaultBeforeAssetAccess {
                    active_account_id,
                    vault_root,
                    asset_key,
                } => {
                    self.on_account_vault_asset_witness_requested(
                        active_account_id,
                        vault_root,
                        asset_key,
                    )
                    .await
                },

                TransactionEvent::AccountStorageBeforeMapItemAccess {
                    active_account_id,
                    map_root,
                    map_key,
                } => {
                    self.on_account_storage_map_witness_requested(
                        active_account_id,
                        map_root,
                        map_key,
                    )
                    .await
                },

                TransactionEvent::AccountAfterIncrementNonce => {
                    self.base_host.on_account_after_increment_nonce()
                },

                TransactionEvent::AccountPushProcedureIndex { code_commitment, procedure_root } => {
                    self.base_host.on_account_push_procedure_index(code_commitment, procedure_root)
                },

                TransactionEvent::NoteBeforeCreated { note_idx, metadata, recipient_data } => {
                    match recipient_data {
                        RecipientData::Digest(recipient_digest) => {
                            self.base_host.output_note_from_recipient_digest(
                                note_idx,
                                metadata,
                                recipient_digest,
                            )
                        },
                        RecipientData::Recipient(note_recipient) => self
                            .base_host
                            .output_note_from_recipient(note_idx, metadata, note_recipient),
                        RecipientData::ScriptMissing {
                            recipient_digest,
                            serial_num,
                            script_root,
                            note_storage,
                        } => {
                            self.on_note_script_requested(
                                note_idx,
                                recipient_digest,
                                script_root,
                                metadata,
                                note_storage,
                                serial_num,
                            )
                            .await
                        },
                    }
                },

                TransactionEvent::NoteBeforeAddAsset { note_idx, asset } => {
                    self.base_host.on_note_before_add_asset(note_idx, asset)
                },

                TransactionEvent::NoteBeforeSetAttachment { note_idx, attachment } => self
                    .base_host
                    .on_note_before_set_attachment(note_idx, attachment)
                    .map(|_| Vec::new()),

                TransactionEvent::AuthRequest { pub_key_hash, tx_summary, signature } => {
                    if let Some(signature) = signature {
                        Ok(self.base_host.on_auth_requested(signature))
                    } else {
                        self.on_auth_requested(pub_key_hash, tx_summary).await
                    }
                },

                // This always returns an error to abort the transaction.
                TransactionEvent::Unauthorized { tx_summary } => {
                    Err(TransactionKernelError::Unauthorized(Box::new(tx_summary)))
                },

                TransactionEvent::EpilogueBeforeTxFeeRemovedFromAccount { fee_asset } => {
                    self.on_before_tx_fee_removed_from_account(fee_asset).await
                },

                TransactionEvent::LinkMapSet { advice_mutation } => Ok(advice_mutation),
                TransactionEvent::LinkMapGet { advice_mutation } => Ok(advice_mutation),
                TransactionEvent::Progress(tx_progress) => match tx_progress {
                    TransactionProgressEvent::PrologueStart(clk) => {
                        self.tx_progress.start_prologue(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::PrologueEnd(clk) => {
                        self.tx_progress.end_prologue(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::NotesProcessingStart(clk) => {
                        self.tx_progress.start_notes_processing(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::NotesProcessingEnd(clk) => {
                        self.tx_progress.end_notes_processing(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::NoteExecutionStart { note_id, clk } => {
                        self.tx_progress.start_note_execution(clk, note_id);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::NoteExecutionEnd(clk) => {
                        self.tx_progress.end_note_execution(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::TxScriptProcessingStart(clk) => {
                        self.tx_progress.start_tx_script_processing(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::TxScriptProcessingEnd(clk) => {
                        self.tx_progress.end_tx_script_processing(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::EpilogueStart(clk) => {
                        self.tx_progress.start_epilogue(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::EpilogueEnd(clk) => {
                        self.tx_progress.end_epilogue(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::EpilogueAuthProcStart(clk) => {
                        self.tx_progress.start_auth_procedure(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::EpilogueAuthProcEnd(clk) => {
                        self.tx_progress.end_auth_procedure(clk);
                        Ok(Vec::new())
                    },
                    TransactionProgressEvent::EpilogueAfterTxCyclesObtained(clk) => {
                        self.tx_progress.epilogue_after_tx_cycles_obtained(clk);
                        Ok(Vec::new())
                    },
                },
            };

            result.map_err(EventError::from)
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Converts an [`AssetWitness`] into the set of advice mutations that need to be inserted in order
/// to access the asset.
fn asset_witness_to_advice_mutation(asset_witness: AssetWitness) -> [AdviceMutation; 2] {
    // Get the nodes in the proof and insert them into the merkle store.
    let merkle_store_ext = AdviceMutation::extend_merkle_store(asset_witness.authenticated_nodes());

    let smt_proof = SmtProof::from(asset_witness);
    let map_ext = AdviceMutation::extend_map(AdviceMap::from_iter([(
        smt_proof.leaf().hash(),
        smt_proof.leaf().to_elements(),
    )]));

    [merkle_store_ext, map_ext]
}
