use alloc::collections::BTreeSet;
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
use miden_protocol::transaction::TransactionEventId;
use miden_protocol::vm::EventId;
use miden_protocol::{CoreLibrary, Word};
use miden_tx::TransactionExecutorHost;
use miden_tx::auth::UnreachableAuth;

use crate::TransactionContext;

// MOCK HOST
// ================================================================================================

/// The [`MockHost`] wraps a [`TransactionExecutorHost`] and forwards event handling requests to it,
/// with the difference that it only handles a subset of the events that the executor host handles.
///
/// Why don't we always forward requests to the executor host? In some tests, when using
/// [`TransactionContext::execute_code`], we want to test that the transaction kernel fails
/// with a certain error when given invalid inputs, but the event handler in the executor host would
/// prematurely abort the transaction due to the invalid inputs. To avoid this situation, the event
/// handler can be disabled and we can test that the transaction kernel has the expected behavior
/// (e.g. even if the transaction host was malicious).
///
/// Some event handlers, such as delta or output note tracking, will similarly interfere with
/// testing a procedure in isolation and these are also turned off in this host.
pub(crate) struct MockHost<'store> {
    /// The underlying [`TransactionExecutorHost`] that the mock host will forward requests to.
    exec_host: TransactionExecutorHost<'store, 'static, TransactionContext, UnreachableAuth>,

    /// The set of event IDs that the mock host will forward to the [`TransactionExecutorHost`].
    ///
    /// Event IDs that are not in this set are not handled. This can be useful in certain test
    /// scenarios.
    handled_events: BTreeSet<EventId>,
}

impl<'store> MockHost<'store> {
    /// Returns a new [`MockHost`] instance with the provided inputs.
    pub fn new(
        exec_host: TransactionExecutorHost<'store, 'static, TransactionContext, UnreachableAuth>,
    ) -> Self {
        // CoreLibrary events are always handled.
        let core_lib_handlers = CoreLibrary::default()
            .handlers()
            .into_iter()
            .map(|(handler_event_name, _)| handler_event_name.to_event_id());
        let mut handled_events = BTreeSet::from_iter(core_lib_handlers);

        // The default set of transaction events that are always handled.
        handled_events.extend(
            [
                &TransactionEventId::AccountPushProcedureIndex,
                &TransactionEventId::LinkMapSet,
                &TransactionEventId::LinkMapGet,
                // TODO: It should be possible to remove this after implementing
                // https://github.com/0xMiden/miden-base/issues/1852.
                &TransactionEventId::EpilogueBeforeTxFeeRemovedFromAccount,
            ]
            .map(TransactionEventId::event_id),
        );

        Self { exec_host, handled_events }
    }

    // Adds the transaction events needed for Lazy loading to the set of handled events.
    pub fn enable_lazy_loading(&mut self) {
        self.handled_events.extend(
            [
                &TransactionEventId::AccountBeforeForeignLoad,
                &TransactionEventId::AccountVaultBeforeGetAsset,
                &TransactionEventId::AccountVaultBeforeAddAsset,
                &TransactionEventId::AccountVaultBeforeRemoveAsset,
                &TransactionEventId::AccountStorageBeforeSetMapItem,
                &TransactionEventId::AccountStorageBeforeGetMapItem,
            ]
            .map(TransactionEventId::event_id),
        );
    }
}

impl<'store> BaseHost for MockHost<'store> {
    fn get_label_and_source_file(
        &self,
        location: &miden_protocol::assembly::debuginfo::Location,
    ) -> (
        miden_protocol::assembly::debuginfo::SourceSpan,
        Option<Arc<miden_protocol::assembly::SourceFile>>,
    ) {
        self.exec_host.get_label_and_source_file(location)
    }
}

impl<'store> AsyncHost for MockHost<'store> {
    fn get_mast_forest(&self, node_digest: &Word) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
        self.exec_host.get_mast_forest(node_digest)
    }

    fn on_event(
        &mut self,
        process: &ProcessState,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let event_id = EventId::from_felt(process.get_stack_item(0));

        async move {
            // If the host should handle the event, delegate to the tx executor host.
            if self.handled_events.contains(&event_id) {
                self.exec_host.on_event(process).await
            } else {
                Ok(Vec::new())
            }
        }
    }
}
