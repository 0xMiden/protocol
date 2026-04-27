use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::note::{Note, NoteId, NoteType, Nullifier};
use miden_protocol::transaction::{ExecutedTransaction, InputNote};

use crate::MockChain;

// TX-LEVEL
// ================================================================================================

/// Spec for [`assert_note_created!`]. Fields left as `None` are skipped.
#[derive(Default, Debug, Clone)]
pub struct OutputNoteSpec {
    pub note_type: Option<NoteType>,
    pub sender: Option<AccountId>,
    pub assets: Option<Vec<Asset>>,
}

/// Returns `true` if at least one output note in `tx` matches `spec`.
pub fn check_output_note_created(tx: &ExecutedTransaction, spec: &OutputNoteSpec) -> bool {
    tx.output_notes().iter().any(|note| {
        if let Some(expected) = spec.note_type
            && note.metadata().note_type() != expected
        {
            return false;
        }
        if let Some(expected) = spec.sender
            && note.metadata().sender() != expected
        {
            return false;
        }
        if let Some(expected) = spec.assets.as_ref() {
            let actual: Vec<&Asset> = note.assets().iter().collect();
            if actual.len() != expected.len() {
                return false;
            }
            // Each actual matches at most once (otherwise [A,A] would match [A,B]).
            let mut consumed = vec![false; actual.len()];
            let matched = expected.iter().all(|exp| {
                let slot = actual.iter().enumerate().find(|(i, a)| !consumed[*i] && **a == exp);
                if let Some((i, _)) = slot {
                    consumed[i] = true;
                    true
                } else {
                    false
                }
            });
            if !matched {
                return false;
            }
        }
        true
    })
}

/// Lets [`assert_note_consumed_by!`] take a `NoteId`, `Nullifier`, `Note`, or `InputNote`.
pub trait MatchesTxInput {
    fn matches_tx_input(&self, input: &InputNote) -> bool;
}

impl MatchesTxInput for NoteId {
    fn matches_tx_input(&self, input: &InputNote) -> bool {
        input.id() == *self
    }
}

impl MatchesTxInput for Nullifier {
    fn matches_tx_input(&self, input: &InputNote) -> bool {
        input.note().nullifier() == *self
    }
}

impl MatchesTxInput for Note {
    fn matches_tx_input(&self, input: &InputNote) -> bool {
        input.id() == self.id()
    }
}

impl MatchesTxInput for InputNote {
    fn matches_tx_input(&self, input: &InputNote) -> bool {
        input.id() == self.id()
    }
}

impl<T: MatchesTxInput + ?Sized> MatchesTxInput for &T {
    fn matches_tx_input(&self, input: &InputNote) -> bool {
        (**self).matches_tx_input(input)
    }
}

/// Asserts the tx emitted a note matching the spec. Fields are optional; unset ones are skipped.
///
/// # Example
/// ```ignore
/// use miden_testing::assert_note_created;
/// use miden_protocol::note::NoteType;
///
/// assert_note_created!(
///     executed_tx,
///     note_type: NoteType::Public,
///     sender: faucet.id(),
///     assets: [FungibleAsset::new(faucet.id(), amount)?.into()],
/// );
/// ```
#[macro_export]
macro_rules! assert_note_created {
    ($tx:expr $(, $key:ident : $val:expr)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut spec = $crate::asserts::OutputNoteSpec::default();
        $(
            $crate::__assert_note_created_field!(spec, $key, $val);
        )*
        let tx: &::miden_protocol::transaction::ExecutedTransaction = &$tx;
        assert!(
            $crate::asserts::check_output_note_created(tx, &spec),
            "no output note matches spec: {:?}\n  tx produced {} output note(s)",
            spec,
            tx.output_notes().num_notes(),
        );
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __assert_note_created_field {
    ($spec:ident,note_type, $val:expr) => {
        $spec.note_type = ::core::option::Option::Some($val);
    };
    ($spec:ident,sender, $val:expr) => {
        $spec.sender = ::core::option::Option::Some($val);
    };
    ($spec:ident,assets, $val:expr) => {
        $spec.assets = ::core::option::Option::Some(
            ::core::iter::IntoIterator::into_iter($val)
                .map(::core::convert::Into::into)
                .collect::<::alloc::vec::Vec<::miden_protocol::asset::Asset>>(),
        );
    };
    ($spec:ident, $key:ident, $val:expr) => {
        ::core::compile_error!(concat!(
            "unknown field in assert_note_created!: `",
            stringify!($key),
            "`. Supported fields: note_type, sender, assets",
        ));
    };
}

/// Asserts the tx consumed the given note (checks `tx.input_notes()`).
///
/// Tx-level counterpart to [`assert_note_consumed!`].
///
/// Accepts `NoteId`, `Nullifier`, `&Note`, or `&InputNote`.
#[macro_export]
macro_rules! assert_note_consumed_by {
    ($tx:expr, $note_ref:expr $(,)?) => {{
        let tx: &::miden_protocol::transaction::ExecutedTransaction = &$tx;
        let matcher = &$note_ref;
        let found = tx
            .input_notes()
            .iter()
            .any(|n| $crate::asserts::MatchesTxInput::matches_tx_input(matcher, n));
        assert!(
            found,
            "tx does not consume the expected note\n  tx has {} input note(s)",
            tx.input_notes().num_notes(),
        );
    }};
}

// CHAIN-LEVEL
// ================================================================================================

/// Lets chain-level macros take a [`NoteId`], a [`Note`], or an [`InputNote`].
pub trait AsNoteId {
    fn as_note_id(&self) -> NoteId;
}

impl AsNoteId for NoteId {
    fn as_note_id(&self) -> NoteId {
        *self
    }
}

impl AsNoteId for Note {
    fn as_note_id(&self) -> NoteId {
        self.id()
    }
}

impl AsNoteId for InputNote {
    fn as_note_id(&self) -> NoteId {
        self.id()
    }
}

impl<T: AsNoteId + ?Sized> AsNoteId for &T {
    fn as_note_id(&self) -> NoteId {
        (**self).as_note_id()
    }
}

/// Lets chain-level macros take a [`Nullifier`], [`NoteId`], [`Note`], or [`InputNote`].
///
/// A bare [`NoteId`] needs the chain for the lookup; other impls ignore it.
pub trait AsNullifier {
    /// # Panics
    /// Panics if the `NoteId` isn't in `chain.committed_notes()` (e.g. a private note).
    fn as_nullifier(&self, chain: &MockChain) -> Nullifier;
}

impl AsNullifier for Nullifier {
    fn as_nullifier(&self, _chain: &MockChain) -> Nullifier {
        *self
    }
}

impl AsNullifier for Note {
    fn as_nullifier(&self, _chain: &MockChain) -> Nullifier {
        self.nullifier()
    }
}

impl AsNullifier for InputNote {
    fn as_nullifier(&self, _chain: &MockChain) -> Nullifier {
        self.note().nullifier()
    }
}

impl AsNullifier for NoteId {
    fn as_nullifier(&self, chain: &MockChain) -> Nullifier {
        chain
            .committed_notes()
            .get(self)
            .and_then(|n| n.note())
            .map(|n| n.nullifier())
            .unwrap_or_else(|| {
                panic!(
                    "NoteId {self} not in chain.committed_notes() (private or unknown). Pass the full Note or Nullifier instead.",
                )
            })
    }
}

impl<T: AsNullifier + ?Sized> AsNullifier for &T {
    fn as_nullifier(&self, chain: &MockChain) -> Nullifier {
        (**self).as_nullifier(chain)
    }
}

/// Asserts the note is in [`MockChain::committed_notes()`](crate::MockChain::committed_notes).
///
/// Accepts `NoteId`, `&Note`, or `&InputNote`.
#[macro_export]
macro_rules! assert_note_committed {
    ($chain:expr, $note_ref:expr $(,)?) => {{
        let chain: &$crate::MockChain = &$chain;
        let id = $crate::asserts::AsNoteId::as_note_id(&$note_ref);
        assert!(
            chain.committed_notes().contains_key(&id),
            "note {id} is not in chain.committed_notes()",
        );
    }};
}

/// Asserts the note's nullifier is not on-chain (note isn't consumed yet).
///
/// Accepts `Nullifier`, `NoteId`, `&Note`, or `&InputNote`. A bare `NoteId` needs the note in
/// `chain.committed_notes()`.
#[macro_export]
macro_rules! assert_note_unspent {
    ($chain:expr, $note_ref:expr $(,)?) => {{
        let chain: &$crate::MockChain = &$chain;
        let nullifier = $crate::asserts::AsNullifier::as_nullifier(&$note_ref, chain);
        assert!(
            chain.nullifier_tree().get_block_num(&nullifier).is_none(),
            "note {nullifier} already on-chain (expected unspent)",
        );
    }};
}

/// Asserts the note's nullifier is on-chain (note is consumed).
///
/// Accepts the same types as [`assert_note_unspent!`].
#[macro_export]
macro_rules! assert_note_consumed {
    ($chain:expr, $note_ref:expr $(,)?) => {{
        let chain: &$crate::MockChain = &$chain;
        let nullifier = $crate::asserts::AsNullifier::as_nullifier(&$note_ref, chain);
        assert!(
            chain.nullifier_tree().get_block_num(&nullifier).is_some(),
            "note {nullifier} not on-chain (expected consumed)",
        );
    }};
}
