//! Assertion macro for note-lifecycle checks in tests.

use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::note::NoteType;
use miden_protocol::transaction::ExecutedTransaction;

/// Spec for [`assert_note_created!`]. Fields left as `None` are skipped.
#[doc(hidden)]
#[derive(Default, Debug, Clone)]
pub struct OutputNoteSpec {
    pub note_type: Option<NoteType>,
    pub sender: Option<AccountId>,
    pub assets: Option<Vec<Asset>>,
}

/// Returns `true` if at least one output note in `tx` matches `spec`.
#[doc(hidden)]
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
            let actual = note.assets();
            if actual.num_assets() != expected.len() {
                return false;
            }
            // Each actual matches at most once (otherwise [A,A] would match [A,B]).
            let mut consumed = vec![false; expected.len()];
            let matched = expected.iter().all(|exp| {
                let slot = actual.iter().enumerate().find(|(i, a)| !consumed[*i] && *a == exp);
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
