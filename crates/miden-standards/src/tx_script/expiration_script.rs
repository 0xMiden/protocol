use core::num::NonZeroU16;

use miden_protocol::transaction::{TransactionScript, TransactionScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::code_builder::CodeBuilder;

// EXPIRATION TRANSACTION SCRIPT
// ================================================================================================

/// Transaction script that sets the expiration delta.
const EXPIRATION_TX_SCRIPT_SOURCE: &str = "\
use miden::protocol::tx

#! Set the transaction's expiration delta.
#!
#! Inputs:  [[delta, 0, 0, 0], pad(12)]
#! Outputs: [pad(16)]
#!
#! Panics if:
#! - delta is 0 or not a u32 in the range 1..=0xFFFF (ERR_TX_INVALID_EXPIRATION_DELTA).
#!
#! Invocation: call
begin
    exec.tx::update_expiration_block_delta
    # => [pad(16)]
end
";

static EXPIRATION_TX_SCRIPT: LazyLock<TransactionScript> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_tx_script(EXPIRATION_TX_SCRIPT_SOURCE)
        .expect("canonical expiration tx script should compile")
});

/// The canonical transaction script that sets the transaction's expiration delta to the value
/// supplied in the first element of `TX_SCRIPT_ARGS`.
///
/// This is the standard tx script a network account allowlists so that the network transaction
/// builder can bound how long a submitted transaction stays valid. Because the delta is an
/// input rather than hardcoded, the single [`ExpirationTransactionScript::script_root`] covers
/// every delta. It is safe to allowlist on an open network account even though an arbitrary
/// submitter controls the argument: the delta only bounds the inclusion window of the submitter's
/// own transaction - it cannot touch the account's nonce, state, or assets - and the kernel
/// hard-caps it at `0xFFFF` blocks. So the only thing the submitter decides is how soon their own
/// transaction must be included before it expires, within that fixed bound.
///
/// The type pairs the script (via [`From<ExpirationTransactionScript>`]) with the matching
/// `TX_SCRIPT_ARGS` ([`ExpirationTransactionScript::tx_script_args`]), so callers do not assemble
/// the argument word by hand:
///
/// ```ignore
/// let script = ExpirationTransactionScript::new(delta);
/// let context = build_tx_context(/* .. */)
///     .tx_script(script.into())
///     .tx_script_args(script.tx_script_args());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpirationTransactionScript {
    delta: NonZeroU16,
}

impl ExpirationTransactionScript {
    /// Creates an expiration script that sets the transaction's expiration block delta to `delta`.
    ///
    /// `delta` is a [`NonZeroU16`] because the kernel's `update_expiration_block_delta` only
    /// accepts a delta in `1..=0xFFFF` and otherwise fails the transaction with
    /// `ERR_TX_INVALID_EXPIRATION_DELTA`. Encoding that bound in the type keeps this constructor
    /// infallible and guarantees the delta produced by [`Self::tx_script_args`] is always in
    /// range.
    pub fn new(delta: NonZeroU16) -> Self {
        Self { delta }
    }

    /// The `TX_SCRIPT_ARGS` word the script reads its delta from: `[delta, 0, 0, 0]`.
    ///
    /// Since `delta` is a [`NonZeroU16`], this word always carries an in-range delta, so the
    /// script never triggers the kernel's range check. A caller that bypasses this type and
    /// hand-crafts an out-of-range first element makes the kernel reject the transaction with
    /// `ERR_TX_INVALID_EXPIRATION_DELTA`; it does not panic the host.
    pub fn tx_script_args(&self) -> Word {
        Word::from([Felt::from(self.delta.get()), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    /// The [`TransactionScriptRoot`] of the canonical script, to be allowlisted on a network
    /// account via `AuthNetworkAccount::with_allowed_tx_scripts`.
    pub fn script_root() -> TransactionScriptRoot {
        EXPIRATION_TX_SCRIPT.root()
    }
}

impl From<ExpirationTransactionScript> for TransactionScript {
    fn from(_script: ExpirationTransactionScript) -> Self {
        EXPIRATION_TX_SCRIPT.clone()
    }
}
