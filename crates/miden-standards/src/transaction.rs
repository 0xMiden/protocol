//! Standardized transaction scripts.

use core::num::NonZeroU16;

use miden_protocol::transaction::{TransactionScript, TransactionScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::code_builder::CodeBuilder;

// EXPIRATION TRANSACTION SCRIPT
// ================================================================================================

/// Source of the canonical transaction script that sets the transaction expiration delta.
///
/// The delta is read from the first element of `TX_SCRIPT_ARGS` rather than baked into the script,
/// so a single MAST root accepts any caller-chosen delta. At script entry the operand stack holds
/// `[TX_SCRIPT_ARGS]`, so the top element is the delta; `update_expiration_block_delta`
/// consumes it and the remaining three argument elements are dropped.
const EXPIRATION_TX_SCRIPT_SOURCE: &str = "\
use miden::protocol::tx

begin
    exec.tx::update_expiration_block_delta
    drop drop drop
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
/// builder can bound how long a submitted network transaction stays valid. Because the delta is an
/// input rather than hardcoded, the single [`ExpirationTransactionScript::script_root`] covers
/// every delta; and since the kernel only ever lets the delta be tightened (never extended) within
/// a single transaction, it is safe to allowlist on an open network account even though the
/// (arbitrary) submitter controls the argument - the worst they can do is make their own
/// transaction expire sooner.
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
    /// `delta` is a [`NonZeroU16`] because the kernel requires the expiration delta to be in
    /// `1..=0xFFFF`; encoding that in the type keeps this constructor infallible.
    pub fn new(delta: NonZeroU16) -> Self {
        Self { delta }
    }

    /// The `TX_SCRIPT_ARGS` word the script reads its delta from: `[delta, 0, 0, 0]`.
    pub fn tx_script_args(&self) -> Word {
        Word::from([Felt::from(self.delta.get()), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    /// The [`TransactionScriptRoot`] shared by every delta - the script reads the delta from
    /// `TX_SCRIPT_ARGS`, so its root is delta-independent. Allowlist this on a network account via
    /// `AuthNetworkAccount::with_allowed_tx_scripts`.
    pub fn script_root() -> TransactionScriptRoot {
        EXPIRATION_TX_SCRIPT.root()
    }
}

impl From<ExpirationTransactionScript> for TransactionScript {
    /// The compiled script is delta-independent (the delta is passed via `TX_SCRIPT_ARGS`), so this
    /// returns the single cached canonical script regardless of the configured delta.
    fn from(_script: ExpirationTransactionScript) -> Self {
        EXPIRATION_TX_SCRIPT.clone()
    }
}
