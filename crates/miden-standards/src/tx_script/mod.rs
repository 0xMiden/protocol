use miden_protocol::assembly::Path;
use miden_protocol::transaction::TransactionScript;

use crate::StandardsLib;

mod expiration_script;
pub use expiration_script::ExpirationTransactionScript;

mod send_notes_script;
pub use send_notes_script::{
    SendFungibleFaucetNotesTransactionScript,
    SendNonFungibleFaucetNotesTransactionScript,
    SendNotesTransactionScript,
    SendNotesTransactionScriptError,
    SendWalletNotesTransactionScript,
};

/// Resolves the transaction script exported at `path` from the standards library.
///
/// `path` must be the fully qualified path of a procedure carrying the `@transaction_script`
/// attribute, e.g. `::miden::standards::tx_scripts::expiration::main`.
pub(crate) fn transaction_script(path: &str) -> TransactionScript {
    let standards_lib = StandardsLib::default();
    TransactionScript::from_package_reference(standards_lib.as_ref(), Path::new(path))
        .expect("standards library contains the transaction script procedure")
}
