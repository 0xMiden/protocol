use core::num::NonZeroU16;

use miden_protocol::account::auth::AuthScheme;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::{Auth, MockChain};

/// Example: attach the standardized expiration transaction script to a transaction and choose the
/// expiration delta at execution time via `TX_SCRIPT_ARGS`, rather than baking it into the script.
/// A single allowlistable script root therefore works for any delta.
#[tokio::test]
async fn expiration_tx_script_sets_expiration_from_tx_args() -> anyhow::Result<()> {
    const DELTA: NonZeroU16 = NonZeroU16::new(42).unwrap();

    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mock_chain = builder.build()?;

    // Mirror how a real caller (client / node) attaches the script: convert the typed script into a
    // `TransactionScript` and read its matching `TX_SCRIPT_ARGS` off the same typed value, rather
    // than assembling the argument word by hand.
    let script = ExpirationTransactionScript::new(DELTA);

    let executed = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(script.into())
        .tx_script_args(script.tx_script_args())
        .build()?
        .execute()
        .await?;

    assert_eq!(
        executed.expiration_block_num(),
        executed.block_header().block_num() + u32::from(DELTA.get()),
        "the tx-args-supplied expiration delta should be applied",
    );

    Ok(())
}
