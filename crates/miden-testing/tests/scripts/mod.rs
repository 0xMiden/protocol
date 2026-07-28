mod allowlist;
mod authority;
mod basic_constant_fee_manager;
mod blocklist;
mod code_inspection;
mod expiration;
mod faucet;
mod faucet_policy_action;
mod fee_collection;
mod fee_manager;
mod fee_sponsorship;
mod non_fungible_faucet;
mod ownable2step;
mod owner_action;
mod p2id;
mod p2ide;
mod pausable;
mod pause_action;
mod pswap;
mod rbac;
mod rbac_action;
mod send_note;
mod swap;
mod tx_fee;
mod warden;

// HELPER FUNCTIONS
// ================================================================================================

/// Consumes an owner-authored admin note in a faucet transaction.
async fn consume_note(
    mock_chain: &mut miden_testing::MockChain,
    account_id: miden_protocol::account::AccountId,
    note: &miden_protocol::note::Note,
) -> anyhow::Result<()> {
    let executed = mock_chain
        .build_transaction(account_id)
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
}
