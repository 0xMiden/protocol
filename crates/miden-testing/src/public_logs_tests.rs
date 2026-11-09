use alloc::vec::Vec;

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountBuilder, AccountComponent, AccountType};
use miden_protocol::{Felt, Hasher};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_tx::LocalTransactionProver;
use rstest::rstest;

use crate::{Auth, MockChain, MockChainBuilder};

#[rstest]
#[case::public_first(AccountType::Public, AccountType::Private)]
#[case::private_first(AccountType::Private, AccountType::Public)]
#[tokio::test]
async fn public_logs_survive_builders_and_snapshot(
    #[case] first_type: AccountType,
    #[case] second_type: AccountType,
) -> anyhow::Result<()> {
    let empty_commitment = Hasher::hash_elements::<Felt>(&[]);
    let component = AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "test::public_logs",
            format!(
                r"
                use miden::protocol::tx
                @account_procedure
                pub proc emit_log
                    push.{empty_commitment} push.29.17 exec.tx::add_log
                end
                ",
            ),
        )?,
        vec![],
        AccountComponentMetadata::mock("test::public_logs"),
    )?;
    let root = component.get_procedure_root_by_path("test::public_logs::emit_log").unwrap();
    let first_account = AccountBuilder::new([51; 32])
        .account_type(first_type)
        .with_component(component)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?;
    let second_account = AccountBuilder::new([52; 32])
        .account_type(second_type)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?;
    let mut chain =
        MockChainBuilder::with_accounts([first_account.clone(), second_account.clone()])?
            .build()?;
    chain.prove_next_block()?;
    let script = CodeBuilder::default().compile_tx_script(format!(
        r"
        use miden::core::sys
        @transaction_script
        pub proc main
            call.{root} exec.sys::truncate_stack
        end
        ",
    ))?;
    let executed = chain
        .build_transaction(first_account)
        .tx_script(script)
        .add_advice_map_entry(empty_commitment, vec![])
        .build()?
        .execute()
        .await?;
    assert_eq!(executed.logs().num_logs(), 1);
    let mut expected = Vec::new();
    if first_type.is_public() {
        expected.push((executed.id(), executed.logs().clone()));
    }
    let proven = LocalTransactionProver::default().prove_dummy(executed)?;
    let first = chain.prove_transaction_batch(chain.propose_transaction_batch([proven])?)?;
    let empty = chain.build_transaction(second_account).build()?.execute().await?;
    assert!(empty.logs().is_empty());
    if second_type.is_public() {
        expected.push((empty.id(), empty.logs().clone()));
    }
    let proven = LocalTransactionProver::default().prove_dummy(empty)?;
    let second = chain.prove_transaction_batch(chain.propose_transaction_batch([proven])?)?;
    let expected_transactions = vec![first.transactions().clone(), second.transactions().clone()];
    chain.add_pending_batch(first);
    chain.add_pending_batch(second);
    let block = chain.prove_next_block()?;
    assert_eq!(block.body().transactions(), expected_transactions);
    assert_eq!(block.body().public_logs().entries(), expected);
    let restored_chain = MockChain::try_from_bytes(&chain.to_bytes())?;
    assert_eq!(restored_chain.latest_block().body().transactions(), expected_transactions);
    assert_eq!(restored_chain.latest_block().body().public_logs(), block.body().public_logs());
    Ok(())
}
