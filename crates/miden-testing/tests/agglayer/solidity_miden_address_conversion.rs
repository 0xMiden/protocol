extern crate alloc;

use alloc::sync::Arc;

use miden_agglayer::{EthAddressFormat, agglayer_library};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_processor::fast::{ExecutionOutput, FastProcessor};
use miden_processor::{AdviceInputs, DefaultHost, ExecutionError, Program, StackInputs};
use miden_protocol::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::address::NetworkId;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    AccountIdBuilder,
};
use miden_protocol::transaction::TransactionKernel;

/// Execute a program with default host
async fn execute_program_with_default_host(
    program: Program,
) -> Result<ExecutionOutput, ExecutionError> {
    let mut host = DefaultHost::default();

    let test_lib = TransactionKernel::library();
    host.load_library(test_lib.mast_forest()).unwrap();

    let std_lib = CoreLibrary::default();
    host.load_library(std_lib.mast_forest()).unwrap();

    for (event_name, handler) in std_lib.handlers() {
        host.register_handler(event_name, handler)?;
    }

    let asset_conversion_lib = agglayer_library();
    host.load_library(asset_conversion_lib.mast_forest()).unwrap();

    let stack_inputs = StackInputs::new(vec![]).unwrap();
    let advice_inputs = AdviceInputs::default();

    let processor = FastProcessor::new_debug(stack_inputs.as_slice(), advice_inputs);
    processor.execute(&program, &mut host).await
}

#[test]
fn test_account_id_to_ethereum_roundtrip() {
    let original_account_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let eth_address = EthAddressFormat::from_account_id(original_account_id);
    let recovered_account_id = eth_address.to_account_id().unwrap();
    assert_eq!(original_account_id, recovered_account_id);
}

#[test]
fn test_bech32_to_ethereum_roundtrip() {
    let test_addresses = [
        "mtst1azcw08rget79fqp8ymr0zqkv5v5lj466",
        "mtst1arxmxavamh7lqyp79mexktt4vgxv40mp",
        "mtst1ar2phe0pa0ln75plsczxr8ryws4s8zyp",
    ];

    let evm_addresses = [
        "0x00000000b0e79c68cafc54802726c6f102cca300",
        "0x00000000cdb3759dddfdf0103e2ef26b2d756200",
        "0x00000000d41be5e1ebff3f503f8604619c647400",
    ];

    for (bech32, expected_evm) in test_addresses.iter().zip(evm_addresses.iter()) {
        let (network_id, account_id) = AccountId::from_bech32(bech32).unwrap();

        let eth = EthAddressFormat::from_account_id(account_id);
        let recovered = eth.to_account_id().unwrap();
        let recovered_bech32 = recovered.to_bech32(network_id);

        assert_eq!(&account_id, &recovered);
        assert_eq!(*expected_evm, eth.to_string());
        assert_eq!(*bech32, recovered_bech32);
    }
}

#[test]
fn test_random_bech32_to_ethereum_roundtrip() {
    let mut rng = rand::rng();
    let network_id = NetworkId::Testnet;

    for _ in 0..3 {
        let account_id = AccountIdBuilder::new().build_with_rng(&mut rng);
        let bech32_address = account_id.to_bech32(network_id.clone());
        let eth_address = EthAddressFormat::from_account_id(account_id);
        let recovered_account_id = eth_address.to_account_id().unwrap();
        let recovered_bech32 = recovered_account_id.to_bech32(network_id.clone());

        assert_eq!(account_id, recovered_account_id);
        assert_eq!(bech32_address, recovered_bech32);
    }
}

#[tokio::test]
async fn test_ethereum_address_to_account_id_in_masm() -> anyhow::Result<()> {
    let test_account_ids = [
        AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?,
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?,
        AccountIdBuilder::new().build_with_rng(&mut rand::rng()),
        AccountIdBuilder::new().build_with_rng(&mut rand::rng()),
        AccountIdBuilder::new().build_with_rng(&mut rand::rng()),
    ];

    for (idx, original_account_id) in test_account_ids.iter().enumerate() {
        let eth_address = EthAddressFormat::from_account_id(*original_account_id);

        let address_felts = eth_address.to_elements().to_vec();
        let le: Vec<u32> = address_felts
            .iter()
            .map(|f| {
                let val = f.as_int();
                assert!(val <= u32::MAX as u64, "felt value {} exceeds u32::MAX", val);
                val as u32
            })
            .collect();

        assert_eq!(le[4], 0, "test {}: expected msw limb (le[4]) to be zero", idx);

        let addr0 = le[0];
        let addr1 = le[1];
        let addr2 = le[2];
        let addr3 = le[3];
        let addr4 = le[4];

        let account_id_felts: [Felt; 2] = (*original_account_id).into();
        let expected_prefix = account_id_felts[0].as_int();
        let expected_suffix = account_id_felts[1].as_int();

        let script_code = format!(
            r#"
            use miden::core::sys
            use miden::agglayer::eth_address

            begin
                push.{}.{}.{}.{}.{}
                exec.eth_address::to_account_id
                exec.sys::truncate_stack
            end
            "#,
            addr4, addr3, addr2, addr1, addr0
        );

        let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
            .with_dynamic_library(CoreLibrary::default())
            .unwrap()
            .with_dynamic_library(agglayer_library())
            .unwrap()
            .assemble_program(&script_code)
            .unwrap();

        let exec_output = execute_program_with_default_host(program).await?;

        let actual_prefix = exec_output.stack[0].as_int();
        let actual_suffix = exec_output.stack[1].as_int();

        assert_eq!(actual_prefix, expected_prefix, "test {}: prefix mismatch", idx);
        assert_eq!(actual_suffix, expected_suffix, "test {}: suffix mismatch", idx);

        let reconstructed_account_id =
            AccountId::try_from([Felt::new(actual_prefix), Felt::new(actual_suffix)])?;

        assert_eq!(
            reconstructed_account_id, *original_account_id,
            "test {}: accountId roundtrip failed",
            idx
        );
    }

    Ok(())
}
