use miden_protocol::account::AccountHeader;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionWitness;
use prost::Message;

use crate::decoded::transaction::inputs::tests::common;
use crate::{BuildUnchecked, DecodeMessage, proto};

#[test]
fn transaction_witness_roundtrips_through_protobuf() -> anyhow::Result<()> {
    let tx_inputs = common::dummy_transaction_inputs();
    let final_account = AccountHeader::from(tx_inputs.account());
    let expected =
        TransactionWitness::new_unchecked(tx_inputs, final_account, BlockNumber::from(42_u32));

    let encoded = proto::transaction::TransactionWitness::from(&expected).encode_to_vec();
    let message = proto::transaction::TransactionWitness::decode(encoded.as_slice())?;

    assert_eq!(message.decode_fields()?.build_unchecked()?, expected);

    Ok(())
}
