use alloc::vec;

use miden_protocol::Word;
use prost::Message;

use crate::decoded::protocol_config::test_utils::dummy_protocol_config;
use crate::{DecodeMessage, Verify, proto};

#[test]
fn protocol_config_roundtrips_through_protobuf_bytes_and_preserves_kernel_order() {
    let config = dummy_protocol_config();

    let encoded = proto::protocol_config::ProtocolConfig::from(&config).encode_to_vec();
    let message = proto::protocol_config::ProtocolConfig::decode(encoded.as_slice()).unwrap();

    assert_eq!(
        message.tx_kernel.as_ref().unwrap().kernel_procs,
        vec![Word::from([2_u32, 0, 0, 0]).into()]
    );
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), config);
}
