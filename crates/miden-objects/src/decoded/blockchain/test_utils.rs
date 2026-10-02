use miden_protocol::Word;
use miden_protocol::block::{BlockHeader, BlockNumber, ValidatorConfig};
use miden_protocol::protocol_config::NextProtocolConfig;

pub(crate) fn block_header_with_scheduled_upgrade() -> BlockHeader {
    let header = BlockHeader::mock(1, None, None, &[]);
    let (_, validator_config) = ValidatorConfig::random_with_signers(3);
    let next_protocol_config =
        NextProtocolConfig::new(BlockNumber::from(42u32), Word::from([9u32, 8, 7, 6])).unwrap();

    BlockHeader::new(
        header.prev_block_commitment(),
        header.block_num(),
        header.chain_commitment(),
        header.account_root(),
        header.nullifier_root(),
        header.note_root(),
        header.tx_commitment(),
        validator_config,
        header.fee_parameters().clone(),
        header.protocol_config_commitment(),
        Some(next_protocol_config),
        header.timestamp(),
    )
}
