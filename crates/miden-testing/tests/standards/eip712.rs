use miden_core_lib::dsa::ecdsa_k256_keccak::encode_signature;
use miden_processor::advice::AdviceInputs;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::eip712;
use miden_testing::executor::CodeExecutor;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[tokio::test]
async fn verifies_transaction_summary_signature() -> anyhow::Result<()> {
    let tx_summary_hash = Word::new([
        Felt::new(0x0123_4567_89ab_cdef)?,
        Felt::new(0x1020_3040_5060_7080)?,
        Felt::new(0x0f1e_2d3c_4b5a_6978)?,
        Felt::new(0x1122_3344_5566_7788)?,
    ]);
    let mut rng = StdRng::from_seed([0x71; 32]);
    let signing_key = SigningKey::with_rng(&mut rng);
    let public_key = signing_key.public_key();
    let signature = signing_key.sign_prehash(eip712::transaction_summary_digest(tx_summary_hash));
    let witness = encode_signature(&public_key, &signature);
    let public_key_commitment = public_key.to_commitment();

    let tx = tx_summary_hash.as_elements();
    let pk = public_key_commitment.as_elements();
    let script = format!(
        r#"
            use miden::standards::auth::eip712

            begin
                push.9.9.9.9 adv.push_mapval dropw
                push.{tx3}.{tx2}.{tx1}.{tx0}
                push.{pk3}.{pk2}.{pk1}.{pk0}
                exec.eip712::verify_transaction_summary
            end
        "#,
        tx0 = tx[0].as_canonical_u64(),
        tx1 = tx[1].as_canonical_u64(),
        tx2 = tx[2].as_canonical_u64(),
        tx3 = tx[3].as_canonical_u64(),
        pk0 = pk[0].as_canonical_u64(),
        pk1 = pk[1].as_canonical_u64(),
        pk2 = pk[2].as_canonical_u64(),
        pk3 = pk[3].as_canonical_u64(),
    );
    let advice = AdviceInputs::default().with_map([(Word::from([9u32; 4]), witness)]);

    CodeExecutor::with_default_host()
        .extend_advice_inputs(advice)
        .run(&script)
        .await?;
    Ok(())
}
