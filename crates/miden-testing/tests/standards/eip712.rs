use miden_core_lib::dsa::ecdsa_k256_keccak::encode_signature;
use miden_processor::advice::AdviceInputs;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey};
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::utils::hex_to_bytes;
use miden_protocol::{Felt, Word};
use miden_standards::StandardsLib;
use miden_standards::account::auth::eip712;
use miden_testing::executor::CodeExecutor;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn preserves_raw_signature_verifier_root() {
    let expected_root = Word::new([
        Felt::new_unchecked(15_564_461_275_229_092_248),
        Felt::new_unchecked(12_282_628_389_156_206_442),
        Felt::new_unchecked(9_355_626_338_475_529_298),
        Felt::new_unchecked(8_256_853_792_885_978_336),
    ]);
    let actual_root = StandardsLib::default()
        .as_ref()
        .get_procedure_root_by_path("::miden::standards::auth::signature::verify_signatures");

    assert_eq!(actual_root, Some(expected_root));
}

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

#[tokio::test]
async fn verifies_generic_eip712_signature() -> anyhow::Result<()> {
    let tx_summary_hash = Word::new([
        Felt::new(0x0123_4567_89ab_cdef)?,
        Felt::new(0x1020_3040_5060_7080)?,
        Felt::new(0x0f1e_2d3c_4b5a_6978)?,
        Felt::new(0x1122_3344_5566_7788)?,
    ]);
    let domain_separator = eip712::domain_separator();
    let struct_hash = eip712::transaction_struct_hash(tx_summary_hash);

    let mut rng = StdRng::from_seed([0x72; 32]);
    let signing_key = SigningKey::with_rng(&mut rng);
    let public_key = signing_key.public_key();
    let signature = signing_key.sign_prehash(eip712::digest(domain_separator, struct_hash));
    let witness = encode_signature(&public_key, &signature);

    let domain = bytes_to_u32_limbs(domain_separator);
    let message = bytes_to_u32_limbs(struct_hash);
    let public_key_commitment = public_key.to_commitment();
    let pk = public_key_commitment.as_elements();
    let script = format!(
        r#"
            use miden::standards::auth::eip712

            begin
                push.9.9.9.9 adv.push_mapval dropw
                push.{message7}.{message6}.{message5}.{message4}
                push.{message3}.{message2}.{message1}.{message0}
                push.{domain7}.{domain6}.{domain5}.{domain4}
                push.{domain3}.{domain2}.{domain1}.{domain0}
                push.{pk3}.{pk2}.{pk1}.{pk0}
                exec.eip712::verify
            end
        "#,
        domain0 = domain[0],
        domain1 = domain[1],
        domain2 = domain[2],
        domain3 = domain[3],
        domain4 = domain[4],
        domain5 = domain[5],
        domain6 = domain[6],
        domain7 = domain[7],
        message0 = message[0],
        message1 = message[1],
        message2 = message[2],
        message3 = message[3],
        message4 = message[4],
        message5 = message[5],
        message6 = message[6],
        message7 = message[7],
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

#[tokio::test]
async fn verifies_ledger_speculos_signature() -> anyhow::Result<()> {
    let public_key = PublicKey::read_from_bytes(&hex_to_bytes::<33>(
        "0x0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299",
    )?)?;
    let signature = Signature::from_sec1_bytes_and_recovery_id(
        hex_to_bytes::<64>(
            "0x3a260929a57fc23dc0b35b3bd41aa66df2d6cf0aff4914e5caf25f65f2f9f15b\
             2fedb745401497982d8ee305c490af99440edabfd17ada7acfd527b7342f54b4",
        )?,
        0,
    )?;
    let tx_summary_hash = Word::new([Felt::new(0xefcd_ab89_6745_2301)?; 4]);
    let digest = eip712::transaction_summary_digest(tx_summary_hash);
    assert_eq!(
        digest,
        hex_to_bytes::<32>("0xe24fddd9b9535fa24adf94097b68c4f00bbed14ee6970cd41d62a62b5b6a07b3")?
    );
    assert!(public_key.verify_prehash(digest, &signature));

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

fn bytes_to_u32_limbs(bytes: [u8; 32]) -> [u32; 8] {
    core::array::from_fn(|index| {
        let start = index * 4;
        u32::from_le_bytes(bytes[start..start + 4].try_into().expect("four-byte chunk"))
    })
}
