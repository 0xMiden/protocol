use miden_core_lib::dsa::ecdsa_k256_keccak::encode_signature;
use miden_processor::advice::AdviceInputs;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey};
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::utils::hex_to_bytes;
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

    let script = format!(
        r#"
            use miden::standards::auth::eip712_transaction_summary

            begin
                push.9.9.9.9 adv.push_mapval dropw
                push.{tx_summary_hash}
                push.{public_key_commitment}
                exec.eip712_transaction_summary::verify
            end
        "#
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
    let domain_separator = [0x11; 32];
    let struct_hash = [0x22; 32];

    let mut rng = StdRng::from_seed([0x72; 32]);
    let signing_key = SigningKey::with_rng(&mut rng);
    let public_key = signing_key.public_key();
    let signature = signing_key.sign_prehash(eip712::digest(domain_separator, struct_hash));
    let witness = encode_signature(&public_key, &signature);

    let domain_push = push_u32_limbs(bytes_to_u32_limbs(domain_separator));
    let message_push = push_u32_limbs(bytes_to_u32_limbs(struct_hash));
    let public_key_commitment = public_key.to_commitment();
    let script = format!(
        r#"
            use miden::standards::auth::eip712

            begin
                push.9.9.9.9 adv.push_mapval dropw
                {message_push}
                {domain_push}
                push.{public_key_commitment}
                exec.eip712::verify
            end
        "#
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
    let script = format!(
        r#"
            use miden::standards::auth::eip712_transaction_summary

            begin
                push.9.9.9.9 adv.push_mapval dropw
                push.{tx_summary_hash}
                push.{public_key_commitment}
                exec.eip712_transaction_summary::verify
            end
        "#
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

fn push_u32_limbs(limbs: [u32; 8]) -> String {
    format!(
        "push.{}.{}.{}.{} push.{}.{}.{}.{}",
        limbs[7], limbs[6], limbs[5], limbs[4], limbs[3], limbs[2], limbs[1], limbs[0]
    )
}
