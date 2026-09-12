use miden_core_lib::dsa::ecdsa_k256_keccak::encode_signature;
use miden_processor::advice::AdviceInputs;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey};
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::utils::{bytes_to_packed_u32_elements, hex_to_bytes};
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
    verify_transaction_summary_signature(tx_summary_hash, &public_key, &signature).await
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

    let domain_push = push_u32_limbs(&bytes_to_packed_u32_elements(&domain_separator));
    let message_push = push_u32_limbs(&bytes_to_packed_u32_elements(&struct_hash));
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

    verify_transaction_summary_signature(tx_summary_hash, &public_key, &signature).await
}

#[tokio::test]
async fn verifies_eth_sign_typed_data_v4_signature() -> anyhow::Result<()> {
    // Generated with @metamask/eth-sig-util from the exact MidenTransaction typed-data object.
    let public_key = PublicKey::read_from_bytes(&hex_to_bytes::<33>(
        "0x034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
    )?)?;
    let signature = Signature::from_sec1_bytes_and_recovery_id(
        hex_to_bytes::<64>(
            "0xdcb39402dc03c3ff8abc5a0e3e4d69968422fd60a6e4cb4ed832326d4ecd9692\
             302ab820da2250c3cff27614bf514f7122a605abfbe492fb83b2ee9b5dcab2b0",
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

    verify_transaction_summary_signature(tx_summary_hash, &public_key, &signature).await
}

async fn verify_transaction_summary_signature(
    tx_summary_hash: Word,
    public_key: &PublicKey,
    signature: &Signature,
) -> anyhow::Result<()> {
    let witness = encode_signature(public_key, signature);
    let public_key_commitment = public_key.to_commitment();
    let script = format!(
        r#"
            use miden::standards::auth::eip712_multisig_v1_transaction_summary

            begin
                push.9.9.9.9 adv.push_mapval dropw
                push.{tx_summary_hash}
                push.{public_key_commitment}
                exec.eip712_multisig_v1_transaction_summary::verify
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

fn push_u32_limbs(limbs: &[Felt]) -> String {
    assert_eq!(limbs.len(), 8);
    format!(
        "push.{}.{}.{}.{} push.{}.{}.{}.{}",
        limbs[7].as_canonical_u64(),
        limbs[6].as_canonical_u64(),
        limbs[5].as_canonical_u64(),
        limbs[4].as_canonical_u64(),
        limbs[3].as_canonical_u64(),
        limbs[2].as_canonical_u64(),
        limbs[1].as_canonical_u64(),
        limbs[0].as_canonical_u64()
    )
}
