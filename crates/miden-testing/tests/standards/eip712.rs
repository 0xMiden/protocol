use alloy_sol_types::{SolStruct, eip712_domain, sol};
use miden_core::deferred::PrecompileError;
use miden_core_lib::dsa::ecdsa_k256_keccak::encode_signature;
use miden_processor::ExecutionError;
use miden_processor::advice::AdviceInputs;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey};
use miden_protocol::crypto::hash::keccak::Keccak256;
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::utils::{bytes_to_packed_u32_elements, hex_to_bytes};
use miden_protocol::{Felt, Word};
use miden_testing::executor::CodeExecutor;
use miden_testing::{ExecError, assert_execution_error};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rstest::rstest;
use serde::Deserialize;

const EIP712_TRANSACTION_SUMMARY_VECTOR_JSON: &str =
    include_str!("test-vectors/eip712_transaction_summary.json");
const METAMASK_VECTOR_JSON: &str = include_str!("test-vectors/eip712_metamask_signature.json");

macro_rules! assert_ecdsa_verification_failed {
    ($result:expr) => {
        assert_execution_error!(
            $result,
            matches ExecutionError::DeferredError {
                err: PrecompileError::Precompile { name: "uint256", source },
                ..
            } if matches!(source.as_ref(), PrecompileError::AssertionFailed)
        );
    };
}

sol! {
    struct MidenTransaction {
        bytes32 txSummaryHash;
    }
}

#[derive(Deserialize)]
struct Eip712TransactionSummaryVector {
    changed_tx_summary_hash: String,
    digest: String,
    different_public_key: String,
    domain_name: String,
    domain_separator: String,
    domain_version: String,
    public_key: String,
    signature_r: String,
    signature_s: String,
    signature_v: u8,
    struct_hash: String,
    tx_summary_hash: String,
}

#[derive(Deserialize)]
struct WalletSignatureVector {
    source: String,
    method: String,
    domain_name: String,
    domain_version: String,
    public_key: String,
    signature_r: String,
    signature_s: String,
    signature_v: u8,
    tx_summary_hash: String,
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
    let signature = signing_key.sign_prehash(alloy_transaction_summary_hash(tx_summary_hash));
    verify_transaction_summary_signature(tx_summary_hash, &public_key, &signature).await?;
    Ok(())
}

#[rstest]
#[case::different_name("Another App", "1")]
#[case::different_version("Miden Transaction", "2")]
#[tokio::test]
async fn rejects_signature_for_different_domain(
    #[case] name: &'static str,
    #[case] version: &'static str,
) -> anyhow::Result<()> {
    let tx_summary_hash = Word::new([Felt::new(0x0123_4567_89ab_cdef)?; 4]);
    let mut rng = StdRng::from_seed([0x73; 32]);
    let signing_key = SigningKey::with_rng(&mut rng);
    let public_key = signing_key.public_key();

    let digest = alloy_transaction_summary_hash_with_domain(tx_summary_hash, name, version);
    let signature = signing_key.sign_prehash(digest);

    let result =
        verify_transaction_summary_signature(tx_summary_hash, &public_key, &signature).await;
    assert_ecdsa_verification_failed!(result);

    Ok(())
}

#[tokio::test]
async fn verifies_generic_eip712_signature() -> anyhow::Result<()> {
    let domain_separator = [0x11; 32];
    let struct_hash = [0x22; 32];

    let mut rng = StdRng::from_seed([0x72; 32]);
    let signing_key = SigningKey::with_rng(&mut rng);
    let public_key = signing_key.public_key();
    let signature = signing_key.sign_prehash(eip712_digest(domain_separator, struct_hash));
    verify_eip712_signature(domain_separator, struct_hash, &public_key, &signature).await?;
    Ok(())
}

#[tokio::test]
async fn verifies_eth_sign_typed_data_v4_signature() -> anyhow::Result<()> {
    let vector: WalletSignatureVector = serde_json::from_str(METAMASK_VECTOR_JSON)?;
    let tx_summary_hash = word_from_hex(&vector.tx_summary_hash)?;

    assert_eq!(vector.source, "@metamask/eth-sig-util");
    assert_eq!(vector.method, "signTypedData V4");
    assert_eq!(vector.domain_name, "Miden Transaction");
    assert_eq!(vector.domain_version, "1");
    let public_key = PublicKey::read_from_bytes(&hex_to_bytes::<33>(&vector.public_key)?)?;
    let signature =
        signature_from_parts(&vector.signature_r, &vector.signature_s, vector.signature_v)?;
    let digest = alloy_transaction_summary_hash(tx_summary_hash);

    assert!(public_key.verify_prehash(digest, &signature));

    verify_transaction_summary_signature(tx_summary_hash, &public_key, &signature).await?;
    Ok(())
}

#[tokio::test]
async fn verifies_foundry_openzeppelin_signature() -> anyhow::Result<()> {
    let vector: Eip712TransactionSummaryVector =
        serde_json::from_str(EIP712_TRANSACTION_SUMMARY_VECTOR_JSON)?;
    let tx_summary_hash = word_from_hex(&vector.tx_summary_hash)?;

    assert_eq!(vector.domain_name, "Miden Transaction");
    assert_eq!(vector.domain_version, "1");
    let domain = eip712_domain! {
        name: vector.domain_name.clone(),
        version: vector.domain_version.clone(),
    };
    let transaction = MidenTransaction {
        txSummaryHash: tx_summary_hash.as_bytes().into(),
    };
    let domain_separator: [u8; 32] = domain.separator().into();
    let struct_hash: [u8; 32] = transaction.eip712_hash_struct().into();
    let digest: [u8; 32] = transaction.eip712_signing_hash(&domain).into();

    assert_eq!(domain_separator, hex_to_bytes::<32>(&vector.domain_separator)?);
    assert_eq!(struct_hash, hex_to_bytes::<32>(&vector.struct_hash)?);
    assert_eq!(digest, hex_to_bytes::<32>(&vector.digest)?);

    let public_key = PublicKey::read_from_bytes(&hex_to_bytes::<33>(&vector.public_key)?)?;
    let signature =
        signature_from_parts(&vector.signature_r, &vector.signature_s, vector.signature_v)?;

    assert!(public_key.verify_prehash(digest, &signature));
    verify_transaction_summary_signature(tx_summary_hash, &public_key, &signature).await?;
    Ok(())
}

#[rstest]
#[case::different_name("Another App", "1")]
#[case::different_version("Miden Transaction", "2")]
#[tokio::test]
async fn rejects_foundry_openzeppelin_signature_for_different_domain(
    #[case] name: &'static str,
    #[case] version: &'static str,
) -> anyhow::Result<()> {
    let vector: Eip712TransactionSummaryVector =
        serde_json::from_str(EIP712_TRANSACTION_SUMMARY_VECTOR_JSON)?;
    let public_key = PublicKey::read_from_bytes(&hex_to_bytes::<33>(&vector.public_key)?)?;
    let signature =
        signature_from_parts(&vector.signature_r, &vector.signature_s, vector.signature_v)?;
    let struct_hash = hex_to_bytes::<32>(&vector.struct_hash)?;

    let domain = eip712_domain! {
        name: name,
        version: version,
    };
    let domain_separator: [u8; 32] = domain.separator().into();

    let result =
        verify_eip712_signature(domain_separator, struct_hash, &public_key, &signature).await;
    assert_ecdsa_verification_failed!(result);

    Ok(())
}

#[tokio::test]
async fn rejects_mutated_foundry_openzeppelin_inputs() -> anyhow::Result<()> {
    let vector: Eip712TransactionSummaryVector =
        serde_json::from_str(EIP712_TRANSACTION_SUMMARY_VECTOR_JSON)?;
    let tx_summary_hash = word_from_hex(&vector.tx_summary_hash)?;
    let public_key = PublicKey::read_from_bytes(&hex_to_bytes::<33>(&vector.public_key)?)?;
    let signature =
        signature_from_parts(&vector.signature_r, &vector.signature_s, vector.signature_v)?;

    let changed_tx_summary_hash = Word::from([1u32, 0, 0, 0]);
    assert_eq!(
        changed_tx_summary_hash.as_bytes(),
        hex_to_bytes::<32>(&vector.changed_tx_summary_hash)?
    );
    let result =
        verify_transaction_summary_signature(changed_tx_summary_hash, &public_key, &signature)
            .await;
    assert_ecdsa_verification_failed!(result);

    let different_public_key =
        PublicKey::read_from_bytes(&hex_to_bytes::<33>(&vector.different_public_key)?)?;
    let result =
        verify_transaction_summary_signature(tx_summary_hash, &different_public_key, &signature)
            .await;
    assert_ecdsa_verification_failed!(result);

    let mut changed_signature_bytes =
        signature_bytes_from_parts(&vector.signature_r, &vector.signature_s)?;
    changed_signature_bytes[31] ^= 1;
    let changed_signature = Signature::from_sec1_bytes_and_recovery_id(
        changed_signature_bytes,
        solidity_recovery_id(vector.signature_v)?,
    )?;
    let result =
        verify_transaction_summary_signature(tx_summary_hash, &public_key, &changed_signature)
            .await;
    assert_ecdsa_verification_failed!(result);

    Ok(())
}

async fn verify_eip712_signature(
    domain_separator: [u8; 32],
    struct_hash: [u8; 32],
    public_key: &PublicKey,
    signature: &Signature,
) -> Result<(), ExecError> {
    let witness = encode_signature(public_key, signature);
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
                exec.eip712::verify_raw
            end
        "#
    );
    let advice = AdviceInputs::default().with_map([(Word::from([9u32; 4]), witness)]);

    CodeExecutor::with_default_host()
        .extend_advice_inputs(advice)
        .run(&script)
        .await
        .map(|_| ())
}

async fn verify_transaction_summary_signature(
    tx_summary_hash: Word,
    public_key: &PublicKey,
    signature: &Signature,
) -> Result<(), ExecError> {
    let witness = encode_signature(public_key, signature);
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
        .await
        .map(|_| ())
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

fn alloy_transaction_summary_hash(tx_summary_hash: Word) -> [u8; 32] {
    alloy_transaction_summary_hash_with_domain(tx_summary_hash, "Miden Transaction", "1")
}

fn alloy_transaction_summary_hash_with_domain(
    tx_summary_hash: Word,
    name: &'static str,
    version: &'static str,
) -> [u8; 32] {
    let domain = eip712_domain! {
        name: name,
        version: version,
    };
    let transaction = MidenTransaction {
        txSummaryHash: tx_summary_hash.as_bytes().into(),
    };
    transaction.eip712_signing_hash(&domain).into()
}

fn eip712_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 66];
    preimage[..2].copy_from_slice(&[0x19, 0x01]);
    preimage[2..34].copy_from_slice(&domain_separator);
    preimage[34..].copy_from_slice(&struct_hash);
    Keccak256::hash(&preimage).into()
}

fn signature_from_parts(r: &str, s: &str, v: u8) -> anyhow::Result<Signature> {
    Signature::from_sec1_bytes_and_recovery_id(
        signature_bytes_from_parts(r, s)?,
        solidity_recovery_id(v)?,
    )
    .map_err(Into::into)
}

fn word_from_hex(value: &str) -> anyhow::Result<Word> {
    Word::read_from_bytes(&hex_to_bytes::<32>(value)?).map_err(Into::into)
}

fn signature_bytes_from_parts(r: &str, s: &str) -> anyhow::Result<[u8; 64]> {
    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(&hex_to_bytes::<32>(r)?);
    signature_bytes[32..].copy_from_slice(&hex_to_bytes::<32>(s)?);
    Ok(signature_bytes)
}

fn solidity_recovery_id(v: u8) -> anyhow::Result<u8> {
    v.checked_sub(27).filter(|recovery_id| *recovery_id <= 1).ok_or_else(|| {
        anyhow::anyhow!("Solidity signature recovery ID must be encoded as 27 or 28")
    })
}
