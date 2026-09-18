use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountComponentName,
    AccountId,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::crypto::dsa::{ecdsa_k256_keccak, falcon512_poseidon2};
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Hasher, Word};

use super::Approver;
use crate::account::account_component_code;

account_component_code!(AUTH_TX_FEE_COLLECTOR_CODE, "miden-standards-auth-tx-fee-collector.masp");

// CONSTANTS
// ================================================================================================

static PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::tx_fee_collector::pub_key")
        .expect("storage slot name should be valid")
});

static SIGNATURE_SCHEME_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::tx_fee_collector::signature_scheme")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] implementing the authentication scheme of a TX_FEE collector account: an
/// account that forwards the assets of the notes it consumes and is never changed by a
/// transaction.
///
/// It exports the procedure `auth_tx_fee_collector`, which:
/// - Creates a P2ID note for the target given by the auth args (see [`Self::auth_args`]) and moves
///   the single asset of every consumed note into it, straight from the note; the account's vault
///   is never touched. A transaction consuming no notes is rejected, except for the one creating
///   the account, which then creates no P2ID note.
/// - Asserts the account's commitment is the one it had at the start of the transaction.
/// - Never increments the nonce, except once when the account is created. That transaction is
///   checked against the vault instead of the full commitment, so the account cannot be created
///   holding assets.
/// - Verifies a signature over the transaction summary against the public key in storage, under the
///   signature scheme stored alongside it.
/// - Creates no TX_FEE note.
///
/// The account is stateless after deployment, and transactions against it can be built
/// concurrently. A batch builder collects the TX_FEE notes of many batches this way: each
/// transaction consumes one batch's fee notes and forwards their assets to the builder's own
/// account.
///
/// Replay protection comes from the input notes the signed transaction summary binds: a
/// transaction leaving the account unchanged must consume at least one input note to be valid, and
/// a note can be consumed once.
///
/// Like every auth component, it is installed alongside at least one other component, typically
/// [`BasicWallet`](crate::account::wallets::BasicWallet).
pub struct AuthTxFeeCollector {
    approver: Approver,
}

impl AuthTxFeeCollector {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::tx_fee_collector";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &AUTH_TX_FEE_COLLECTOR_CODE
    }

    /// Creates a new [`AuthTxFeeCollector`] component with the given approver.
    pub fn new(approver: Approver) -> Self {
        Self { approver }
    }

    /// Creates a new [`AuthTxFeeCollector`] component using the Falcon512Poseidon2 signature
    /// scheme.
    ///
    /// The public key commitment is derived from the provided Falcon512 public key.
    pub fn falcon512_poseidon2(pub_key: falcon512_poseidon2::PublicKey) -> Self {
        Self {
            approver: Approver::new(pub_key.into(), AuthScheme::Falcon512Poseidon2),
        }
    }

    /// Creates a new [`AuthTxFeeCollector`] component using the EcdsaK256Keccak signature scheme.
    ///
    /// The public key commitment is derived from the provided ECDSA K256 public key.
    ///
    /// # Privacy
    /// This scheme discloses the signer's public key and signature at proving time and
    /// therefore does not provide public-key privacy. See
    /// [`AuthScheme::EcdsaK256Keccak`][scheme] for details, and prefer
    /// [`falcon512_poseidon2`](Self::falcon512_poseidon2) if signer-key privacy is required.
    ///
    /// [scheme]: miden_protocol::account::auth::AuthScheme::EcdsaK256Keccak
    pub fn ecdsa_k256_keccak(pub_key: ecdsa_k256_keccak::PublicKey) -> Self {
        Self {
            approver: Approver::new(pub_key.into(), AuthScheme::EcdsaK256Keccak),
        }
    }

    /// Creates a new [`AuthTxFeeCollector`] component from a [`PublicKey`].
    ///
    /// The authentication scheme and public key commitment are derived from the provided key.
    pub fn from_public_key(pub_key: PublicKey) -> Self {
        Self {
            approver: Approver::new(pub_key.to_commitment(), pub_key.auth_scheme()),
        }
    }

    /// Returns the approver of this component.
    pub fn approver(&self) -> Approver {
        self.approver
    }

    /// Returns the auth args that make the auth procedure create its P2ID note for `target`.
    ///
    /// The word is `[target_id_suffix, target_id_prefix, tag, note_type]`, with the tag derived
    /// from `target` as by [`NoteTag::with_account_target`]. Pass it as the transaction's auth
    /// args.
    pub fn auth_args(target: AccountId, note_type: NoteType) -> Word {
        Word::new([
            target.suffix(),
            target.prefix().as_felt(),
            Felt::from(NoteTag::with_account_target(target)),
            Felt::from(note_type),
        ])
    }

    /// Derives the serial number of the P2ID note the auth procedure creates in a transaction
    /// with the given auth args and input notes commitment.
    ///
    /// The serial number is `hash(auth_args || input_notes_commitment)`, which is unique per
    /// transaction since no two valid transactions consume the same notes. Together with the
    /// target it lets the note's recipient be computed before the transaction executes.
    ///
    /// This derivation must be kept in sync with `forward_note_assets` in the component's MASM
    /// code.
    pub fn derive_serial_number(auth_args: Word, input_notes_commitment: Word) -> Word {
        Hasher::merge(&[auth_args, input_notes_commitment])
    }

    /// Returns the [`StorageSlotName`] where the public key is stored.
    pub fn public_key_slot() -> &'static StorageSlotName {
        &PUBKEY_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the signature scheme is stored.
    pub fn signature_scheme_slot() -> &'static StorageSlotName {
        &SIGNATURE_SCHEME_SLOT_NAME
    }

    /// Returns the storage slot schema for the public key slot.
    pub fn public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::public_key_slot().clone(),
            StorageSlotSchema::value("Public key commitment", SchemaType::pub_key()),
        )
    }

    /// Returns the storage slot schema for the signature scheme slot.
    pub fn signature_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::signature_scheme_slot().clone(),
            StorageSlotSchema::value("Signature scheme", SchemaType::auth_scheme()),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            Self::public_key_slot_schema(),
            Self::signature_scheme_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("TX_FEE collector authentication component")
            .with_storage_schema(storage_schema)
    }
}

impl From<AuthTxFeeCollector> for AccountComponent {
    fn from(collector: AuthTxFeeCollector) -> Self {
        let metadata = AuthTxFeeCollector::component_metadata();

        let storage_slots = vec![
            StorageSlot::with_value(
                AuthTxFeeCollector::public_key_slot().clone(),
                collector.approver.pub_key().into(),
            ),
            StorageSlot::with_value(
                AuthTxFeeCollector::signature_scheme_slot().clone(),
                Word::from([collector.approver.auth_scheme().as_u8(), 0, 0, 0]),
            ),
        ];

        AccountComponent::new(AuthTxFeeCollector::code().clone(), storage_slots, metadata).expect(
            "AuthTxFeeCollector component should satisfy the requirements of a valid account \
             component",
        )
    }
}
