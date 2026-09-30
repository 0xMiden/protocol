//! `XUsdcMintNote`: builds the note that carries a Circle-attested deposit to the faucet.
//!
//! The note is a standard [`MintNote`] driving the standard `mint_and_send`, everything specific
//! to xUSDC is in attachments. The authorization decision lives entirely in the faucet's mint
//! policy.
//!
//! - The mint-note storage holds the output note's pay-to-id recipe: target = the intent's
//!   `remoteRecipient`, serial = the key derived from the deposit nonce, asset = the reduced
//!   attested amount, tag = the attested recipient.
//! - Two attachments travel with it. Scheme 4 is the whole transport in one attachment: the
//!   attestation as nine words — attester public key (16 felts), signature (17), 3 padding felts,
//!   in the order the policy reads them — and then the carried mint payload, zero-padded to a word
//!   boundary. The policy re-derives the true felt length from the payload's own `hookDataLen`, so
//!   the padding cannot hide extra data. Scheme 2 routes the note to the faucet's network account.
//!
//!   The attestation comes FIRST because it is fixed-width: that keeps the payload's starting
//!   offset a constant instead of a function of `hookDataLen`, which is what lets the policy read
//!   every sub-region at a constant offset. The Circle-signed DepositIntent itself does not
//!   travel — the faucet rebuilds it from the carried payload plus its own state.

use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::crypto::SequentialCommit;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAttachment, NoteAttachmentScheme, NoteScript, NoteScriptRoot, NoteTag,
};
use miden_protocol::{Felt, Word, WORD_SIZE};
use miden_standards::note::{
    MintNote, MintNoteStorage, NetworkAccountTarget, NoteExecutionHint, P2idNoteStorage,
};

use crate::xreserve::encoding::{
    CircleDomain, DepositIntent, DepositIntentHeader, DepositNonce, MintIntent, Signature,
    BYTES_PER_PACKED_FELT,
};

/// The mint-note transport attachment scheme (u16, project-chosen: >= 4, clear of
/// the reserved "none" value 1 and the standard values 2 `NetworkAccountTarget` / 3 `Pswap`).
/// This attachment carries both the attestation and the DepositIntent preimage.
pub const XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME: u16 = 4;

/// The attestation section word count: `[pubkey(16), signature(17), pad(3)]` = 36 felts (the
/// pubkey is the 16-felt affine form). The operator `feeAmount` is not carried at all — the faucet
/// writes a zero fee into the preimage it rebuilds, so a non-zero one is inexpressible.
pub const XUSDC_MINT_ATTESTATION_NUM_WORDS: usize = 9;

/// Word offset of the carried mint payload inside the transport attachment: past the fixed-width
/// attestation. Constant by construction — see the module docs on why the attestation goes first.
pub const XUSDC_MINT_TRANSPORT_PAYLOAD_WORD_OFF: usize = XUSDC_MINT_ATTESTATION_NUM_WORDS;

/// How much hookData this transport can carry: the protocol's per-attachment ceiling less the fixed
/// prefix (the attestation section and the carried payload), in bytes. Everything past that prefix
/// is packed hookData. Deposits with more data than this cannot be processed.
///
/// This is what bounds hookData — see [`HookData::MAX_LEN`], which is defined as this value.
///
/// [`HookData::MAX_LEN`]: crate::xreserve::encoding::HookData::MAX_LEN
pub const XUSDC_MINT_TRANSPORT_HOOK_DATA_MAX_LEN: usize = (NoteAttachment::MAX_NUM_WORDS as usize
    * WORD_SIZE
    - XUSDC_MINT_ATTESTATION_NUM_WORDS * WORD_SIZE
    - MintIntent::NUM_FELTS)
    * BYTES_PER_PACKED_FELT;

/// The Circle deposit attestation crossing the note boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositAttestation {
    signature: Signature,
    pubkey: PublicKey,
}

impl DepositAttestation {
    /// Bundles the signature with the candidate attester key.
    pub fn new(signature: Signature, pubkey: PublicKey) -> Self {
        Self { signature, pubkey }
    }

    /// The signature.
    pub fn signature(&self) -> Signature {
        self.signature
    }

    /// The candidate attester key.
    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }
}

/// The note storage of the [`XUsdcMintNote`] derived from a [`DepositIntent`].
pub struct XUsdcMintNoteStorage {
    storage: MintNoteStorage,
}

impl XUsdcMintNoteStorage {
    /// Derives the mint-note storage from the decoded `intent` and the target faucet.
    pub fn new(intent_header: &DepositIntentHeader, target: AccountId) -> Self {
        let recipient_id = intent_header.remote_recipient();
        let asset = FungibleAsset::new(target, intent_header.amount().as_u64())
            .expect("asset amount should be valid");
        let serial_num = intent_header.nonce().to_word();
        let recipient = P2idNoteStorage::new(recipient_id).into_recipient(serial_num);
        let tag = NoteTag::with_account_target(recipient_id);
        let storage = MintNoteStorage::new_public(recipient, asset, tag)
            .expect("p2id note storage should not exceed max number of storage items");

        Self { storage }
    }

    /// A read-only view of the derived stock mint storage.
    pub fn as_mint_storage(&self) -> &MintNoteStorage {
        &self.storage
    }

    /// Consumes into the stock [`MintNoteStorage`] the [`MintNote`] builder installs.
    pub fn into_mint_storage(self) -> MintNoteStorage {
        self.storage
    }
}

/// The Circle deposit a mint note carries: the decoded [`MintIntent`] together with the
/// [`DepositAttestation`] that authorizes it.
///
/// This is the scheme-4 transport attachment in domain form. It converts into the
/// [`NoteAttachment`] the faucet hash-verifies, the way the standards [`NetworkAccountTarget`]
/// converts into the scheme-2 routing one.
pub struct XUsdcDeposit {
    intent: MintIntent,
    attestation: DepositAttestation,
}

impl XUsdcDeposit {
    /// Bundles a decoded intent with the attestation over the payload it was decoded from.
    pub fn new(intent: MintIntent, attestation: DepositAttestation) -> Self {
        Self {
            intent,
            attestation,
        }
    }

    /// The carried mint payload.
    pub fn intent(&self) -> &MintIntent {
        &self.intent
    }

    /// The attestation travelling beside it.
    pub fn attestation(&self) -> &DepositAttestation {
        &self.attestation
    }
}

impl From<&XUsdcDeposit> for NoteAttachment {
    /// Builds the transport attachment — everything the faucet needs to rebuild and verify the
    /// Circle-signed message, in three sections:
    ///
    /// 1. the [`DepositAttestation`].
    /// 2. the [`MintIntent`].
    /// 3. the [`HookData`](crate::xreserve::encoding::HookData).
    fn from(deposit: &XUsdcDeposit) -> Self {
        let mut elements: Vec<Felt> = Vec::new();

        elements.extend(deposit.attestation.pubkey().to_elements());
        elements.extend(deposit.attestation.signature().to_elements());
        elements.extend([Felt::ZERO; 3]);
        debug_assert_eq!(elements.len(), XUSDC_MINT_TRANSPORT_PAYLOAD_WORD_OFF * 4);

        elements.extend(deposit.intent.to_elements());
        while !elements.len().is_multiple_of(Word::NUM_ELEMENTS) {
            elements.push(Felt::ZERO);
        }

        let words: Vec<Word> = elements
            .as_chunks::<{ Word::NUM_ELEMENTS }>()
            .0
            .iter()
            .map(|chunk| Word::new(*chunk))
            .collect();
        NoteAttachment::with_words(
            NoteAttachmentScheme::new(XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME)
                .expect("the transport scheme is neither reserved nor past the protocol maximum"),
            words,
        )
        // the compile-time assertion above ties MAX_HOOK_DATA_LEN to this transport's capacity, and
        // the carried hookData is bounded by it, so the assembled words always fit
        .expect("the hookData bound keeps the transport within the per-attachment word cap")
    }
}

/// The mint note carrying the xUSDC attested transport: a [`MintNote`] whose two attachments are
/// the [`XUsdcDeposit`] and the [`NetworkAccountTarget`].
pub struct XUsdcMintNote {
    sender: AccountId,
    storage: XUsdcMintNoteStorage,
    serial_number: Word,
    deposit: XUsdcDeposit,
    network_account_target: NetworkAccountTarget,
}

impl XUsdcMintNote {
    /// The [`MintNote`] script the transport rides on.
    pub fn script() -> NoteScript {
        MintNote::script()
    }

    /// The [`MintNote`] script root.
    pub fn script_root() -> NoteScriptRoot {
        MintNote::script_root()
    }

    /// The Circle deposit the note carries.
    pub fn deposit(&self) -> &XUsdcDeposit {
        &self.deposit
    }

    /// The nonce of the carried deposit — the key of the faucet's replay guard.
    pub fn nonce(&self) -> DepositNonce {
        self.deposit.intent().nonce()
    }
}

#[bon::bon]
impl XUsdcMintNote {
    /// Builds the mint note.
    ///
    /// The `sender` is the relayer account and `target` the consuming faucet. The `remote_domain`
    /// must match the configured remote domain in the target faucet.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the intent is addressed to another target faucet or another domain
    /// - if `target` is not a public account.
    #[builder]
    pub fn new(
        sender: AccountId,
        target: AccountId,
        remote_domain: CircleDomain,
        deposit_intent: DepositIntent,
        attestation: DepositAttestation,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        let mint_intent = MintIntent::from_deposit_intent(&deposit_intent, target, remote_domain)
            .map_err(|source| {
            NoteError::other_with_source(
                "deposit intent cannot be carried by the mint transport",
                source,
            )
        })?;

        let network_account_target = NetworkAccountTarget::new(target, NoteExecutionHint::Always)
            .map_err(|err| {
            NoteError::other_with_source("faucet id is not a public network account", err)
        })?;

        let storage = XUsdcMintNoteStorage::new(deposit_intent.header(), target);

        Ok(Self {
            sender,
            storage,
            serial_number,
            deposit: XUsdcDeposit::new(mint_intent, attestation),
            network_account_target,
        })
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: x_usdc_mint_note_builder::State> XUsdcMintNoteBuilder<S>
where
    S::SerialNumber: x_usdc_mint_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> XUsdcMintNoteBuilder<x_usdc_mint_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<XUsdcMintNote> for Note {
    /// Creates the stock [`MintNote`] and converts it into a protocol [`Note`].
    fn from(note: XUsdcMintNote) -> Self {
        MintNote::builder()
            .sender(note.sender)
            .mint_storage(note.storage.into_mint_storage())
            .serial_number(note.serial_number)
            .attachment(&note.deposit)
            .attachment(note.network_account_target)
            .build()
            .expect("two attachments are within the protocol's per-note limit")
            .into()
    }
}
