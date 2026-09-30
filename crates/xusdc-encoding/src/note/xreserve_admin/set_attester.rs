use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::Package;
use miden_protocol::{Felt, Word};

use super::build_admin_note;

static SET_ATTESTER_NOTE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let package = Package::read_from_bytes_trusted(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/notes/xreserve-set-attester-note.masp"
    )))
    .expect("the shipped note package deserializes");
    NoteScript::from_package(&package).expect("the note package exports exactly one note script")
});

/// The dedicated `set_attester` note-storage type: the `NoteStorage.items` payload
/// `[pk_commitment(4), enabled]`. Built with a `bon` builder
/// (`XReserveSetAttesterNoteStorage::builder().commitment(..).enabled(..).build()`), mirroring the
/// standards `PswapNoteStorage` pattern, and converted to its felt items by [`Self::into_items`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, bon::Builder)]
pub struct XReserveSetAttesterNoteStorage {
    commitment: Word,
    enabled: u8,
}

impl XReserveSetAttesterNoteStorage {
    /// The `NoteStorage.items` felt count: `[commitment(4), enabled]`.
    pub const NUM_ITEMS: usize = 5;

    /// The attester pubkey commitment (the xReserveAttesters map key).
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// `1` = allowlist the attester, `0` = remove it.
    pub fn enabled(&self) -> u8 {
        self.enabled
    }

    /// The `NoteStorage.items` felt layout `[commitment(4), enabled]`.
    pub fn into_items(self) -> Vec<Felt> {
        vec![
            self.commitment[0],
            self.commitment[1],
            self.commitment[2],
            self.commitment[3],
            Felt::from(u32::from(self.enabled)),
        ]
    }
}

/// The `ATTEST_ADMIN`-gated `set_attester` admin note. Storage layout: `[pk_commitment(4),
/// enabled]`. Consumed against the faucet network account; `attester_admin::set_attester` gates on
/// the (kernel-forced) note sender through the account-wide authority, resolving to the
/// `ATTEST_ADMIN` role.
pub struct XReserveSetAttesterNote;

#[bon::bon]
impl XReserveSetAttesterNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_set_attester_note.masm` with the
    /// xreserve library linked).
    pub fn script() -> NoteScript {
        SET_ATTESTER_NOTE_SCRIPT.clone()
    }

    /// The compiled note-script root. It binds transitively to `attester_admin::set_attester`'s
    /// digest; the allowlist row for this note derives from the same compiled script.
    pub fn script_root() -> NoteScriptRoot {
        SET_ATTESTER_NOTE_SCRIPT.root()
    }

    /// Builds a `set_attester` admin note via a `bon` builder
    /// (`XReserveSetAttesterNote::builder().sender(..).faucet_id(..).storage(..).rng(..).build()`):
    /// `sender` is the admin party (an `ATTEST_ADMIN` role holder, for success), `faucet_id` the target
    /// faucet (PUBLIC), `storage` the typed [`XReserveSetAttesterNoteStorage`] payload.
    #[builder]
    pub fn new<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        storage: XReserveSetAttesterNoteStorage,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(sender, faucet_id, Self::script(), storage.into_items(), rng)
    }

    /// Convenience constructor over the raw `commitment` / `enabled` params. Retained (a thin
    /// delegator to the [`builder`](Self::builder)) because the frozen conformance suites pin this
    /// signature; new callers should prefer the typed builder.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        commitment: Word,
        enabled: u8,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Self::builder()
            .sender(sender)
            .faucet_id(faucet_id)
            .storage(
                XReserveSetAttesterNoteStorage::builder()
                    .commitment(commitment)
                    .enabled(enabled)
                    .build(),
            )
            .rng(rng)
            .build()
    }
}
