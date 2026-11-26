//! Transfer policy components and the send and receive policy descriptors used by
//! [`super::TokenPolicyManager`].
//!
//! Layout convention inside this module:
//! - File at the root (e.g. `allow_all`, `basic_blocklist`, `basic_allowlist`) = a transfer policy
//!   variant. Each exports a `check_send_policy` and/or a `check_receive_policy` procedure that the
//!   manager's `invoke_send_policy` / `invoke_receive_policy` wrapper dispatches to via `dyncall`
//!   (after the pause check) once the active policy is set. `encrypted_assets` exports only a
//!   `check_send_policy` procedure.
//! - Folder at the root (e.g. `blocklist`, `allowlist`) = a primitive bundle: storage namespace +
//!   helpers + auth-gated admin component(s) that maintain the storage. Primitives are not transfer
//!   policies by themselves; they are consumed by policy variants.

use alloc::vec::Vec;

use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot};
use thiserror::Error;

use crate::note::EncryptedAssetsIssuerKey;

mod allow_all;
mod allowlist;
mod basic_allowlist;
mod basic_blocklist;
mod blocklist;
mod encrypted_assets;
mod supply_restriction;
mod supply_restriction_policy;

pub use allow_all::TransferAllowAll;
pub use allowlist::{AllowlistManager, AllowlistStorage};
pub use basic_allowlist::BasicAllowlist;
pub use basic_blocklist::BasicBlocklist;
pub use blocklist::{BlocklistManager, BlocklistStorage};
pub use encrypted_assets::EncryptedAssetsSendPolicy;
pub use supply_restriction::{
    SupplyRestrictionError,
    SupplyRestrictionManager,
    SupplyRestrictionStorage,
};
pub use supply_restriction_policy::SupplyRestrictionPolicy;

// TRANSFER POLICY ERROR
// ================================================================================================

/// Errors returned by the constructors of [`SendPolicy`] and [`ReceivePolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransferPolicyError {
    /// The procedure root supplied to [`SendPolicy::custom`] or [`ReceivePolicy::custom`] is not
    /// exported by any of the provided components.
    #[error(
        "custom transfer policy root must match a procedure root in one of the provided components"
    )]
    RootNotInComponents,
}

// SEND POLICY
// ================================================================================================

/// Descriptor for the send policy registered with a [`super::TokenPolicyManager`].
///
/// A send policy binds together the procedure root that the manager's `invoke_send_policy` wrapper
/// dispatches to (via `dyncall`, after the account-wide pause check) with any companion
/// [`AccountComponent`]s that must be installed on the account for that procedure root to work.
///
/// ## Interface
///
/// The wrapper is the faucet's `on_before_note_sealed` callback, which the kernel invokes once
/// when an output note holding the faucet's assets is sealed. The policy procedure has the
/// interface of that callback, and the wrapper returns the policy's outputs to the kernel:
///
/// ```text
/// Inputs:  [note_idx, pad(15)]
/// Outputs: [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]
/// ```
///
/// It reads the note itself and the note creator via `native_account::get_id`.
/// `output_note::get_assets` returns all of the note's assets, so a policy that inspects the
/// faucet's assets selects them by comparing `asset::id_to_faucet_id` with
/// `active_account::get_id`.
///
/// A policy that returns attachments for the note puts their attachment list into the advice map
/// under `ATTACHMENT_LIST_COMMITMENT` and the elements of each attachment under its commitment, and
/// the kernel appends them to the note. A `num_attachments` of `0` returns no attachment and
/// requires `ATTACHMENT_LIST_COMMITMENT` to be the empty word. Of the bundled policies, only
/// [`Self::with_encrypted_assets`] returns an attachment.
///
/// ## Minting
///
/// Note that minting crosses the send callback: the note created by `mint_and_send` runs
/// `on_before_note_sealed` when it is sealed, with the issuing faucet itself as the native account,
/// indistinguishable at that point from an ordinary send. The bundled blocklist, allowlist and
/// supply restriction policies therefore exempt the issuer by comparing the active account ID (the
/// issuing faucet) against the native account ID.
///
/// ## Expiration
///
/// Send policies run through FPI. Policies that read mutable, security-sensitive state must set
/// an expiration delta in the execution path that reads that state. The built-in blocklist,
/// allowlist and supply restriction policies, and the encrypted assets policy for private notes,
/// apply the standards default; custom policies should call
/// `miden::standards::expiration::apply_default` or `tx::update_expiration_block_delta` directly
/// with a custom expiration delta.
///
/// ## Companion components
///
/// The companion components carried by the descriptor are inlined into the account by the
/// [`super::TokenPolicyManager`] when it is converted into account components.
///
/// The basic blocklist and allowlist send and receive policies share their list component, so the
/// two kinds always check the same list. Seed both with the same initial list: the
/// [`super::TokenPolicyManager`] then installs the component once, while different initial lists
/// fail the account build.
#[derive(Debug, Clone)]
pub struct SendPolicy {
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
}

impl SendPolicy {
    /// Returns a send policy that accepts every output note unconditionally.
    ///
    /// Resolves to [`TransferAllowAll::send_root`] and ships the companion [`TransferAllowAll`]
    /// component.
    pub fn allow_all() -> Self {
        Self {
            root: TransferAllowAll::send_root(),
            components: vec![TransferAllowAll.into()],
        }
    }

    /// Returns a send policy that rejects output notes whose creator (the native account) is in
    /// the `blocked_accounts` map, starting with an empty blocklist. To seed initial entries use
    /// [`Self::with_basic_blocklist`].
    pub fn empty_basic_blocklist() -> Self {
        Self {
            root: BasicBlocklist::send_root(),
            components: vec![BasicBlocklist::default().into()],
        }
    }

    /// Returns a basic-blocklist send policy seeded with the given initial blocked accounts.
    pub fn with_basic_blocklist<I>(blocked_accounts: I) -> Self
    where
        I: IntoIterator<Item = AccountId>,
    {
        Self {
            root: BasicBlocklist::send_root(),
            components: vec![BasicBlocklist::with_blocked_accounts(blocked_accounts).into()],
        }
    }

    /// Returns a send policy that rejects output notes whose creator (the native account) is not
    /// in the `allowed_accounts` map, starting with an empty allowlist (every send rejected). To
    /// seed initial entries use [`Self::with_basic_allowlist`].
    pub fn empty_basic_allowlist() -> Self {
        Self {
            root: BasicAllowlist::send_root(),
            components: vec![BasicAllowlist::default().into()],
        }
    }

    /// Returns a basic-allowlist send policy. The provided [`AllowlistStorage`] seeds the initial
    /// allowlist entries at component-construction time.
    pub fn with_basic_allowlist(allow_list: AllowlistStorage) -> Self {
        Self {
            root: BasicAllowlist::send_root(),
            components: vec![BasicAllowlist::from(allow_list).into()],
        }
    }

    /// Returns a send policy that rejects output notes which would spend frozen or confiscated
    /// amounts of their creator (the native account), starting without restricted accounts. To seed
    /// initial entries use [`Self::with_supply_restriction`].
    pub fn empty_supply_restriction() -> Self {
        Self::with_supply_restriction(SupplyRestrictionStorage::new())
    }

    /// Returns a supply restriction send policy. The provided [`SupplyRestrictionStorage`] seeds
    /// the initial restricted amounts at component-construction time.
    pub fn with_supply_restriction(storage: SupplyRestrictionStorage) -> Self {
        Self {
            root: SupplyRestrictionPolicy::send_root(),
            components: vec![SupplyRestrictionPolicy::new(storage).into()],
        }
    }

    /// Returns a send policy that attaches the
    /// [`EncryptedAssetsAttachment`](crate::note::EncryptedAssetsAttachment), encrypted to
    /// `issuer_key`, to every private output note holding the faucet's assets, so the issuer can
    /// track them. Public notes get no attachment. A private note may hold only one asset, since
    /// the attachment would show the assets of other faucets to the issuer.
    ///
    /// Resolves to [`EncryptedAssetsSendPolicy::send_root`] and ships the companion
    /// [`EncryptedAssetsSendPolicy`] component and `issuer_key` as the component that installs
    /// the key and lets the faucet's authority rotate it (see [`EncryptedAssetsIssuerKey`]). The
    /// manager installs the components of a policy root once, so registering this policy again
    /// with another key keeps the first key.
    ///
    /// A private note seals only if the transaction's advice map holds its recipient preimage, so
    /// a note whose creator knows only its recipient digest cannot hold the faucet's assets. A
    /// MINT note with a private output note holds only that digest: the faucet mints it only if
    /// the transaction supplies the preimage, so a network faucet cannot. The same holds for the
    /// private payback note of a SWAP note that requests the faucet's asset. The transaction
    /// arguments must also carry an [`IesSealSeed`](miden_protocol::transaction::IesSealSeed).
    ///
    /// A custom policy that composes other checks with this one `exec`s them and then
    /// `encrypted_assets::check_send_policy`, so that its attachment list is the output.
    pub fn with_encrypted_assets(issuer_key: EncryptedAssetsIssuerKey) -> Self {
        Self {
            root: EncryptedAssetsSendPolicy::send_root(),
            components: vec![EncryptedAssetsSendPolicy.into(), issuer_key.into()],
        }
    }

    /// Returns a send policy resolving to `root` and shipping the provided companion
    /// `components` (anything that can be converted into an [`AccountComponent`]).
    ///
    /// The procedure at `root` is invoked with the send policy inputs `[note_idx, pad(15)]` and
    /// returns the send policy outputs `[num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]`
    /// (see [`SendPolicy`]).
    ///
    /// # Errors
    ///
    /// Returns [`TransferPolicyError::RootNotInComponents`] if `root` is not the procedure
    /// root of any procedure exported by the provided components.
    pub fn custom<I>(root: AccountProcedureRoot, components: I) -> Result<Self, TransferPolicyError>
    where
        I: IntoIterator,
        I::Item: Into<AccountComponent>,
    {
        let components = custom_policy_components(root, components)?;
        Ok(Self { root, components })
    }

    /// Returns the procedure root of the policy this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }
}

impl Default for SendPolicy {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl IntoIterator for SendPolicy {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s carried by this send policy descriptor in installation
    /// order.
    fn into_iter(self) -> Self::IntoIter {
        self.components.into_iter()
    }
}

// RECEIVE POLICY
// ================================================================================================

/// Descriptor for the receive policy registered with a [`super::TokenPolicyManager`].
///
/// A receive policy binds together the procedure root that the manager's `invoke_receive_policy`
/// wrapper dispatches to (via `dyncall`, after the account-wide pause check) with any companion
/// [`AccountComponent`]s that must be installed on the account for that procedure root to work.
///
/// ## Interface
///
/// The wrapper is the faucet's `on_before_asset_added_to_account` callback, which the kernel
/// invokes when one of the faucet's assets is added to an account vault. The policy procedure has
/// the interface of that callback:
///
/// ```text
/// Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
/// Outputs: [pad(16)]
/// ```
///
/// It reads the receiving account via `native_account::get_id`.
///
/// ## Expiration
///
/// Receive policies run through FPI. Policies that read mutable, security-sensitive state must
/// set an expiration delta in the execution path that reads that state. The built-in blocklist
/// and allowlist policies apply the standards default; custom policies should call
/// `miden::standards::expiration::apply_default` or `tx::update_expiration_block_delta` directly
/// with a custom expiration delta.
///
/// ## Companion components
///
/// The companion components carried by the descriptor are inlined into the account by the
/// [`super::TokenPolicyManager`] when it is converted into account components.
///
/// The basic blocklist and allowlist send and receive policies share their list component, so the
/// two kinds always check the same list. Seed both with the same initial list: the
/// [`super::TokenPolicyManager`] then installs the component once, while different initial lists
/// fail the account build.
#[derive(Debug, Clone)]
pub struct ReceivePolicy {
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
}

impl ReceivePolicy {
    /// Returns a receive policy that accepts every asset unconditionally.
    ///
    /// Resolves to [`TransferAllowAll::receive_root`] and ships the companion
    /// [`TransferAllowAll`] component.
    pub fn allow_all() -> Self {
        Self {
            root: TransferAllowAll::receive_root(),
            components: vec![TransferAllowAll.into()],
        }
    }

    /// Returns a receive policy that rejects assets added to an account (the native account) in
    /// the `blocked_accounts` map, starting with an empty blocklist. To seed initial entries use
    /// [`Self::with_basic_blocklist`].
    pub fn empty_basic_blocklist() -> Self {
        Self {
            root: BasicBlocklist::receive_root(),
            components: vec![BasicBlocklist::default().into()],
        }
    }

    /// Returns a basic-blocklist receive policy seeded with the given initial blocked accounts.
    pub fn with_basic_blocklist<I>(blocked_accounts: I) -> Self
    where
        I: IntoIterator<Item = AccountId>,
    {
        Self {
            root: BasicBlocklist::receive_root(),
            components: vec![BasicBlocklist::with_blocked_accounts(blocked_accounts).into()],
        }
    }

    /// Returns a receive policy that rejects assets added to an account (the native account) not
    /// in the `allowed_accounts` map, starting with an empty allowlist (every receive rejected).
    /// To seed initial entries use [`Self::with_basic_allowlist`].
    pub fn empty_basic_allowlist() -> Self {
        Self {
            root: BasicAllowlist::receive_root(),
            components: vec![BasicAllowlist::default().into()],
        }
    }

    /// Returns a basic-allowlist receive policy. The provided [`AllowlistStorage`] seeds the
    /// initial allowlist entries at component-construction time.
    pub fn with_basic_allowlist(allow_list: AllowlistStorage) -> Self {
        Self {
            root: BasicAllowlist::receive_root(),
            components: vec![BasicAllowlist::from(allow_list).into()],
        }
    }

    /// Returns a receive policy resolving to `root` and shipping the provided companion
    /// `components` (anything that can be converted into an [`AccountComponent`]).
    ///
    /// The procedure at `root` is invoked with the receive policy inputs `[ASSET_ID, ASSET_VALUE,
    /// pad(8)]`.
    ///
    /// # Errors
    ///
    /// Returns [`TransferPolicyError::RootNotInComponents`] if `root` is not the procedure
    /// root of any procedure exported by the provided components.
    pub fn custom<I>(root: AccountProcedureRoot, components: I) -> Result<Self, TransferPolicyError>
    where
        I: IntoIterator,
        I::Item: Into<AccountComponent>,
    {
        let components = custom_policy_components(root, components)?;
        Ok(Self { root, components })
    }

    /// Returns the procedure root of the policy this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }
}

impl Default for ReceivePolicy {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl IntoIterator for ReceivePolicy {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s carried by this receive policy descriptor in installation
    /// order.
    fn into_iter(self) -> Self::IntoIter {
        self.components.into_iter()
    }
}

// HELPERS
// ================================================================================================

/// Collects the companion `components` of a custom transfer policy and checks that one of them
/// exports `root`.
fn custom_policy_components<I>(
    root: AccountProcedureRoot,
    components: I,
) -> Result<Vec<AccountComponent>, TransferPolicyError>
where
    I: IntoIterator,
    I::Item: Into<AccountComponent>,
{
    let components: Vec<AccountComponent> = components.into_iter().map(Into::into).collect();
    if !components.iter().any(|component| component.has_procedure(root)) {
        return Err(TransferPolicyError::RootNotInComponents);
    }
    Ok(components)
}
