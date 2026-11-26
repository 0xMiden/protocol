//! Tests for the [`miden_standards::account::policies::SupplyRestrictionManager`] component and the
//! `SUPPLY_RESTRICTION_CONFIG` standard note that dispatches its admin procedures, and for the
//! [`miden_standards::account::policies::SupplyRestrictionPolicy`] that enforces the restrictions.

use anyhow::Context;
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    AccountType,
    StorageMapKey,
};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::errors::protocol::ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    ReceivePolicy,
    SendPolicy,
    SupplyRestrictionManager,
    SupplyRestrictionStorage,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FAUCET_SUPPLY_DECREASE_EXCEEDS_TOKEN_SUPPLY,
    ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT,
    ERR_SENDER_NOT_OWNER,
    ERR_SUPPLY_RESTRICTION_AMOUNT_EXCEEDS_MAX_AMOUNT,
    ERR_SUPPLY_RESTRICTION_CONFIG_NOTE_IS_NOT_PUBLIC,
    ERR_SUPPLY_RESTRICTION_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_SUPPLY_RESTRICTION_CONFIG_UNKNOWN_VARIANT,
    ERR_SUPPLY_RESTRICTION_TOTAL_EXCEEDS_MAX_AMOUNT,
    ERR_SUPPLY_RESTRICTION_TRANSFER_EXCEEDS_UNRESTRICTED_BALANCE,
    ERR_SUPPLY_RESTRICTION_UNFREEZE_EXCEEDS_FROZEN_AMOUNT,
};
use miden_standards::note::config::{SupplyRestrictionConfig, SupplyRestrictionConfigNote};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint, P2idNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
use miden_tx::TransactionExecutorError;
use rand::RngExt;
use rstest::rstest;

use super::assert_default_expiration_limit;
use super::rbac::test_account_id;
use super::transfer_policy::{assert_minted_note, build_mint_note};
use crate::into_private_note;

// CONSTANTS
// ================================================================================================

/// Token supply the test faucets start with.
const INITIAL_TOKEN_SUPPLY: u32 = 1_000;

/// Note storage variants of the supply restriction config note.
const VARIANT_FREEZE: u32 = 0;
const VARIANT_CONFISCATE: u32 = 2;

// HELPERS
// ================================================================================================

fn dummy_owner() -> AccountId {
    AccountId::mock_private(9)
}

/// Builds a fungible faucet without restricted accounts, see
/// [`add_faucet_with_owner_supply_restriction_initialized`].
fn add_faucet_with_owner_supply_restriction(
    builder: &mut MockChainBuilder,
    owner_id: AccountId,
) -> anyhow::Result<Account> {
    add_faucet_with_owner_supply_restriction_initialized(
        builder,
        owner_id,
        SupplyRestrictionStorage::new(),
    )
}

/// Builds a fungible faucet with an initial token supply of [`INITIAL_TOKEN_SUPPLY`] and an active
/// supply restriction send policy seeded with `restrictions`. It carries the
/// [`SupplyRestrictionManager`] component, gated by `owner_id` via `Authority::OwnerControlled`.
fn add_faucet_with_owner_supply_restriction_initialized(
    builder: &mut MockChainBuilder,
    owner_id: AccountId,
    restrictions: SupplyRestrictionStorage,
) -> anyhow::Result<Account> {
    let account_builder = AccountBuilder::new([43u8; 32])
        .account_type(AccountType::Public)
        .with_component(fungible_faucet()?)
        .with_component(Ownable2Step::new(owner_id))
        .with_component(Authority::OwnerControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(SendPolicy::with_supply_restriction(restrictions))
                .active_receive_policy(ReceivePolicy::allow_all())
                .build(),
        )
        .with_component(SupplyRestrictionManager);

    builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        account_builder,
        AccountState::Exists,
    )
}

fn fungible_faucet() -> anyhow::Result<FungibleFaucet> {
    Ok(FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(FungibleAsset::MAX_AMOUNT)
        .token_supply(AssetAmount::from(INITIAL_TOKEN_SUPPLY))
        .build()?)
}

/// Builds a [`SupplyRestrictionConfigNote`] for `config`, sent by `sender` and targeting the
/// faucet.
fn supply_restriction_config_note(
    sender: AccountId,
    faucet_id: AccountId,
    config: SupplyRestrictionConfig,
) -> anyhow::Result<Note> {
    let note = SupplyRestrictionConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .serial_number(rand::rng().random())
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the SupplyRestrictionConfig script with hand-crafted storage, bypassing
/// the builder so malformed inputs can be exercised.
///
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note, so
/// the note passes the script's target check and reaches the guard under test.
fn malformed_supply_restriction_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rand::rng())
        .script(SupplyRestrictionConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
        .build()?;
    Ok(note)
}

/// Returns the `(frozen, confiscated)` amounts of `holder` in the faucet's latest committed
/// restricted amounts map.
fn restricted_amounts(
    mock_chain: &MockChain,
    faucet_id: AccountId,
    holder: AccountId,
) -> anyhow::Result<(Felt, Felt)> {
    let faucet = mock_chain.committed_account(faucet_id)?;
    let key = StorageMapKey::new(AccountIdKey::from(holder).as_word());
    let value = faucet
        .storage()
        .get_map_item(SupplyRestrictionStorage::restricted_amounts_slot(), key)?;
    assert_eq!(value[2], Felt::ZERO, "unused restriction element should be zero");
    assert_eq!(value[3], Felt::ZERO, "unused restriction element should be zero");
    Ok((value[0], value[1]))
}

/// Returns the faucet's latest committed token supply.
fn token_supply(mock_chain: &MockChain, faucet_id: AccountId) -> anyhow::Result<AssetAmount> {
    let faucet = mock_chain.committed_account(faucet_id)?;
    Ok(FungibleFaucet::try_from(faucet.storage())?.token_supply())
}

// TESTS
// ================================================================================================

/// The note dispatches every action: freezing and unfreezing change only the frozen amount,
/// confiscating changes only the confiscated amount and decreases the token supply, and other
/// holders are unaffected.
#[tokio::test]
async fn freeze_unfreeze_and_confiscate() -> anyhow::Result<()> {
    const FREEZE_AMOUNT: u32 = 300;
    const PARTIAL_UNFREEZE_AMOUNT: u32 = 100;
    const CONFISCATE_AMOUNT: u32 = 50;
    const REMAINING_FROZEN_AMOUNT: u32 = FREEZE_AMOUNT - PARTIAL_UNFREEZE_AMOUNT;
    const REMAINING_TOKEN_SUPPLY: u32 = INITIAL_TOKEN_SUPPLY - CONFISCATE_AMOUNT;

    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let other_holder = AccountId::mock_private(4);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;

    let configs = [
        SupplyRestrictionConfig::Freeze {
            account: holder,
            amount: AssetAmount::from(FREEZE_AMOUNT),
        },
        SupplyRestrictionConfig::Unfreeze {
            account: holder,
            amount: AssetAmount::from(PARTIAL_UNFREEZE_AMOUNT),
        },
        SupplyRestrictionConfig::Confiscate {
            account: holder,
            amount: AssetAmount::from(CONFISCATE_AMOUNT),
        },
        SupplyRestrictionConfig::Unfreeze {
            account: holder,
            amount: AssetAmount::from(REMAINING_FROZEN_AMOUNT),
        },
    ];
    let notes = configs
        .into_iter()
        .map(|config| supply_restriction_config_note(owner_id, faucet.id(), config))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for note in &notes {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // (frozen, confiscated, token supply) after each note
    let expected = [
        (FREEZE_AMOUNT, 0, INITIAL_TOKEN_SUPPLY),
        (REMAINING_FROZEN_AMOUNT, 0, INITIAL_TOKEN_SUPPLY),
        (REMAINING_FROZEN_AMOUNT, CONFISCATE_AMOUNT, REMAINING_TOKEN_SUPPLY),
        (0, CONFISCATE_AMOUNT, REMAINING_TOKEN_SUPPLY),
    ];
    for (note, (frozen, confiscated, supply)) in notes.into_iter().zip(expected) {
        mock_chain.consume_notes_and_commit(faucet.id(), [note]).await?;

        assert_eq!(
            restricted_amounts(&mock_chain, faucet.id(), holder)?,
            (Felt::from(frozen), Felt::from(confiscated))
        );
        assert_eq!(token_supply(&mock_chain, faucet.id())?, AssetAmount::from(supply));
    }

    assert_eq!(
        restricted_amounts(&mock_chain, faucet.id(), other_holder)?,
        (Felt::ZERO, Felt::ZERO)
    );

    Ok(())
}

/// Unfreezing more than the frozen amount fails, even if the holder also has confiscated amounts.
///
/// The holder has 100 frozen and 100 confiscated. Unfreezing 101 fails because only the frozen
/// amount can be unfrozen: the confiscated amount is tracked separately and is never released.
#[tokio::test]
async fn unfreeze_more_than_frozen_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;

    let freeze = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Freeze {
            account: holder,
            amount: AssetAmount::from(100u32),
        },
    )?;
    let confiscate = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Confiscate {
            account: holder,
            amount: AssetAmount::from(100u32),
        },
    )?;
    for note in [&freeze, &confiscate] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    mock_chain.consume_notes_and_commit(faucet.id(), [freeze.clone()]).await?;
    mock_chain.consume_notes_and_commit(faucet.id(), [confiscate.clone()]).await?;

    let unfreeze = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Unfreeze {
            account: holder,
            amount: AssetAmount::from(101u32),
        },
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [unfreeze]).await?;

    assert_transaction_executor_error!(
        result,
        ERR_SUPPLY_RESTRICTION_UNFREEZE_EXCEEDS_FROZEN_AMOUNT
    );

    Ok(())
}

/// Confiscating more than the token supply fails.
#[tokio::test]
async fn confiscate_more_than_token_supply_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    let confiscate = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Confiscate {
            account: AccountId::mock_private(3),
            amount: AssetAmount::from(INITIAL_TOKEN_SUPPLY + 1),
        },
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [confiscate]).await?;

    assert_transaction_executor_error!(result, ERR_FAUCET_SUPPLY_DECREASE_EXCEEDS_TOKEN_SUPPLY);

    Ok(())
}

/// Freezing or confiscating an amount above the maximum fungible asset amount fails, including
/// an amount that would wrap the stored amounts around the field modulus.
#[rstest]
#[case::freeze_above_max(VARIANT_FREEZE, Felt::from(FungibleAsset::MAX_AMOUNT) + Felt::ONE)]
#[case::freeze_wrapping(VARIANT_FREEZE, Felt::ZERO - Felt::ONE)]
#[case::confiscate_above_max(VARIANT_CONFISCATE, Felt::from(FungibleAsset::MAX_AMOUNT) + Felt::ONE)]
#[case::confiscate_wrapping(VARIANT_CONFISCATE, Felt::ZERO - Felt::ONE)]
#[tokio::test]
async fn amount_above_max_amount_fails(
    #[case] variant: u32,
    #[case] amount: Felt,
) -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    let note = malformed_supply_restriction_config_note(
        owner_id,
        faucet.id(),
        vec![Felt::from(variant), holder.suffix(), holder.prefix().as_felt(), amount],
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(result, ERR_SUPPLY_RESTRICTION_AMOUNT_EXCEEDS_MAX_AMOUNT);

    Ok(())
}

/// Freezing or confiscating for a malformed account ID fails, so a typo in the account ID cannot
/// restrict a balance that no account holds.
#[rstest]
#[case::freeze(VARIANT_FREEZE)]
#[case::confiscate(VARIANT_CONFISCATE)]
#[tokio::test]
async fn malformed_account_id_fails(#[case] variant: u32) -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    // a valid suffix has its lower 8 bits set to zero
    let malformed_suffix = holder.suffix() + Felt::ONE;
    let note = malformed_supply_restriction_config_note(
        owner_id,
        faucet.id(),
        vec![Felt::from(variant), malformed_suffix, holder.prefix().as_felt(), Felt::ONE],
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(
        result,
        ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO
    );

    Ok(())
}

/// The frozen plus confiscated amount of a holder cannot exceed the maximum fungible asset
/// amount, even when every single amount is within it.
#[rstest]
#[case::freeze(SupplyRestrictionConfig::Freeze { account: AccountId::mock_private(3), amount: AssetAmount::from(1u32) })]
#[case::confiscate(SupplyRestrictionConfig::Confiscate { account: AccountId::mock_private(3), amount: AssetAmount::from(1u32) })]
#[tokio::test]
async fn total_above_max_amount_fails(
    #[case] config: SupplyRestrictionConfig,
) -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;

    let freeze_max = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Freeze {
            account: AccountId::mock_private(3),
            amount: FungibleAsset::MAX_AMOUNT,
        },
    )?;
    builder.add_output_note(RawOutputNote::Full(freeze_max.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    mock_chain.consume_notes_and_commit(faucet.id(), [freeze_max.clone()]).await?;

    let note = supply_restriction_config_note(owner_id, faucet.id(), config)?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(result, ERR_SUPPLY_RESTRICTION_TOTAL_EXCEEDS_MAX_AMOUNT);

    Ok(())
}

/// A sender other than the owner cannot dispatch any action.
#[rstest]
#[case::confiscate(SupplyRestrictionConfig::Confiscate { account: AccountId::mock_private(3), amount: AssetAmount::from(1u32) })]
#[tokio::test]
async fn non_owner_cannot_restrict(#[case] config: SupplyRestrictionConfig) -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let stranger = test_account_id(63);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    let note = supply_restriction_config_note(stranger, faucet.id(), config)?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

/// A note whose variant matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_variant_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    // variant 99 is not a known action
    let note = malformed_supply_restriction_config_note(
        owner_id,
        faucet.id(),
        vec![Felt::from(99u32), holder.suffix(), holder.prefix().as_felt(), Felt::from(1u32)],
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(result, ERR_SUPPLY_RESTRICTION_CONFIG_UNKNOWN_VARIANT);

    Ok(())
}

/// A note whose storage item count does not match the layout is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    // Freeze variant but the amount is missing
    let note = malformed_supply_restriction_config_note(
        owner_id,
        faucet.id(),
        vec![Felt::from(VARIANT_FREEZE), holder.suffix(), holder.prefix().as_felt()],
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(
        result,
        ERR_SUPPLY_RESTRICTION_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );

    Ok(())
}

/// The note is bound to its target faucet, so a decoy faucet with the same owner cannot consume
/// a note meant for another one.
#[tokio::test]
async fn decoy_faucet_cannot_consume_note_of_another_faucet() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let decoy = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::mock_public(9);

    let note = supply_restriction_config_note(
        owner_id,
        target,
        SupplyRestrictionConfig::Freeze {
            account: AccountId::mock_private(3),
            amount: AssetAmount::from(1u32),
        },
    )?;
    let result = mock_chain.consume_notes(decoy.id(), [note]).await?;

    assert_transaction_executor_error!(
        result,
        ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT
    );

    Ok(())
}

/// A private note carrying the same script and storage as a legitimate config note is rejected
/// before any restriction changes.
#[tokio::test]
async fn private_note_cannot_dispatch_the_action() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    let note = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Freeze {
            account: AccountId::mock_private(3),
            amount: AssetAmount::from(1u32),
        },
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [into_private_note(note)]).await?;

    assert_transaction_executor_error!(result, ERR_SUPPLY_RESTRICTION_CONFIG_NOTE_IS_NOT_PUBLIC);

    Ok(())
}

// SEND POLICY TESTS
// ================================================================================================

/// A holder of a faucet's asset whose account code can also remove assets from its vault without
/// moving them to a note, which the standard wallet cannot.
struct Holder {
    mock_chain: MockChain,
    faucet_id: AccountId,
    account_id: AccountId,
    remove_asset_root: AccountProcedureRoot,
}

impl Holder {
    /// Sets up a chain with a holder that has the given balance and restricted amounts.
    async fn new(balance: u32, frozen: u32, confiscated: u32) -> anyhow::Result<Self> {
        Ok(Self::with_notes(balance, frozen, confiscated, |_, _| Ok([])).await?.0)
    }

    /// Like [`Self::new`], but also commits the notes that `build_notes` returns for the IDs of the
    /// faucet and the holder.
    async fn with_notes<const NUM_NOTES: usize>(
        balance: u32,
        frozen: u32,
        confiscated: u32,
        build_notes: impl FnOnce(AccountId, AccountId) -> anyhow::Result<[Note; NUM_NOTES]>,
    ) -> anyhow::Result<(Self, [Note; NUM_NOTES])> {
        // build the component that can remove assets from the vault
        let component_name = "tests::holder";
        let code = CodeBuilder::default().compile_component_code(
            component_name,
            r#"
            use miden::protocol::native_account

            #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
            #! Outputs: [pad(16)]
            @account_procedure
            pub proc remove_asset
                exec.native_account::remove_asset dropw
            end
            "#,
        )?;
        let component =
            AccountComponent::new(code, vec![], AccountComponentMetadata::mock(component_name))?;
        let remove_asset_root = component
            .get_procedure_root_by_path(format!("{component_name}::remove_asset").as_str())
            .context("remove_asset procedure should exist")?;

        // add the holder and a faucet that restricts it
        let mut builder = MockChain::builder();
        let account = builder.add_account_from_builder(
            Auth::IncrNonce,
            AccountBuilder::new([44u8; 32])
                .account_type(AccountType::Public)
                .with_component(BasicWallet)
                .with_component(component),
            AccountState::Exists,
        )?;
        let restrictions = SupplyRestrictionStorage::with_restricted_amounts([(
            account.id(),
            AssetAmount::from(frozen),
            AssetAmount::from(confiscated),
        )])?;
        let faucet = add_faucet_with_owner_supply_restriction_initialized(
            &mut builder,
            dummy_owner(),
            restrictions,
        )?;

        // add the note that funds the holder, also with an asset of another faucet
        let asset = FungibleAsset::new(faucet.id(), balance.into())?;
        let note = builder.add_p2id_note(
            faucet.id(),
            account.id(),
            &[asset.into(), FungibleAsset::mock(balance.into())],
            NoteType::Public,
        )?;

        // add the notes of the caller
        let notes = build_notes(faucet.id(), account.id())?;
        for note in &notes {
            builder.add_output_note(RawOutputNote::Full(note.clone()));
        }

        let mut holder = Self {
            mock_chain: builder.build()?,
            faucet_id: faucet.id(),
            account_id: account.id(),
            remove_asset_root,
        };

        // fund the holder, which succeeds since restricted accounts can always receive assets
        let tx = holder.execute("nop", [note]).await??;
        holder.commit(&tx)?;
        assert_eq!(holder.balance()?, AssetAmount::from(balance));

        Ok((holder, notes))
    }

    /// Executes a transaction of the holder that consumes the committed `notes` and runs `script`.
    async fn execute(
        &self,
        script: &str,
        notes: impl IntoIterator<Item = Note>,
    ) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
        let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(format!(
            "
            use mock::util

            @transaction_script
            pub proc main
                {script}
            end
            "
        ))?;
        Ok(self
            .mock_chain
            .build_transaction(self.account_id)
            .authenticated_input_notes(notes)
            .tx_script(tx_script)
            .foreign_accounts(vec![self.mock_chain.get_foreign_account_inputs(self.faucet_id)?])
            .build()?
            .execute()
            .await)
    }

    fn commit(&mut self, tx: &ExecutedTransaction) -> anyhow::Result<()> {
        self.mock_chain.add_pending_executed_transaction(tx)?;
        self.mock_chain.prove_next_block()?;
        Ok(())
    }

    fn balance(&self) -> anyhow::Result<AssetAmount> {
        let asset = FungibleAsset::new(self.faucet_id, 0)?;
        let account = self.mock_chain.committed_account(self.account_id)?;
        Ok(account.vault().get_balance(Asset::from(asset).id())?)
    }

    /// Returns MASM code that pushes `amount` of the faucet's asset.
    fn push_asset(&self, amount: u32) -> anyhow::Result<String> {
        let asset = Asset::from(FungibleAsset::new(self.faucet_id, amount.into())?);
        Ok(push_asset(asset))
    }

    /// Returns MASM code that moves `amount` from the vault to a new note and seals it.
    fn send(&self, amount: u32) -> anyhow::Result<String> {
        let asset = self.push_asset(amount)?;
        Ok(format!("{asset} exec.util::create_default_note_with_moved_asset\n"))
    }

    /// Returns MASM code that adds `amount` to a new note without removing it from the vault and
    /// seals the note.
    fn send_without_removing(&self, amount: u32) -> anyhow::Result<String> {
        let asset = self.push_asset(amount)?;
        Ok(format!("{asset} exec.util::create_default_note_with_asset\n"))
    }

    /// Returns MASM code that removes `amount` from the vault.
    fn remove(&self, amount: u32) -> anyhow::Result<String> {
        self.call_with_asset(self.remove_asset_root, amount)
    }

    /// Returns MASM code that adds `amount` to the vault without taking it from an input note.
    fn add(&self, amount: u32) -> anyhow::Result<String> {
        self.call_with_asset(BasicWallet::receive_asset_root(), amount)
    }

    fn call_with_asset(&self, root: AccountProcedureRoot, amount: u32) -> anyhow::Result<String> {
        let asset = self.push_asset(amount)?;
        Ok(format!("padw padw {asset} call.{root} dropw dropw dropw dropw\n"))
    }
}

fn push_asset(asset: Asset) -> String {
    format!("push.{} push.{}", asset.to_value_word(), asset.to_id_word())
}

/// Builds a note that adds `amount` of the faucet's asset, and an asset of another faucet, to the
/// vault of the account.
fn receive_note(faucet_id: AccountId, account_id: AccountId, amount: u32) -> anyhow::Result<Note> {
    let note = P2idNote::builder()
        .sender(faucet_id)
        .target(account_id)
        .assets([
            Asset::from(FungibleAsset::new(faucet_id, amount.into())?),
            FungibleAsset::mock(100),
        ])
        .serial_number(rand::rng().random())
        .build()?;
    Ok(note.into())
}

/// Builds a note with `amount` of the faucet's asset that moves `forwarded` of it directly to a new
/// output note and the rest to the vault of the consuming account.
fn forward_note(faucet_id: AccountId, amount: u32, forwarded: u32) -> anyhow::Result<Note> {
    let forwarded_asset = push_asset(FungibleAsset::new(faucet_id, forwarded.into())?.into());
    let script = CodeBuilder::with_mock_packages().compile_note_script(format!(
        "
        use miden::protocol::active_note
        use miden::standards::wallets::basic
        use mock::util

        @note_script
        pub proc main
            dropw
            # => [pad(16)]

            {forwarded_asset} exec.active_note::remove_asset dropw
            # => [pad(16)]

            {forwarded_asset} exec.util::create_default_note_with_asset
            # => [pad(16)]

            exec.basic::move_note_assets_to_account
            # => [pad(16)]
        end
        "
    ))?;
    let note = NoteBuilder::new(faucet_id, rand::rng())
        .add_assets([FungibleAsset::new(faucet_id, amount.into())?.into()])
        .script(script)
        .build()?;
    Ok(note)
}

/// A holder can send its balance except for the frozen and confiscated amounts, summed up over all
/// notes of the transaction.
#[rstest]
#[case::unrestricted(100, 0, 0, &[60, 40], true)]
#[case::up_to_frozen(100, 40, 0, &[60], true)]
#[case::frozen(100, 40, 0, &[61], false)]
#[case::up_to_confiscated(100, 0, 40, &[60], true)]
#[case::confiscated(100, 0, 40, &[61], false)]
#[case::up_to_frozen_and_confiscated(100, 10, 30, &[60], true)]
#[case::frozen_and_confiscated(100, 10, 30, &[61], false)]
#[case::up_to_frozen_in_many_notes(100, 40, 0, &[10, 20, 30], true)]
#[case::frozen_in_many_notes(100, 40, 0, &[10, 20, 31], false)]
#[case::entire_balance_frozen(100, 100, 0, &[1], false)]
#[case::more_than_balance_frozen(100, 101, 0, &[1], false)]
#[tokio::test]
async fn restricted_amounts_cannot_be_sent(
    #[case] balance: u32,
    #[case] frozen: u32,
    #[case] confiscated: u32,
    #[case] amounts: &[u32],
    #[case] is_accepted: bool,
) -> anyhow::Result<()> {
    let holder = Holder::new(balance, frozen, confiscated).await?;
    let script = amounts
        .iter()
        .map(|amount| holder.send(*amount))
        .collect::<anyhow::Result<String>>()?;

    let result = holder.execute(&script, []).await?;

    if is_accepted {
        assert_default_expiration_limit(&result?);
    } else {
        assert_transaction_executor_error!(
            result,
            ERR_SUPPLY_RESTRICTION_TRANSFER_EXCEEDS_UNRESTRICTED_BALANCE
        );
    }

    Ok(())
}

/// Only the faucet's own asset counts towards the sent amount, also if a note holds other assets.
#[rstest]
#[case::up_to_frozen(60, true)]
#[case::frozen(61, false)]
#[tokio::test]
async fn assets_of_other_faucets_are_not_restricted(
    #[case] amount: u32,
    #[case] is_accepted: bool,
) -> anyhow::Result<()> {
    let holder = Holder::new(100, 40, 0).await?;
    let other_asset = push_asset(FungibleAsset::mock(100));
    let asset = holder.push_asset(amount)?;
    let script = format!(
        "
        exec.util::create_default_note
        # => [note_idx]

        {other_asset} dup.8 movdn.8 exec.util::move_asset_to_note
        # => [note_idx]

        {asset} dup.8 movdn.8 exec.util::move_asset_to_note
        # => [note_idx]

        exec.::miden::protocol::output_note::seal
        # => []
        "
    );

    let result = holder.execute(&script, []).await?;

    if is_accepted {
        result?;
    } else {
        assert_transaction_executor_error!(
            result,
            ERR_SUPPLY_RESTRICTION_TRANSFER_EXCEEDS_UNRESTRICTED_BALANCE
        );
    }

    Ok(())
}

/// A holder whose entire balance is frozen cannot bypass the policy by making its vault balance
/// look sufficient only while the note is sealed. Both transactions preserve assets.
#[rstest]
#[case::removed_after_sealing(false)]
#[case::added_temporarily(true)]
#[tokio::test]
async fn policy_does_not_rely_on_the_balance_while_sealing(
    #[case] adds_temporarily: bool,
) -> anyhow::Result<()> {
    const BALANCE: u32 = 100;

    let script = |holder: &Holder| -> anyhow::Result<String> {
        Ok(if adds_temporarily {
            [holder.add(BALANCE)?, holder.send(BALANCE)?, holder.remove(BALANCE)?].concat()
        } else {
            [holder.send_without_removing(BALANCE)?, holder.remove(BALANCE)?].concat()
        })
    };

    // sanity check that the script is valid for an unrestricted holder
    let mut holder = Holder::new(BALANCE, 0, 0).await?;
    let tx = holder.execute(&script(&holder)?, []).await??;
    holder.commit(&tx)?;
    assert_eq!(holder.balance()?, AssetAmount::ZERO);

    let holder = Holder::new(BALANCE, BALANCE, 0).await?;
    let result = holder.execute(&script(&holder)?, []).await?;
    assert_transaction_executor_error!(
        result,
        ERR_SUPPLY_RESTRICTION_TRANSFER_EXCEEDS_UNRESTRICTED_BALANCE
    );

    Ok(())
}

/// Amounts received in input notes count towards the amount that a holder can send in the same
/// transaction, summed up over all input notes and without the assets of other faucets. What the
/// holder must keep is exactly the restricted amount, even if its initial balance does not cover
/// it.
#[rstest]
#[case::up_to_received(40, 40, [4, 6], 10, true)]
#[case::more_than_received(40, 40, [4, 6], 11, false)]
#[case::up_to_uncovered_restriction(100, 150, [50, 30], 30, true)]
#[case::more_than_uncovered_restriction(100, 150, [50, 30], 31, false)]
#[tokio::test]
async fn received_amounts_can_be_sent_in_same_transaction(
    #[case] balance: u32,
    #[case] frozen: u32,
    #[case] received: [u32; 2],
    #[case] sent: u32,
    #[case] is_accepted: bool,
) -> anyhow::Result<()> {
    let (mut holder, [note_0, note_1]) =
        Holder::with_notes(balance, frozen, 0, |faucet_id, account_id| {
            let note = |amount: u32| receive_note(faucet_id, account_id, amount);
            Ok([note(received[0])?, note(received[1])?])
        })
        .await?;

    let result = holder.execute(&holder.send(sent)?, [note_0, note_1]).await?;

    if is_accepted {
        holder.commit(&result?)?;
        assert_eq!(
            holder.balance()?,
            AssetAmount::from(balance + received.iter().sum::<u32>() - sent)
        );
    } else {
        assert_transaction_executor_error!(
            result,
            ERR_SUPPLY_RESTRICTION_TRANSFER_EXCEEDS_UNRESTRICTED_BALANCE
        );
    }

    Ok(())
}

/// Assets that an input note moves directly to an output note, without the vault, are restricted
/// like any other transfer.
#[rstest]
#[case::up_to_received(40, 40, 10, 10, true)]
#[case::received_partially_frozen(40, 41, 10, 10, false)]
#[case::up_to_uncovered_restriction(100, 150, 80, 30, true)]
#[case::more_than_uncovered_restriction(100, 150, 80, 31, false)]
#[tokio::test]
async fn direct_transfers_between_notes_are_restricted(
    #[case] balance: u32,
    #[case] frozen: u32,
    #[case] received: u32,
    #[case] forwarded: u32,
    #[case] is_accepted: bool,
) -> anyhow::Result<()> {
    let (mut holder, [note]) = Holder::with_notes(balance, frozen, 0, |faucet_id, _| {
        Ok([forward_note(faucet_id, received, forwarded)?])
    })
    .await?;

    let result = holder.execute("nop", [note]).await?;

    if is_accepted {
        holder.commit(&result?)?;
        assert_eq!(holder.balance()?, AssetAmount::from(balance + received - forwarded));
    } else {
        assert_transaction_executor_error!(
            result,
            ERR_SUPPLY_RESTRICTION_TRANSFER_EXCEEDS_UNRESTRICTED_BALANCE
        );
    }

    Ok(())
}

/// Amounts frozen and unfrozen through the config note take effect in the send policy.
#[tokio::test]
async fn policy_enforces_frozen_amounts_of_config_notes() -> anyhow::Result<()> {
    const BALANCE: u32 = 100;

    let amount = AssetAmount::from(BALANCE);
    let (mut holder, [freeze, unfreeze]) =
        Holder::with_notes(BALANCE, 0, 0, |faucet_id, account| {
            let note = |config| supply_restriction_config_note(dummy_owner(), faucet_id, config);
            Ok([
                note(SupplyRestrictionConfig::Freeze { account, amount })?,
                note(SupplyRestrictionConfig::Unfreeze { account, amount })?,
            ])
        })
        .await?;
    let send = holder.send(BALANCE)?;

    holder.mock_chain.consume_notes_and_commit(holder.faucet_id, [freeze]).await?;
    let result = holder.execute(&send, []).await?;
    assert_transaction_executor_error!(
        result,
        ERR_SUPPLY_RESTRICTION_TRANSFER_EXCEEDS_UNRESTRICTED_BALANCE
    );

    holder.mock_chain.consume_notes_and_commit(holder.faucet_id, [unfreeze]).await?;
    holder.execute(&send, []).await??;

    Ok(())
}

/// Minting invokes the send policy with the faucet as the native account, which is exempt from its
/// own restrictions.
#[tokio::test]
async fn mint_succeeds_after_faucet_restricts_itself() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let freeze = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Freeze {
            account: faucet.id(),
            amount: AssetAmount::from(1u32),
        },
    )?;
    builder.add_output_note(RawOutputNote::Full(freeze.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.consume_notes_and_commit(faucet.id(), [freeze]).await?;

    let mint = build_mint_note(owner_id, faucet.id(), AccountId::mock_private(3), 100, 10)?;
    let tx = mock_chain.consume_notes(faucet.id(), [mint.note.clone()]).await??;
    assert_minted_note(&tx, &mint)?;

    Ok(())
}
