//! Spending-limit tests for [`AuthMultisigSmart`].
//!
//! Every fungible asset a transaction sends out is priced into the base asset, one to one for the
//! base asset itself and through the oracle for everything else, and charged to the account's
//! budget. The budget is enforced after the signature check, so the probe execution clients use to
//! obtain the summary stops at the unauthorized event as usual and a spend over the budget fails in
//! the signed execution with the spending-limit error.

use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    AccountType,
};
use miden_protocol::asset::{Asset, AssetId, FungibleAsset, NonFungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionScript};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::account::auth::multisig_smart::{
    SpendingBudget,
    SpendingLimitsPolicy,
    SpendingOracle,
    UncoveredAssetPolicy,
};
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    AuthMultisigSmart,
    AuthMultisigSmartConfig,
    MultisigAuthArgs,
};
use miden_standards::account::oracle::PriceOracle;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_BASE_ASSET_NOT_FUNGIBLE,
    ERR_MAX_ORACLE_BLOCK_AGE_WITHOUT_ORACLE,
    ERR_MAX_ORACLE_BLOCK_AGE_ZERO,
    ERR_SPENDING_LIMIT_EXCEEDED,
    ERR_SPENDING_LIMIT_REQUIRES_BASE_ASSET,
    ERR_UNCOVERED_ASSET_POLICY_INVALID,
    ERR_UNCOVERED_ASSET_REJECTED,
};
use miden_standards::note::P2idNote;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{
    Auth,
    MockChain,
    MockChainBuilder,
    MockTransactionBuilder,
    assert_transaction_executor_error,
};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rstest::rstest;

use super::multisig::{MultisigAuthArgsExt, setup_keys_and_authenticators_with_scheme};

// CONSTANTS
// ================================================================================================

/// Window length used throughout: short enough that a test can cross a boundary cheaply.
const WINDOW_BLOCKS: u32 = 16;

/// The spending limit, denominated in the USDCX-like base asset.
const SPENDING_LIMIT: u64 = 100_000;

/// Blocks a transaction stays includable after reading the oracle. Below `WINDOW_BLOCKS`, so the
/// oracle bound is visible next to the window bound.
const MAX_ORACLE_BLOCK_AGE: u16 = 8;

/// Rate the test oracle quotes for every pair: 3000 base units per unit of the source asset.
const ORACLE_RATE: u64 = 3_000;

const FIXED_RATE_PROVIDER: &str = "fixed_rate_3000";
const UNPRICED_PROVIDER: &str = "unpriced";

const RATE_PROVIDERS_PATH: &str = "test::spending_limits::rate_providers";

/// Rate providers with the shape `price_oracle::get_conversion_rate` dispatches to.
const RATE_PROVIDERS_CODE: &str = r#"
    use miden::core::sys

    #! Prices every pair at 3000/1, observed at timestamp 7.
    #!
    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [last_updated, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc fixed_rate_3000
        dropw dropw
        push.1 push.3000 push.7
        exec.sys::truncate_stack
    end

    #! Prices nothing.
    #!
    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [last_updated, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc unpriced
        dropw dropw
        push.0 push.0 push.0
        exec.sys::truncate_stack
    end
"#;

// HELPERS
// ================================================================================================

fn faucet(id: u128) -> AccountId {
    AccountId::try_from(id).expect("test faucet id should be valid")
}

/// An asset priced through the oracle.
fn eth() -> AccountId {
    faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
}

/// The base asset of the budget.
fn usdcx() -> AccountId {
    faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)
}

fn fungible(faucet_id: AccountId, amount: u64) -> Asset {
    FungibleAsset::new(faucet_id, amount)
        .expect("test amount should be valid")
        .into()
}

fn nft() -> Asset {
    NonFungibleAsset::mock(&[1, 2, 3])
}

fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("non-zero")
}

/// The budget: `SPENDING_LIMIT` USDCX per window, priced through the given oracle account when
/// there is one.
fn budget(oracle: Option<AccountId>) -> SpendingBudget {
    let budget = SpendingBudget::new(AssetId::new_fungible(usdcx()), nonzero(SPENDING_LIMIT))
        .expect("budget should be valid");
    match oracle {
        Some(oracle) => budget.with_oracle(SpendingOracle::new(
            oracle,
            NonZeroU16::new(MAX_ORACLE_BLOCK_AGE).unwrap(),
        )),
        None => budget,
    }
}

fn policy(oracle: Option<AccountId>, uncovered: UncoveredAssetPolicy) -> SpendingLimitsPolicy {
    SpendingLimitsPolicy::new(NonZeroU32::new(WINDOW_BLOCKS).unwrap(), budget(oracle))
        .with_uncovered_assets(uncovered)
}

fn rate_providers_code() -> anyhow::Result<AccountComponentCode> {
    Ok(CodeBuilder::default().compile_component_code(RATE_PROVIDERS_PATH, RATE_PROVIDERS_CODE)?)
}

fn rate_provider_root(
    code: &AccountComponentCode,
    name: &str,
) -> anyhow::Result<AccountProcedureRoot> {
    code.get_procedure_root_by_path(format!("{RATE_PROVIDERS_PATH}::{name}").as_str())
        .ok_or_else(|| anyhow::anyhow!("component should export {name}"))
}

/// Builds an oracle account dispatching to the named test rate provider.
fn oracle_account(provider: &str) -> anyhow::Result<Account> {
    let code = rate_providers_code()?;
    let oracle = PriceOracle::new(rate_provider_root(&code, provider)?);
    let providers = AccountComponent::new(
        code,
        Vec::new(),
        AccountComponentMetadata::mock(RATE_PROVIDERS_PATH),
    )?;

    Ok(AccountBuilder::new([31; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(Authority::AuthControlled)
        .with_component(oracle)
        .with_component(providers)
        .build_existing()?)
}

/// Builds the multisig account under test, holding every asset the tests send.
fn multisig_account(
    threshold: u32,
    public_keys: &[PublicKey],
    policy: Option<SpendingLimitsPolicy>,
) -> anyhow::Result<Account> {
    let approvers: Vec<_> = public_keys.iter().map(Approver::from).collect();
    let approver_set = ApproverSet::new(approvers, threshold)?;
    let mut config = AuthMultisigSmartConfig::new(approver_set);
    if let Some(policy) = policy {
        config = config.with_spending_limits_policy(policy);
    }

    let assets = [fungible(usdcx(), 1_000_000), fungible(eth(), 1_000), nft()];

    Ok(AccountBuilder::new([0; 32])
        .with_component(AuthMultisigSmart::new(config)?)
        .with_component(BasicWallet)
        .account_type(AccountType::Public)
        .with_assets(assets)
        .build_existing()?)
}

fn compile_tx_script(script: impl AsRef<str>) -> anyhow::Result<TransactionScript> {
    Ok(CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisigSmart::code())?
        .compile_tx_script(script.as_ref())?)
}

/// Everything a test needs to drive transactions against the multisig account.
struct Harness {
    chain: MockChain,
    account: Account,
    public_keys: Vec<PublicKey>,
    authenticators: Vec<BasicAuthenticator>,
    /// The oracle account, passed as a foreign account input to every transaction while set.
    oracle: Option<Account>,
    salt_seed: u8,
}

impl Harness {
    /// A 2-of-2 multisig, next to an oracle account dispatching to the named rate provider when one
    /// is given. With an uncovered-asset policy given, the account gets the spending-limit policy
    /// with a USDCX budget, priced through that oracle if any; without one, spending limits are
    /// disabled.
    fn new(
        uncovered: Option<UncoveredAssetPolicy>,
        provider: Option<&str>,
    ) -> anyhow::Result<Self> {
        let (_secret_keys, _schemes, public_keys, authenticators) =
            setup_keys_and_authenticators_with_scheme(2, 2, AuthScheme::EcdsaK256Keccak)?;

        let oracle = provider.map(oracle_account).transpose()?;
        let policy = uncovered.map(|uncovered| policy(oracle.as_ref().map(Account::id), uncovered));
        let account = multisig_account(2, &public_keys, policy)?;

        let mut accounts = vec![account.clone()];
        accounts.extend(oracle.clone());
        let chain = MockChainBuilder::with_accounts(accounts)?.build()?;

        Ok(Self {
            chain,
            account,
            public_keys,
            authenticators,
            oracle,
            salt_seed: 1,
        })
    }

    /// The default setup: the policy enabled with `reject` for uncovered assets and an oracle that
    /// prices every pair at `ORACLE_RATE`.
    fn with_policy() -> anyhow::Result<Self> {
        Self::new(Some(UncoveredAssetPolicy::Reject), Some(FIXED_RATE_PROVIDER))
    }

    /// The policy enabled with the given uncovered-asset policy and no oracle at all.
    fn without_oracle(uncovered: UncoveredAssetPolicy) -> anyhow::Result<Self> {
        Self::new(Some(uncovered), None)
    }

    fn next_salt(&mut self) -> Word {
        self.salt_seed += 1;
        Word::from([Felt::new_unchecked(self.salt_seed as u64); 4])
    }

    fn latest_block(&self) -> BlockNumber {
        self.chain.latest_block_header().block_num()
    }

    fn output_note(&self, asset: Asset, seed: Word) -> anyhow::Result<Note> {
        self.output_note_with_assets(vec![asset], seed)
    }

    fn output_note_with_assets(&self, assets: Vec<Asset>, seed: Word) -> anyhow::Result<Note> {
        Ok(P2idNote::builder()
            .sender(self.account.id())
            .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into()?)
            .assets(assets)
            .note_type(NoteType::Public)
            .generate_serial_number(&mut RandomCoin::new(seed))
            .build()?
            .into())
    }

    /// Adds the oracle account to the transaction inputs while the harness has one.
    fn with_foreign_inputs<'a>(
        &self,
        builder: MockTransactionBuilder<'a>,
    ) -> anyhow::Result<MockTransactionBuilder<'a>> {
        match &self.oracle {
            Some(oracle) => {
                Ok(builder
                    .foreign_accounts([self.chain.get_foreign_account_inputs(oracle.id())?]))
            },
            None => Ok(builder),
        }
    }

    fn oracle_id(&self) -> AccountId {
        self.oracle.as_ref().expect("harness should have an oracle").id()
    }

    /// Sends all `assets` in one P2ID note, both approvers signing.
    async fn send_bundle(
        &mut self,
        assets: Vec<Asset>,
    ) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
        let salt = self.next_salt();
        let note = self.output_note_with_assets(assets, salt)?;
        let script = SendNotesTransactionScript::new(
            &self.account.code_interface(),
            &[note.clone().into()],
        )?;
        let builder = self
            .chain
            .build_transaction(self.account.id())
            .expected_output_note(RawOutputNote::Full(note))
            .send_notes_script(&script)
            .multisig_auth_args(MultisigAuthArgs::new(self.latest_block(), salt));
        let builder = self.with_foreign_inputs(builder)?;
        let result =
            Self::sign_and_execute(builder, &[0, 1], &self.public_keys, &self.authenticators)
                .await?;
        if let Ok(tx) = &result {
            self.commit(tx)?;
        }
        Ok(result)
    }

    /// Builds a transaction sending `asset` in one P2ID note, bound to `reference_block` (or the
    /// latest block), probe-executes it to obtain the summary, signs it with the given approvers
    /// and executes for real. A successful transaction is applied to the account and sealed into a
    /// block; a spend the budget rejects comes back as the spending-limit error.
    async fn send_signed(
        &mut self,
        asset: Asset,
        signers: &[usize],
        reference_block: Option<BlockNumber>,
    ) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
        let salt = self.next_salt();
        let result = self.run_send_notes(vec![asset], salt, signers, reference_block).await?;
        if let Ok(tx) = &result {
            self.commit(tx)?;
        }
        Ok(result)
    }

    /// Sends `asset` with both approvers signing and expects success.
    async fn send(&mut self, asset: Asset) -> anyhow::Result<ExecutedTransaction> {
        Ok(self.send_signed(asset, &[0, 1], None).await??)
    }

    /// Sends each asset in its own P2ID note within one transaction, both approvers signing.
    async fn send_many(
        &mut self,
        assets: Vec<Asset>,
    ) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
        let salt = self.next_salt();
        let result = self.run_send_notes(assets, salt, &[0, 1], None).await?;
        if let Ok(tx) = &result {
            self.commit(tx)?;
        }
        Ok(result)
    }

    /// Runs a configuration transaction script with both approvers signing. A successful
    /// transaction is applied to the account and sealed into a block.
    async fn configure(
        &mut self,
        script: &str,
    ) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
        let salt = self.next_salt();
        let tx_script = compile_tx_script(script)?;
        let builder = self
            .chain
            .build_transaction(self.account.id())
            .tx_script(tx_script)
            .multisig_auth_args(MultisigAuthArgs::new(self.latest_block(), salt));
        let result =
            Self::sign_and_execute(builder, &[0, 1], &self.public_keys, &self.authenticators)
                .await?;
        if let Ok(tx) = &result {
            self.commit(tx)?;
        }
        Ok(result)
    }

    async fn run_send_notes(
        &self,
        assets: Vec<Asset>,
        salt: Word,
        signers: &[usize],
        reference_block: Option<BlockNumber>,
    ) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
        let notes = assets
            .into_iter()
            .enumerate()
            .map(|(i, asset)| {
                let seed = Word::from([salt[0], Felt::new_unchecked(i as u64), salt[2], salt[3]]);
                self.output_note(asset, seed)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let partial_notes: Vec<_> = notes.iter().cloned().map(Into::into).collect();
        let script =
            SendNotesTransactionScript::new(&self.account.code_interface(), &partial_notes)?;
        let bound_block = reference_block.unwrap_or_else(|| self.latest_block());

        let mut builder = self
            .chain
            .build_transaction(self.account.id())
            .expected_output_notes(notes.into_iter().map(RawOutputNote::Full).collect())
            .send_notes_script(&script)
            .multisig_auth_args(MultisigAuthArgs::new(bound_block, salt));
        if let Some(reference_block) = reference_block {
            builder = builder.reference_block(reference_block);
        }
        let builder = self.with_foreign_inputs(builder)?;

        Self::sign_and_execute(builder, signers, &self.public_keys, &self.authenticators).await
    }

    /// Probe-executes `builder`; when the probe stops at signature verification and `signers` is
    /// non-empty, signs the summary with those approvers and executes again.
    async fn sign_and_execute(
        builder: MockTransactionBuilder<'_>,
        signers: &[usize],
        public_keys: &[PublicKey],
        authenticators: &[BasicAuthenticator],
    ) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
        let probe = builder.clone().build()?.execute().await;
        let tx_summary = match probe {
            Err(TransactionExecutorError::Unauthorized(tx_summary)) if !signers.is_empty() => {
                tx_summary
            },
            other => return Ok(other),
        };

        let msg = tx_summary.as_ref().to_commitment();
        let signing_inputs = SigningInputs::TransactionSummary(tx_summary);
        let mut builder = builder;
        for &signer in signers {
            let signature = authenticators[signer]
                .get_signature(public_keys[signer].to_commitment(), &signing_inputs)
                .await?;
            builder = builder.add_signature(public_keys[signer].to_commitment(), msg, signature);
        }

        Ok(builder.build()?.execute().await)
    }

    /// Applies a successful transaction to the account and seals it into a block.
    fn commit(&mut self, tx: &ExecutedTransaction) -> anyhow::Result<()> {
        self.account.apply_patch(tx.account_patch())?;
        self.chain.add_pending_executed_transaction(tx)?;
        self.chain.prove_next_block()?;
        Ok(())
    }

    fn config(&self) -> Word {
        self.account
            .storage()
            .get_item(AuthMultisigSmart::spending_config_slot())
            .expect("spending config slot should be present")
    }

    fn tracker(&self) -> Word {
        self.account
            .storage()
            .get_item(AuthMultisigSmart::spending_tracker_slot())
            .expect("spending tracker slot should be present")
    }

    fn limit(&self) -> Word {
        self.account
            .storage()
            .get_item(AuthMultisigSmart::spending_limit_slot())
            .expect("spending limit slot should be present")
    }
}

fn window_index(block: BlockNumber) -> u32 {
    block.as_u32() / WINDOW_BLOCKS
}

fn tracker_word(spent: u64, block: BlockNumber, generation: u32) -> Word {
    Word::from([
        Felt::new_unchecked(spent),
        Felt::from(window_index(block)),
        Felt::from(generation),
        Felt::from(0u32),
    ])
}

// BUDGET
// ================================================================================================

#[tokio::test]
async fn spend_within_the_limit_is_allowed_and_tracked() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    let block = h.latest_block();

    h.send(fungible(usdcx(), 50_000)).await?;

    assert_eq!(h.tracker(), tracker_word(50_000, block, 0));
    Ok(())
}

#[tokio::test]
async fn spend_over_the_limit_fails_even_with_every_signature() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    let result = h.send_signed(fungible(usdcx(), SPENDING_LIMIT + 1), &[0, 1], None).await?;

    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);
    Ok(())
}

#[tokio::test]
async fn spend_exactly_at_the_limit_is_allowed() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    h.send(fungible(usdcx(), SPENDING_LIMIT)).await?;

    Ok(())
}

#[tokio::test]
async fn spends_accumulate_within_a_window_and_reset_after_it() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    h.send(fungible(usdcx(), 60_000)).await?;

    // 60_000 + 50_000 exceeds the limit inside the same window.
    let result = h.send_signed(fungible(usdcx(), 50_000), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);

    // The next window starts from zero.
    let next_window_block = (window_index(h.latest_block()) + 1) * WINDOW_BLOCKS;
    h.chain.prove_until_block(next_window_block)?;
    h.send(fungible(usdcx(), 50_000)).await?;

    let block = h.latest_block();
    assert_eq!(window_index(block), window_index(BlockNumber::from(next_window_block)));
    assert_eq!(h.tracker(), tracker_word(50_000, block, 0));
    Ok(())
}

#[tokio::test]
async fn an_older_reference_block_does_not_release_budget() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    // Spend in window N, then move into window N+1 and spend again.
    let window_n_block = h.latest_block();
    h.send(fungible(usdcx(), 60_000)).await?;
    let next_window_block = (window_index(window_n_block) + 1) * WINDOW_BLOCKS;
    h.chain.prove_until_block(next_window_block)?;
    h.send(fungible(usdcx(), 50_000)).await?;

    // A transaction referencing a block back in window N finds the tracker ahead of it and keeps
    // charging window N+1: 50_000 + 60_000 exceeds the limit, no budget was released.
    let result = h.send_signed(fungible(usdcx(), 60_000), &[0, 1], Some(window_n_block)).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);
    Ok(())
}

#[tokio::test]
async fn a_disabled_policy_does_not_meter() -> anyhow::Result<()> {
    let mut h = Harness::new(None, Some(FIXED_RATE_PROVIDER))?;

    let tx = h.send(fungible(usdcx(), 500_000)).await?;

    assert_eq!(h.tracker(), Word::empty());
    // Nothing bound the expiration either.
    assert_eq!(tx.expiration_block_num(), BlockNumber::from(u32::MAX));
    Ok(())
}

#[tokio::test]
async fn non_fungible_assets_are_not_metered() -> anyhow::Result<()> {
    // `reject` for uncovered assets and no price for the NFT: the send still goes through.
    let mut h = Harness::new(Some(UncoveredAssetPolicy::Reject), Some(UNPRICED_PROVIDER))?;

    h.send(nft()).await?;

    assert_eq!(h.tracker(), Word::empty());
    Ok(())
}

#[tokio::test]
async fn spending_limits_leave_the_signature_threshold_unchanged() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    // One of two signatures: within the limit, still unauthorized.
    let result = h.send_signed(fungible(usdcx(), 1_000), &[0], None).await?;
    result.unwrap_err().unwrap_unauthorized_err();

    Ok(())
}

// PRICING
// ================================================================================================

#[tokio::test]
async fn the_base_asset_is_charged_one_to_one_without_the_oracle() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    // Drop the oracle from the transaction inputs: the base asset must not need it.
    h.oracle = None;
    let block = h.latest_block();

    h.send(fungible(usdcx(), 60_000)).await?;

    assert_eq!(h.tracker(), tracker_word(60_000, block, 0));
    Ok(())
}

#[tokio::test]
async fn other_assets_are_converted_through_the_oracle() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    let block = h.latest_block();

    h.send(fungible(eth(), 10)).await?;

    assert_eq!(h.tracker(), tracker_word(10 * ORACLE_RATE, block, 0));
    Ok(())
}

#[tokio::test]
async fn the_budget_accumulates_across_assets() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    h.send(fungible(usdcx(), 60_000)).await?;
    h.send(fungible(eth(), 10)).await?;

    // 60_000 + 30_000 + 15_000 exceeds the limit.
    let result = h.send_signed(fungible(eth(), 5), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);
    Ok(())
}

#[rstest]
#[case::reject(UncoveredAssetPolicy::Reject)]
#[case::allow(UncoveredAssetPolicy::Allow)]
#[tokio::test]
async fn an_unpriced_asset_falls_to_the_policy(
    #[case] uncovered: UncoveredAssetPolicy,
) -> anyhow::Result<()> {
    let mut h = Harness::new(Some(uncovered), Some(UNPRICED_PROVIDER))?;

    let result = h.send_signed(fungible(eth(), 10), &[0, 1], None).await?;

    match uncovered {
        UncoveredAssetPolicy::Reject => {
            assert_transaction_executor_error!(result, ERR_UNCOVERED_ASSET_REJECTED);
        },
        UncoveredAssetPolicy::Allow => {
            result?;
            assert_eq!(h.tracker(), Word::empty());
        },
        _ => unreachable!("the policy has two variants"),
    }
    Ok(())
}

#[tokio::test]
async fn reading_the_oracle_tightens_the_expiration() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    let reference_block = h.latest_block();

    let tx = h.send(fungible(eth(), 1)).await?;

    assert_eq!(tx.expiration_block_num(), reference_block + u32::from(MAX_ORACLE_BLOCK_AGE));
    Ok(())
}

#[tokio::test]
async fn the_policy_binds_the_expiration_to_the_window() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    let reference_block = h.latest_block();

    // The base asset reads no oracle, so the window is the only bound.
    let tx = h.send(fungible(usdcx(), 1)).await?;

    assert_eq!(tx.expiration_block_num(), reference_block + WINDOW_BLOCKS);
    Ok(())
}

/// A past window with no spend in it looks fresh to the tracker. Referencing a block inside it does
/// open a fresh budget, but the transaction expires one window after that block, so it can no
/// longer be included once the chain has moved on.
#[tokio::test]
async fn an_idle_window_cannot_be_reopened_with_an_old_reference_block() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    h.send(fungible(usdcx(), 60_000)).await?;

    // Leave the next window idle and stand two windows past it.
    let idle_window_block = (window_index(h.latest_block()) + 1) * WINDOW_BLOCKS;
    h.chain.prove_until_block(idle_window_block + 2 * WINDOW_BLOCKS)?;

    let salt = h.next_salt();
    let tx = h
        .run_send_notes(
            vec![fungible(usdcx(), 60_000)],
            salt,
            &[0, 1],
            Some(BlockNumber::from(idle_window_block)),
        )
        .await??;

    assert_eq!(tx.expiration_block_num(), BlockNumber::from(idle_window_block + WINDOW_BLOCKS));
    assert!(tx.expiration_block_num() < h.latest_block(), "the transaction must be expired");
    Ok(())
}

#[tokio::test]
async fn a_priced_spend_without_the_oracle_account_fails() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    h.oracle = None;

    let result = h.send_signed(fungible(eth(), 1), &[0, 1], None).await?;

    assert!(result.is_err(), "the foreign call must fail without the oracle inputs");
    Ok(())
}

#[rstest]
#[case::reject(UncoveredAssetPolicy::Reject)]
#[case::allow(UncoveredAssetPolicy::Allow)]
#[tokio::test]
async fn without_an_oracle_only_the_base_asset_is_priced(
    #[case] uncovered: UncoveredAssetPolicy,
) -> anyhow::Result<()> {
    let mut h = Harness::without_oracle(uncovered)?;
    let block = h.latest_block();

    // The base asset is charged one to one with no foreign inputs at all.
    h.send(fungible(usdcx(), 60_000)).await?;
    assert_eq!(h.tracker(), tracker_word(60_000, block, 0));

    // Everything else is unpriced and falls to the policy.
    let result = h.send_signed(fungible(eth(), 1), &[0, 1], None).await?;
    match uncovered {
        UncoveredAssetPolicy::Reject => {
            assert_transaction_executor_error!(result, ERR_UNCOVERED_ASSET_REJECTED);
        },
        UncoveredAssetPolicy::Allow => {
            result?;
            assert_eq!(h.tracker()[0], Felt::new_unchecked(60_000));
        },
        _ => unreachable!("the policy has two variants"),
    }
    Ok(())
}

/// The response to a faulty oracle: unset it. The base asset stays under the limit, with its
/// running total intact, and other assets fall to the policy.
#[tokio::test]
async fn unsetting_the_oracle_keeps_the_base_asset_under_the_limit() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    h.send(fungible(eth(), 10)).await?;
    assert_eq!(h.tracker()[0], Felt::new_unchecked(10 * ORACLE_RATE));

    h.configure(&unset_oracle_script(0)).await??;
    h.oracle = None;

    let result = h.send_signed(fungible(eth(), 1), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_UNCOVERED_ASSET_REJECTED);

    h.send(fungible(usdcx(), 60_000)).await?;
    assert_eq!(h.tracker()[0], Felt::new_unchecked(10 * ORACLE_RATE + 60_000));
    Ok(())
}

// CONFIGURATION
// ================================================================================================

/// Pushes the procedure's inputs in reverse and drops them again after the call, since `call.`
/// does not consume the caller's stack.
fn set_limit_script(limit: u64) -> String {
    format!(
        "
        @transaction_script
        pub proc main
            push.{limit}
            call.::miden::standards::components::auth::multisig_smart::set_spending_limit
            drop
        end
        "
    )
}

fn update_policy_script(window_blocks: u32, uncovered_policy: u32) -> String {
    format!(
        "
        @transaction_script
        pub proc main
            push.{uncovered_policy}
            push.{window_blocks}
            call.::miden::standards::components::auth::multisig_smart::update_spending_limits_policy
            drop drop
        end
        "
    )
}

fn update_oracle_script(oracle_id: AccountId, max_block_age: u32, base_asset: AssetId) -> String {
    update_oracle_script_raw(
        oracle_id.prefix().as_felt(),
        oracle_id.suffix(),
        max_block_age,
        Word::from(base_asset),
    )
}

/// Unsets the oracle, keeping USDCX as the base asset.
fn unset_oracle_script(max_block_age: u32) -> String {
    update_oracle_script_raw(
        Felt::from(0u32),
        Felt::from(0u32),
        max_block_age,
        Word::from(AssetId::new_fungible(usdcx())),
    )
}

fn update_oracle_script_raw(
    prefix: Felt,
    suffix: Felt,
    max_block_age: u32,
    base_asset: Word,
) -> String {
    format!(
        "
        @transaction_script
        pub proc main
            push.{base_asset}
            push.{max_block_age}
            push.{prefix}
            push.{suffix}
            call.::miden::standards::components::auth::multisig_smart::update_spending_oracle
            drop drop drop dropw
        end
        "
    )
}

#[tokio::test]
async fn set_spending_limit_writes_and_clears_the_slot() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    h.configure(&set_limit_script(500)).await??;
    assert_eq!(h.limit(), Word::from([500u32, 0, 0, 0]));

    // The new limit applies from the next transaction on: 1 ETH is 3000 in the base asset.
    let result = h.send_signed(fungible(eth(), 1), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);

    // A cleared limit leaves every fungible asset uncovered, the base asset included.
    h.configure(&set_limit_script(0)).await??;
    assert_eq!(h.limit(), Word::empty());
    let result = h.send_signed(fungible(usdcx(), 1), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_UNCOVERED_ASSET_REJECTED);
    Ok(())
}

#[tokio::test]
async fn changing_the_window_length_resets_the_tracker() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    h.send(fungible(usdcx(), 60_000)).await?;

    // Re-saving the same window length keeps the running total.
    h.configure(&update_policy_script(WINDOW_BLOCKS, UncoveredAssetPolicy::Reject.as_u32()))
        .await??;
    let result = h.send_signed(fungible(usdcx(), 50_000), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);

    // A different window length bumps the generation and the total starts over.
    h.configure(&update_policy_script(WINDOW_BLOCKS * 2, UncoveredAssetPolicy::Reject.as_u32()))
        .await??;
    h.send(fungible(usdcx(), 50_000)).await?;
    assert_eq!(h.tracker()[0], Felt::new_unchecked(50_000));
    assert_eq!(h.tracker()[2], Felt::from(1u32));
    Ok(())
}

#[tokio::test]
async fn update_spending_limits_policy_rejects_an_invalid_uncovered_policy() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    let result = h.configure(&update_policy_script(WINDOW_BLOCKS, 2)).await?;

    assert_transaction_executor_error!(result, ERR_UNCOVERED_ASSET_POLICY_INVALID);
    Ok(())
}

#[tokio::test]
async fn update_spending_oracle_rejects_a_zero_block_age() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    let oracle = h.oracle_id();

    let result = h
        .configure(&update_oracle_script(oracle, 0, AssetId::new_fungible(usdcx())))
        .await?;

    assert_transaction_executor_error!(result, ERR_MAX_ORACLE_BLOCK_AGE_ZERO);
    Ok(())
}

#[tokio::test]
async fn update_spending_oracle_rejects_a_non_fungible_base_asset() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    let oracle = h.oracle_id();

    let result = h
        .configure(&update_oracle_script_raw(
            oracle.prefix().as_felt(),
            oracle.suffix(),
            MAX_ORACLE_BLOCK_AGE.into(),
            nft().to_id_word(),
        ))
        .await?;

    assert_transaction_executor_error!(result, ERR_BASE_ASSET_NOT_FUNGIBLE);
    Ok(())
}

#[tokio::test]
async fn unsetting_the_oracle_requires_a_zero_block_age() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    let result = h.configure(&unset_oracle_script(MAX_ORACLE_BLOCK_AGE.into())).await?;

    assert_transaction_executor_error!(result, ERR_MAX_ORACLE_BLOCK_AGE_WITHOUT_ORACLE);
    Ok(())
}

#[tokio::test]
async fn a_limit_cannot_be_set_without_a_base_asset() -> anyhow::Result<()> {
    // No policy: the base asset slot is empty.
    let mut h = Harness::new(None, Some(FIXED_RATE_PROVIDER))?;

    let result = h.configure(&set_limit_script(100_000)).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_REQUIRES_BASE_ASSET);

    // Clearing never needs one.
    h.configure(&set_limit_script(0)).await??;
    Ok(())
}

// INVARIANTS
// ================================================================================================

#[tokio::test]
async fn assets_across_notes_accumulate_within_a_transaction() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    // Two notes of 60_000 USDCX each: 120_000 in one transaction exceeds the limit.
    let result = h.send_many(vec![fungible(usdcx(), 60_000), fungible(usdcx(), 60_000)]).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);

    // Two notes of 30_000 fit and the tracker holds their sum.
    let block = h.latest_block();
    h.send_many(vec![fungible(usdcx(), 30_000), fungible(usdcx(), 30_000)])
        .await??;
    assert_eq!(h.tracker(), tracker_word(60_000, block, 0));
    Ok(())
}

#[tokio::test]
async fn two_assets_in_one_note_are_both_charged() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    let block = h.latest_block();

    // The base asset and a priced asset ride in a single note: 20_000 plus 5 ETH at 3000.
    h.send_bundle(vec![fungible(usdcx(), 20_000), fungible(eth(), 5)]).await??;
    assert_eq!(h.tracker(), tracker_word(20_000 + 5 * ORACLE_RATE, block, 0));

    // The second asset in the note is what pushes the budget over: 35_001 + 66_000.
    let result = h.send_bundle(vec![fungible(usdcx(), 1), fungible(eth(), 22)]).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);
    Ok(())
}

/// Raises the limit and sends 110_000 USDCX in the same transaction. The limit is read from the
/// initial account state, so the raise does not apply to the transaction that makes it.
#[tokio::test]
async fn a_limit_raised_in_the_same_transaction_does_not_apply_to_it() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;

    let target = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE)?;
    let serial_num = Word::from([7u32, 7, 7, 7]);
    let asset = fungible(usdcx(), 110_000);
    let note: Note = P2idNote::builder()
        .sender(h.account.id())
        .target(target)
        .asset(asset)
        .note_type(NoteType::Public)
        .serial_number(serial_num)
        .build()?
        .into();

    let script = compile_tx_script(format!(
        "
        use miden::standards::notes::p2id

        @transaction_script
        pub proc main
            # raise the limit far above the spend below
            push.{new_limit}
            call.::miden::standards::components::auth::multisig_smart::set_spending_limit
            drop

            # send 110_000 USDCX
            push.{serial_num}
            push.{note_type}
            push.{tag}
            push.{target_prefix}
            push.{target_suffix}
            exec.p2id::create_output_note
            # => [note_idx]

            push.{asset_value}
            push.{asset_id}
            call.::miden::standards::wallets::basic::move_asset_to_note
            dropw dropw dropw dropw
        end
        ",
        new_limit = 1_000_000u64,
        note_type = NoteType::Public as u8,
        tag = Felt::from(NoteTag::with_account_target(target)),
        target_prefix = target.prefix().as_felt(),
        target_suffix = target.suffix(),
        asset_value = asset.to_value_word(),
        asset_id = asset.to_id_word(),
    ))?;

    let salt = h.next_salt();
    let builder = h
        .chain
        .build_transaction(h.account.id())
        .expected_output_note(RawOutputNote::Full(note))
        .tx_script(script)
        .multisig_auth_args(MultisigAuthArgs::new(h.latest_block(), salt));
    let result =
        Harness::sign_and_execute(builder, &[0, 1], &h.public_keys, &h.authenticators).await?;

    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);
    Ok(())
}

#[tokio::test]
async fn disabling_and_re_enabling_the_policy_bumps_the_generation_twice() -> anyhow::Result<()> {
    let mut h = Harness::with_policy()?;
    let reject = UncoveredAssetPolicy::Reject.as_u32();

    h.send(fungible(usdcx(), 60_000)).await?;
    assert_eq!(h.config()[2], Felt::from(0u32));

    // N -> 0: disabled, nothing is metered, generation 1.
    h.configure(&update_policy_script(0, reject)).await??;
    assert_eq!(h.config(), Word::from([0u32, reject, 1, 0]));
    h.send(fungible(usdcx(), 500_000)).await?;
    assert_eq!(h.tracker()[0], Felt::new_unchecked(60_000));

    // 0 -> N: enabled again, generation 2, the old tracker is stale and the budget starts over.
    h.configure(&update_policy_script(WINDOW_BLOCKS, reject)).await??;
    assert_eq!(h.config(), Word::from([WINDOW_BLOCKS, reject, 2, 0]));
    let block = h.latest_block();
    h.send(fungible(usdcx(), 70_000)).await?;
    assert_eq!(h.tracker(), tracker_word(70_000, block, 2));
    Ok(())
}
