//! Spending-limit tests for [`AuthMultisigSmart`].
//!
//! Every fungible asset a transaction sends out is charged to the budget of its faucet and, when
//! the oracle can price it, to the combined budget in the base asset. The budgets are enforced
//! after the signature check, so the probe execution clients use to obtain the summary stops at
//! the unauthorized event as usual and a spend over any budget fails in the signed execution with
//! the spending-limit error.

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
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionScript};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::account::auth::multisig_smart::{
    CombinedSpendingLimit,
    ProcedurePolicy,
    SpendingLimitsPolicy,
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
    ERR_COMBINED_LIMIT_REQUIRES_ORACLE,
    ERR_FAUCET_ID_ZERO,
    ERR_MAX_ORACLE_BLOCK_AGE_ZERO,
    ERR_SPENDING_LIMIT_EXCEEDED,
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

/// Per-faucet limit on the USDC-like asset.
const USDC_LIMIT: u64 = 80_000;

/// Combined limit, denominated in the USDCX-like base asset.
const COMBINED_LIMIT: u64 = 100_000;

/// Blocks a transaction stays includable after reading the oracle.
const MAX_ORACLE_BLOCK_AGE: u16 = 32;

/// Rate the test oracle quotes for every pair: 3000 base units per unit of the source asset.
const ORACLE_RATE: u64 = 3_000;

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

/// The asset with a per-faucet limit.
fn usdc() -> AccountId {
    faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
}

/// An asset without a per-faucet limit, priced by the oracle.
fn eth() -> AccountId {
    faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)
}

/// The base asset of the combined budget.
fn usdcx() -> AccountId {
    faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)
}

/// An asset no budget covers.
fn exotic() -> AccountId {
    faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3)
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

/// A policy with the USDC per-faucet limit and the default `reject` for uncovered assets.
fn faucet_limit_policy() -> SpendingLimitsPolicy {
    SpendingLimitsPolicy::new(NonZeroU32::new(WINDOW_BLOCKS).unwrap())
        .with_faucet_limits(vec![(usdc(), nonzero(USDC_LIMIT))])
        .expect("policy should be valid")
}

/// Adds the combined limit, converting through the given oracle account into USDCX.
fn with_combined_limit(policy: SpendingLimitsPolicy, oracle: AccountId) -> SpendingLimitsPolicy {
    policy.with_combined_limit(
        CombinedSpendingLimit::new(
            oracle,
            AssetId::new_fungible(usdcx()),
            NonZeroU16::new(MAX_ORACLE_BLOCK_AGE).unwrap(),
            nonzero(COMBINED_LIMIT),
        )
        .expect("combined limit should be valid"),
    )
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
    proc_policies: Vec<(Word, ProcedurePolicy)>,
) -> anyhow::Result<Account> {
    let approvers: Vec<_> = public_keys.iter().map(Approver::from).collect();
    let approver_set = ApproverSet::new(approvers, threshold)?;
    let mut config =
        AuthMultisigSmartConfig::new(approver_set).with_proc_policies(proc_policies)?;
    if let Some(policy) = policy {
        config = config.with_spending_limits_policy(policy);
    }

    let assets = [
        fungible(usdc(), 1_000_000),
        fungible(eth(), 1_000),
        fungible(usdcx(), 1_000_000),
        fungible(exotic(), 1_000),
        nft(),
    ];

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
    oracle: Option<Account>,
    salt_seed: u8,
}

impl Harness {
    /// A 2-of-2 multisig with the given spending-limit policy and, optionally, an oracle account
    /// dispatching to the named rate provider. With an oracle, the policy gains the combined limit.
    fn new(
        policy: Option<SpendingLimitsPolicy>,
        oracle_provider: Option<&str>,
        proc_policies: Vec<(Word, ProcedurePolicy)>,
    ) -> anyhow::Result<Self> {
        let (_secret_keys, _schemes, public_keys, authenticators) =
            setup_keys_and_authenticators_with_scheme(2, 2, AuthScheme::EcdsaK256Keccak)?;

        let oracle = oracle_provider.map(oracle_account).transpose()?;
        let policy = match (&policy, &oracle) {
            (Some(policy), Some(oracle)) => Some(with_combined_limit(policy.clone(), oracle.id())),
            _ => policy,
        };
        let account = multisig_account(2, &public_keys, policy, proc_policies)?;

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
        let builder = match &self.oracle {
            Some(oracle) => {
                builder.foreign_accounts([self.chain.get_foreign_account_inputs(oracle.id())?])
            },
            None => builder,
        };
        let result =
            Self::sign_and_execute(builder, &[0, 1], &self.public_keys, &self.authenticators)
                .await?;
        if let Ok(tx) = &result {
            self.commit(tx)?;
        }
        Ok(result)
    }

    fn config(&self) -> Word {
        self.account
            .storage()
            .get_item(AuthMultisigSmart::spending_config_slot())
            .expect("spending config slot should be present")
    }

    /// Builds a transaction sending `asset` in one P2ID note, bound to `reference_block` (or the
    /// latest block), probe-executes it to obtain the summary, signs it with the given approvers
    /// and executes for real. A successful transaction is applied to the account and sealed into a
    /// block; a spend the budgets reject comes back as the spending-limit error.
    async fn send_signed(
        &mut self,
        asset: Asset,
        signers: &[usize],
        reference_block: Option<BlockNumber>,
    ) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
        let salt = self.next_salt();
        let result = self.run_send(asset, salt, signers, reference_block).await?;
        if let Ok(tx) = &result {
            self.commit(tx)?;
        }
        Ok(result)
    }

    /// Sends `asset` with both approvers signing and expects success.
    async fn send(&mut self, asset: Asset) -> anyhow::Result<ExecutedTransaction> {
        Ok(self.send_signed(asset, &[0, 1], None).await??)
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

    async fn run_send(
        &self,
        asset: Asset,
        salt: Word,
        signers: &[usize],
        reference_block: Option<BlockNumber>,
    ) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
        self.run_send_notes(vec![asset], salt, signers, reference_block).await
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
        if let Some(oracle) = &self.oracle {
            builder =
                builder.foreign_accounts([self.chain.get_foreign_account_inputs(oracle.id())?]);
        }

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

    fn tracker(&self, faucet_id: Option<AccountId>) -> Word {
        let key = match faucet_id {
            Some(faucet_id) => SpendingLimitsPolicy::faucet_key(faucet_id),
            None => SpendingLimitsPolicy::combined_budget_key(),
        };
        self.account
            .storage()
            .get_map_item(AuthMultisigSmart::spending_trackers_slot(), key)
            .expect("spending trackers slot should be present")
    }

    fn limit(&self, faucet_id: AccountId) -> Word {
        self.account
            .storage()
            .get_map_item(
                AuthMultisigSmart::spending_limits_slot(),
                SpendingLimitsPolicy::faucet_key(faucet_id),
            )
            .expect("spending limits slot should be present")
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

// PER-FAUCET BUDGET
// ================================================================================================

#[tokio::test]
async fn spend_within_the_faucet_limit_is_allowed_and_tracked() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;
    let block = h.latest_block();

    h.send(fungible(usdc(), 50_000)).await?;

    assert_eq!(h.tracker(Some(usdc())), tracker_word(50_000, block, 0));
    Ok(())
}

#[tokio::test]
async fn spend_over_the_faucet_limit_fails_even_with_every_signature() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    let result = h.send_signed(fungible(usdc(), USDC_LIMIT + 1), &[0, 1], None).await?;

    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);
    Ok(())
}

#[tokio::test]
async fn spend_exactly_at_the_faucet_limit_is_allowed() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    h.send(fungible(usdc(), USDC_LIMIT)).await?;

    Ok(())
}

#[tokio::test]
async fn spends_accumulate_within_a_window_and_reset_after_it() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    h.send(fungible(usdc(), 50_000)).await?;

    // 50_000 + 40_000 exceeds the limit inside the same window.
    let result = h.send_signed(fungible(usdc(), 40_000), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);

    // The next window starts from zero.
    let next_window_block = (window_index(h.latest_block()) + 1) * WINDOW_BLOCKS;
    h.chain.prove_until_block(next_window_block)?;
    h.send(fungible(usdc(), 40_000)).await?;

    let block = h.latest_block();
    assert_eq!(window_index(block), window_index(BlockNumber::from(next_window_block)));
    assert_eq!(h.tracker(Some(usdc())), tracker_word(40_000, block, 0));
    Ok(())
}

#[tokio::test]
async fn an_older_reference_block_does_not_release_budget() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    // Spend in window N, then move into window N+1 and spend again.
    let window_n_block = h.latest_block();
    h.send(fungible(usdc(), 50_000)).await?;
    let next_window_block = (window_index(window_n_block) + 1) * WINDOW_BLOCKS;
    h.chain.prove_until_block(next_window_block)?;
    h.send(fungible(usdc(), 40_000)).await?;

    // A transaction referencing a block back in window N finds the tracker ahead of it and keeps
    // charging window N+1: 40_000 + 70_000 exceeds the limit, no budget was released.
    let result = h.send_signed(fungible(usdc(), 70_000), &[0, 1], Some(window_n_block)).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);
    Ok(())
}

#[tokio::test]
async fn a_disabled_policy_does_not_meter() -> anyhow::Result<()> {
    let mut h = Harness::new(None, None, vec![])?;

    h.send(fungible(usdc(), 500_000)).await?;

    assert_eq!(h.tracker(Some(usdc())), Word::empty());
    Ok(())
}

#[rstest]
#[case::reject(UncoveredAssetPolicy::Reject)]
#[case::allow(UncoveredAssetPolicy::Allow)]
#[tokio::test]
async fn an_asset_no_budget_covers_falls_to_the_policy(
    #[case] uncovered: UncoveredAssetPolicy,
) -> anyhow::Result<()> {
    let policy = faucet_limit_policy().with_uncovered_assets(uncovered);
    let mut h = Harness::new(Some(policy), None, vec![])?;

    let result = h.send_signed(fungible(exotic(), 1), &[0, 1], None).await?;

    match uncovered {
        UncoveredAssetPolicy::Reject => {
            assert_transaction_executor_error!(result, ERR_UNCOVERED_ASSET_REJECTED);
        },
        UncoveredAssetPolicy::Allow => {
            result?;
            assert_eq!(h.tracker(Some(exotic())), Word::empty());
        },
        _ => unreachable!("the policy has two variants"),
    }
    Ok(())
}

#[tokio::test]
async fn non_fungible_assets_are_not_metered() -> anyhow::Result<()> {
    // `reject` for uncovered assets, no budget for the NFT faucet: the send still goes through.
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    h.send(nft()).await?;

    Ok(())
}

#[tokio::test]
async fn spending_limits_leave_the_signature_threshold_unchanged() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    // One of two signatures: within the limit, still unauthorized.
    let result = h.send_signed(fungible(usdc(), 1_000), &[0], None).await?;
    result.unwrap_err().unwrap_unauthorized_err();

    Ok(())
}

// COMBINED BUDGET
// ================================================================================================

#[tokio::test]
async fn the_base_asset_is_charged_one_to_one_without_the_oracle() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), Some("fixed_rate_3000"), vec![])?;
    // Drop the oracle from the transaction inputs: the base asset must not need it.
    h.oracle = None;
    let block = h.latest_block();

    h.send(fungible(usdcx(), 60_000)).await?;

    assert_eq!(h.tracker(None), tracker_word(60_000, block, 0));
    Ok(())
}

#[tokio::test]
async fn other_assets_are_converted_through_the_oracle() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), Some("fixed_rate_3000"), vec![])?;
    let block = h.latest_block();

    h.send(fungible(eth(), 10)).await?;

    assert_eq!(h.tracker(None), tracker_word(10 * ORACLE_RATE, block, 0));
    // ETH has no per-faucet budget, so nothing is tracked under its own key.
    assert_eq!(h.tracker(Some(eth())), Word::empty());
    Ok(())
}

#[tokio::test]
async fn the_combined_budget_accumulates_across_assets() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), Some("fixed_rate_3000"), vec![])?;

    h.send(fungible(usdcx(), 60_000)).await?;
    h.send(fungible(eth(), 10)).await?;

    // 60_000 + 30_000 + 15_000 exceeds the combined limit.
    let result = h.send_signed(fungible(eth(), 5), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);
    Ok(())
}

#[tokio::test]
async fn both_budgets_have_to_allow_a_spend() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), Some("fixed_rate_3000"), vec![])?;

    // 50_000 USDC fits its own limit and charges the combined budget at 3000x.
    let result = h.send_signed(fungible(usdc(), 50_000), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);

    // 30 USDC is 90_000 in the base asset: fine for both budgets.
    h.send(fungible(usdc(), 30)).await?;
    assert_eq!(h.tracker(Some(usdc()))[0], Felt::new_unchecked(30));
    assert_eq!(h.tracker(None)[0], Felt::new_unchecked(30 * ORACLE_RATE));
    Ok(())
}

#[rstest]
#[case::reject(UncoveredAssetPolicy::Reject)]
#[case::allow(UncoveredAssetPolicy::Allow)]
#[tokio::test]
async fn an_unpriced_asset_falls_to_the_policy(
    #[case] uncovered: UncoveredAssetPolicy,
) -> anyhow::Result<()> {
    let policy = faucet_limit_policy().with_uncovered_assets(uncovered);
    let mut h = Harness::new(Some(policy), Some("unpriced"), vec![])?;

    let result = h.send_signed(fungible(eth(), 10), &[0, 1], None).await?;

    match uncovered {
        UncoveredAssetPolicy::Reject => {
            assert_transaction_executor_error!(result, ERR_UNCOVERED_ASSET_REJECTED);
        },
        UncoveredAssetPolicy::Allow => {
            result?;
            assert_eq!(h.tracker(None), Word::empty());
        },
        _ => unreachable!("the policy has two variants"),
    }
    Ok(())
}

#[tokio::test]
async fn reading_the_oracle_tightens_the_expiration() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), Some("fixed_rate_3000"), vec![])?;
    let reference_block = h.latest_block();

    let tx = h.send(fungible(eth(), 1)).await?;

    assert_eq!(tx.expiration_block_num(), reference_block + u32::from(MAX_ORACLE_BLOCK_AGE));
    Ok(())
}

#[tokio::test]
async fn a_priced_spend_without_the_oracle_account_fails() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), Some("fixed_rate_3000"), vec![])?;
    h.oracle = None;

    let result = h.send_signed(fungible(eth(), 1), &[0, 1], None).await?;

    assert!(result.is_err(), "the foreign call must fail without the oracle inputs");
    Ok(())
}

// CONFIGURATION
// ================================================================================================

/// Pushes `set_faucet_spending_limit`'s inputs in reverse and drops them again after the call,
/// since `call.` does not consume the caller's stack.
fn set_faucet_limit_script(faucet_id: AccountId, limit: u64) -> String {
    format!(
        "
        @transaction_script
        pub proc main
            push.{limit}
            push.{prefix}
            push.{suffix}
            call.::miden::standards::components::auth::multisig_smart::set_faucet_spending_limit
            drop drop drop
        end
        ",
        prefix = faucet_id.prefix().as_felt(),
        suffix = faucet_id.suffix(),
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
    update_oracle_script_raw(oracle_id, max_block_age, Word::from(base_asset))
}

fn update_oracle_script_raw(oracle_id: AccountId, max_block_age: u32, base_asset: Word) -> String {
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
        ",
        prefix = oracle_id.prefix().as_felt(),
        suffix = oracle_id.suffix(),
    )
}

fn set_combined_limit_script(limit: u64) -> String {
    format!(
        "
        @transaction_script
        pub proc main
            push.{limit}
            call.::miden::standards::components::auth::multisig_smart::set_combined_spending_limit
            drop
        end
        "
    )
}

#[tokio::test]
async fn set_faucet_spending_limit_writes_and_clears_the_entry() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    h.configure(&set_faucet_limit_script(eth(), 500)).await??;
    assert_eq!(h.limit(eth()), Word::from([500u32, 0, 0, 0]));

    // The new limit applies from the next transaction on.
    let result = h.send_signed(fungible(eth(), 501), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);

    h.configure(&set_faucet_limit_script(eth(), 0)).await??;
    assert_eq!(h.limit(eth()), Word::empty());
    Ok(())
}

#[tokio::test]
async fn changing_the_window_length_resets_the_trackers() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    h.send(fungible(usdc(), 50_000)).await?;

    // Re-saving the same window length keeps the running total.
    h.configure(&update_policy_script(WINDOW_BLOCKS, UncoveredAssetPolicy::Reject.as_u32()))
        .await??;
    let result = h.send_signed(fungible(usdc(), 40_000), &[0, 1], None).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);

    // A different window length bumps the generation and the total starts over.
    h.configure(&update_policy_script(WINDOW_BLOCKS * 2, UncoveredAssetPolicy::Reject.as_u32()))
        .await??;
    h.send(fungible(usdc(), 40_000)).await?;
    assert_eq!(h.tracker(Some(usdc()))[0], Felt::new_unchecked(40_000));
    assert_eq!(h.tracker(Some(usdc()))[2], Felt::from(1u32));
    Ok(())
}

#[tokio::test]
async fn update_spending_limits_policy_rejects_an_invalid_uncovered_policy() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    let result = h.configure(&update_policy_script(WINDOW_BLOCKS, 2)).await?;

    assert_transaction_executor_error!(result, ERR_UNCOVERED_ASSET_POLICY_INVALID);
    Ok(())
}

#[tokio::test]
async fn update_spending_oracle_rejects_a_zero_block_age() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    let result = h
        .configure(&update_oracle_script(usdcx(), 0, AssetId::new_fungible(usdcx())))
        .await?;

    assert_transaction_executor_error!(result, ERR_MAX_ORACLE_BLOCK_AGE_ZERO);
    Ok(())
}

// INVARIANTS
// ================================================================================================

#[tokio::test]
async fn assets_of_one_faucet_across_notes_accumulate_within_a_transaction() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    // Two notes of 50_000 USDC each: 100_000 in one transaction exceeds the 80_000 limit.
    let result = h.send_many(vec![fungible(usdc(), 50_000), fungible(usdc(), 50_000)]).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);

    // Two notes of 30_000 fit and the tracker holds their sum.
    let block = h.latest_block();
    h.send_many(vec![fungible(usdc(), 30_000), fungible(usdc(), 30_000)]).await??;
    assert_eq!(h.tracker(Some(usdc())), tracker_word(60_000, block, 0));
    Ok(())
}

/// Raises the USDC limit and sends 90_000 USDC in the same transaction. The limit is read from
/// the initial account state, so the raise does not apply to the transaction that makes it.
#[tokio::test]
async fn a_limit_raised_in_the_same_transaction_does_not_apply_to_it() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    let target = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE)?;
    let serial_num = Word::from([7u32, 7, 7, 7]);
    let asset = fungible(usdc(), 90_000);
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
            # raise the USDC limit far above the spend below
            push.{new_limit}
            push.{usdc_prefix}
            push.{usdc_suffix}
            call.::miden::standards::components::auth::multisig_smart::set_faucet_spending_limit
            drop drop drop

            # send 90_000 USDC
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
        usdc_prefix = usdc().prefix().as_felt(),
        usdc_suffix = usdc().suffix(),
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
async fn a_combined_limit_cannot_be_set_without_an_oracle() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    let result = h.configure(&set_combined_limit_script(100_000)).await?;
    assert_transaction_executor_error!(result, ERR_COMBINED_LIMIT_REQUIRES_ORACLE);

    // Clearing never needs one.
    h.configure(&set_combined_limit_script(0)).await??;
    Ok(())
}

#[tokio::test]
async fn update_spending_oracle_rejects_a_non_fungible_base_asset() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    let result = h
        .configure(&update_oracle_script_raw(
            usdcx(),
            MAX_ORACLE_BLOCK_AGE.into(),
            nft().to_id_word(),
        ))
        .await?;

    assert_transaction_executor_error!(result, ERR_BASE_ASSET_NOT_FUNGIBLE);
    Ok(())
}

#[tokio::test]
async fn set_faucet_spending_limit_rejects_the_combined_budget_key() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;

    // A zero faucet id would address the combined budget and skip its oracle check.
    let script = "
        @transaction_script
        pub proc main
            push.100000 push.0 push.0
            call.::miden::standards::components::auth::multisig_smart::set_faucet_spending_limit
            drop drop drop
        end
        ";
    let result = h.configure(script).await?;

    assert_transaction_executor_error!(result, ERR_FAUCET_ID_ZERO);
    Ok(())
}

#[tokio::test]
async fn two_faucets_in_one_note_are_each_charged_to_their_own_budget() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), Some("fixed_rate_3000"), vec![])?;
    let block = h.latest_block();

    // USDC has its own budget, ETH only the combined one; both ride in a single note.
    h.send_bundle(vec![fungible(usdc(), 20), fungible(eth(), 5)]).await??;

    assert_eq!(h.tracker(Some(usdc())), tracker_word(20, block, 0));
    assert_eq!(h.tracker(Some(eth())), Word::empty());
    // Combined: 20 USDC at 3000 plus 5 ETH at 3000.
    assert_eq!(h.tracker(None), tracker_word(25 * ORACLE_RATE, block, 0));

    // The second asset in the note is what pushes the combined budget over.
    let result = h.send_bundle(vec![fungible(usdc(), 1), fungible(eth(), 10)]).await?;
    assert_transaction_executor_error!(result, ERR_SPENDING_LIMIT_EXCEEDED);
    Ok(())
}

#[tokio::test]
async fn disabling_and_re_enabling_the_policy_bumps_the_generation_twice() -> anyhow::Result<()> {
    let mut h = Harness::new(Some(faucet_limit_policy()), None, vec![])?;
    let reject = UncoveredAssetPolicy::Reject.as_u32();

    h.send(fungible(usdc(), 50_000)).await?;
    assert_eq!(h.config()[2], Felt::from(0u32));

    // N -> 0: disabled, nothing is metered, generation 1.
    h.configure(&update_policy_script(0, reject)).await??;
    assert_eq!(h.config(), Word::from([0u32, reject, 1, 0]));
    h.send(fungible(usdc(), 500_000)).await?;
    assert_eq!(h.tracker(Some(usdc()))[0], Felt::new_unchecked(50_000));

    // 0 -> N: enabled again, generation 2, the old tracker is stale and the budget starts over.
    h.configure(&update_policy_script(WINDOW_BLOCKS, reject)).await??;
    assert_eq!(h.config(), Word::from([WINDOW_BLOCKS, reject, 2, 0]));
    let block = h.latest_block();
    h.send(fungible(usdc(), 70_000)).await?;
    assert_eq!(h.tracker(Some(usdc())), tracker_word(70_000, block, 2));
    Ok(())
}
