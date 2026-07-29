use core::fmt;

pub mod trace_capture;
pub mod utils;

/// Indicates the type of the transaction execution benchmark
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutionBenchmark {
    ConsumeSingleP2IDFalcon,
    ConsumeSingleP2IDEcdsa,
    ConsumeTwoP2IDFalcon,
    ConsumeTwoP2IDEcdsa,
    CreateSingleP2IDFalcon,
    CreateSingleP2IDEcdsa,
    ConsumeClaimNoteL1ToMiden,
    ConsumeClaimNoteL2ToMiden,
    ConsumeB2AggNote,
    ConsumeB2AggNotePopulated2p31,
    ConsumeB2AggNotePopulated2p31m1,
    ConsumeP2idNetwork,
    ConsumeP2idMaxAssetsNetwork,
    ConsumeP2ideClaimNetwork,
    ConsumeP2ideMaxAssetsNetwork,
    ConsumeP2ideReclaimNetwork,
    ConsumeSwapPublicPaybackNetwork,
    ConsumeSwapPrivatePaybackNetwork,
    ConsumePswapFullFillNetwork,
    ConsumePswapPartialFillNetwork,
    ConsumeMintFungibleNetwork,
    ConsumeMintNonFungibleNetwork,
    ConsumeBurnNetwork,
    ConsumeFaucetPolicyActionNetwork,
    ConsumePauseActionNetwork,
    ConsumeOwnerActionNetwork,
    ConsumeRbacActionNetwork,
    ConsumeNetworkAccountConfigNetwork,
    ConsumeConstantFeePolicyConfigNetwork,
    ConsumeFeeSponsorshipWithFeatureNetwork,
    ConsumeFeeSponsorshipReclaim,
    ConsumeClaimL1WithFee,
    ConsumeClaimL2WithFee,
    ConsumeB2AggWithFee,
    ConsumeB2AggPopulatedWithFee,
    ConsumeConfigAggBridgeWithFee,
    ConsumeDeregisterAggFaucetWithFee,
    ConsumeUpdateGerWithFee,
    ConsumeRemoveGerWithFee,
}

impl ExecutionBenchmark {
    /// All benchmark scenarios, in the order their results appear in `bench-tx.json`.
    pub const fn all() -> &'static [ExecutionBenchmark] {
        &[
            ExecutionBenchmark::ConsumeSingleP2IDFalcon,
            ExecutionBenchmark::ConsumeSingleP2IDEcdsa,
            ExecutionBenchmark::ConsumeTwoP2IDFalcon,
            ExecutionBenchmark::ConsumeTwoP2IDEcdsa,
            ExecutionBenchmark::CreateSingleP2IDFalcon,
            ExecutionBenchmark::CreateSingleP2IDEcdsa,
            ExecutionBenchmark::ConsumeClaimNoteL1ToMiden,
            ExecutionBenchmark::ConsumeClaimNoteL2ToMiden,
            ExecutionBenchmark::ConsumeB2AggNote,
            ExecutionBenchmark::ConsumeB2AggNotePopulated2p31,
            ExecutionBenchmark::ConsumeB2AggNotePopulated2p31m1,
            ExecutionBenchmark::ConsumeP2idNetwork,
            ExecutionBenchmark::ConsumeP2idMaxAssetsNetwork,
            ExecutionBenchmark::ConsumeP2ideClaimNetwork,
            ExecutionBenchmark::ConsumeP2ideMaxAssetsNetwork,
            ExecutionBenchmark::ConsumeP2ideReclaimNetwork,
            ExecutionBenchmark::ConsumeSwapPublicPaybackNetwork,
            ExecutionBenchmark::ConsumeSwapPrivatePaybackNetwork,
            ExecutionBenchmark::ConsumePswapFullFillNetwork,
            ExecutionBenchmark::ConsumePswapPartialFillNetwork,
            ExecutionBenchmark::ConsumeMintFungibleNetwork,
            ExecutionBenchmark::ConsumeMintNonFungibleNetwork,
            ExecutionBenchmark::ConsumeBurnNetwork,
            ExecutionBenchmark::ConsumeFaucetPolicyActionNetwork,
            ExecutionBenchmark::ConsumePauseActionNetwork,
            ExecutionBenchmark::ConsumeOwnerActionNetwork,
            ExecutionBenchmark::ConsumeRbacActionNetwork,
            ExecutionBenchmark::ConsumeNetworkAccountConfigNetwork,
            ExecutionBenchmark::ConsumeConstantFeePolicyConfigNetwork,
            ExecutionBenchmark::ConsumeFeeSponsorshipWithFeatureNetwork,
            ExecutionBenchmark::ConsumeFeeSponsorshipReclaim,
            ExecutionBenchmark::ConsumeClaimL1WithFee,
            ExecutionBenchmark::ConsumeClaimL2WithFee,
            ExecutionBenchmark::ConsumeB2AggWithFee,
            ExecutionBenchmark::ConsumeB2AggPopulatedWithFee,
            ExecutionBenchmark::ConsumeConfigAggBridgeWithFee,
            ExecutionBenchmark::ConsumeDeregisterAggFaucetWithFee,
            ExecutionBenchmark::ConsumeUpdateGerWithFee,
            ExecutionBenchmark::ConsumeRemoveGerWithFee,
        ]
    }
}

impl fmt::Display for ExecutionBenchmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionBenchmark::ConsumeSingleP2IDFalcon => {
                write!(f, "consume single P2ID note with Falcon signing")
            },
            ExecutionBenchmark::ConsumeSingleP2IDEcdsa => {
                write!(f, "consume single P2ID note with ECDSA signing")
            },
            ExecutionBenchmark::ConsumeTwoP2IDFalcon => {
                write!(f, "consume two P2ID notes with Falcon signing")
            },
            ExecutionBenchmark::ConsumeTwoP2IDEcdsa => {
                write!(f, "consume two P2ID notes with ECDSA signing")
            },
            ExecutionBenchmark::CreateSingleP2IDFalcon => {
                write!(f, "create single P2ID note with Falcon signing")
            },
            ExecutionBenchmark::CreateSingleP2IDEcdsa => {
                write!(f, "create single P2ID note with ECDSA signing")
            },
            ExecutionBenchmark::ConsumeClaimNoteL1ToMiden => {
                write!(f, "consume CLAIM note (L1 to Miden)")
            },
            ExecutionBenchmark::ConsumeClaimNoteL2ToMiden => {
                write!(f, "consume CLAIM note (L2 to Miden)")
            },
            ExecutionBenchmark::ConsumeB2AggNote => {
                write!(f, "consume B2AGG note (bridge-out)")
            },
            ExecutionBenchmark::ConsumeB2AggNotePopulated2p31 => {
                write!(f, "consume B2AGG note (bridge-out, 2^31 leaves)")
            },
            ExecutionBenchmark::ConsumeB2AggNotePopulated2p31m1 => {
                write!(f, "consume B2AGG note (bridge-out, 2^31-1 leaves)")
            },
            ExecutionBenchmark::ConsumeP2idNetwork => {
                write!(f, "consume P2ID note (network account)")
            },
            ExecutionBenchmark::ConsumeP2idMaxAssetsNetwork => {
                write!(f, "consume P2ID note (16 assets, network account)")
            },
            ExecutionBenchmark::ConsumeP2ideClaimNetwork => {
                write!(f, "consume P2IDE note (claim, network account)")
            },
            ExecutionBenchmark::ConsumeP2ideMaxAssetsNetwork => {
                write!(f, "consume P2IDE note (claim, 16 assets, network account)")
            },
            ExecutionBenchmark::ConsumeP2ideReclaimNetwork => {
                write!(f, "consume P2IDE note (reclaim, network account)")
            },
            ExecutionBenchmark::ConsumeSwapPublicPaybackNetwork => {
                write!(f, "consume SWAP note (public payback, network account)")
            },
            ExecutionBenchmark::ConsumeSwapPrivatePaybackNetwork => {
                write!(f, "consume SWAP note (private payback, network account)")
            },
            ExecutionBenchmark::ConsumePswapFullFillNetwork => {
                write!(f, "consume PSWAP note (full fill, network account)")
            },
            ExecutionBenchmark::ConsumePswapPartialFillNetwork => {
                write!(f, "consume PSWAP note (partial fill, network account)")
            },
            ExecutionBenchmark::ConsumeMintFungibleNetwork => {
                write!(f, "consume MINT note (fungible faucet, network account)")
            },
            ExecutionBenchmark::ConsumeMintNonFungibleNetwork => {
                write!(f, "consume MINT note (non-fungible faucet, network account)")
            },
            ExecutionBenchmark::ConsumeBurnNetwork => {
                write!(f, "consume BURN note (network account)")
            },
            ExecutionBenchmark::ConsumeFaucetPolicyActionNetwork => {
                write!(f, "consume FAUCET_POLICY_ACTION note (network account)")
            },
            ExecutionBenchmark::ConsumePauseActionNetwork => {
                write!(f, "consume PAUSE_ACTION note (network account)")
            },
            ExecutionBenchmark::ConsumeOwnerActionNetwork => {
                write!(f, "consume OWNER_ACTION note (network account)")
            },
            ExecutionBenchmark::ConsumeRbacActionNetwork => {
                write!(f, "consume RBAC_ACTION note (network account)")
            },
            ExecutionBenchmark::ConsumeNetworkAccountConfigNetwork => {
                write!(f, "consume NETWORK_ACCOUNT_CONFIG note (network account)")
            },
            ExecutionBenchmark::ConsumeConstantFeePolicyConfigNetwork => {
                write!(f, "consume CONSTANT_FEE_POLICY_CONFIG note (network account)")
            },
            ExecutionBenchmark::ConsumeFeeSponsorshipWithFeatureNetwork => {
                write!(f, "consume FEE_SPONSORSHIP note with feature note (network account)")
            },
            ExecutionBenchmark::ConsumeFeeSponsorshipReclaim => {
                write!(f, "consume FEE_SPONSORSHIP note (reclaim)")
            },
            ExecutionBenchmark::ConsumeClaimL1WithFee => {
                write!(f, "consume CLAIM note (L1 to Miden, with fee payment)")
            },
            ExecutionBenchmark::ConsumeClaimL2WithFee => {
                write!(f, "consume CLAIM note (L2 to Miden, with fee payment)")
            },
            ExecutionBenchmark::ConsumeB2AggWithFee => {
                write!(f, "consume B2AGG note (bridge-out, with fee payment)")
            },
            ExecutionBenchmark::ConsumeB2AggPopulatedWithFee => {
                write!(f, "consume B2AGG note (bridge-out, 2^31-1 leaves, with fee payment)")
            },
            ExecutionBenchmark::ConsumeConfigAggBridgeWithFee => {
                write!(f, "consume CONFIG_AGG_BRIDGE note (with fee payment)")
            },
            ExecutionBenchmark::ConsumeDeregisterAggFaucetWithFee => {
                write!(f, "consume DEREGISTER_AGG_FAUCET note (with fee payment)")
            },
            ExecutionBenchmark::ConsumeUpdateGerWithFee => {
                write!(f, "consume UPDATE_GER note (with fee payment)")
            },
            ExecutionBenchmark::ConsumeRemoveGerWithFee => {
                write!(f, "consume REMOVE_GER note (with fee payment)")
            },
        }
    }
}
