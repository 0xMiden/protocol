use miden_core::Felt;
use miden_core::field::PrimeField64;
use miden_core::mast::MastNodeExt;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::{CoreLibrary, ProtocolLib, Word};
use miden_protocol::assembly::Library;
use miden_standards::StandardsLib;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::MockChain;
use miden_tx::{MastForestStore, TransactionMastStore};

fn matches(word: &Word, target: [u64; 4], target_rev: [u64; 4]) -> bool {
    let elems: [u64; 4] = word.map(|felt| felt.as_canonical_u64());
    elems == target || elems == target_rev
}

fn scan_forest(
    label: &str,
    forest: &miden_protocol::assembly::mast::MastForest,
    target: [u64; 4],
    target_rev: [u64; 4],
) {
    let mut hit = false;
    for (idx, node) in forest.nodes().iter().enumerate() {
        if matches(&node.digest(), target, target_rev) {
            let kind = match node {
                miden_core::mast::MastNode::Block(_) => "block",
                miden_core::mast::MastNode::Join(_) => "join",
                miden_core::mast::MastNode::Split(_) => "split",
                miden_core::mast::MastNode::Loop(_) => "loop",
                miden_core::mast::MastNode::Call(_) => "call",
                miden_core::mast::MastNode::Dyn(_) => "dyn",
                miden_core::mast::MastNode::External(_) => "external",
            };
            let node_id = miden_core::mast::MastNodeId::from(idx as u32);
            let is_proc_root = forest.is_procedure_root(node_id);
            println!("{label}: node_id={idx} kind={kind} proc_root={is_proc_root}");
            hit = true;
        }
    }

    if hit {
        let digest = Word::from([
            Felt::new(target[0]),
            Felt::new(target[1]),
            Felt::new(target[2]),
            Felt::new(target[3]),
        ]);
        let mast_store = TransactionMastStore::new();
        println!("{label}: mast_store_has_digest={}", mast_store.get(&digest).is_some());
        if let Some(name) = forest.procedure_name(&digest) {
            println!("{label}: procedure_name={name}");
        }
        for (root, name) in forest.procedure_names() {
            if matches(&root, target, target_rev) {
                println!("{label}: procedure_names match={name}");
            }
        }
    }
}

fn scan_library_exports(label: &str, lib: &Library, target: [u64; 4], target_rev: [u64; 4]) {
    for export in lib.exports().filter_map(|export| export.as_procedure()) {
        let digest = lib.mast_forest()[export.node].digest();
        if matches(&digest, target, target_rev) {
            println!("{label}: export match path={}", export.path);
        }
    }
}

fn main() {
    let target: [u64; 4] = [
        4410162016693140613,
        9339813725324401356,
        16470561989268149228,
        1688422771219118252,
    ];
    let target_rev: [u64; 4] = [target[3], target[2], target[1], target[0]];

    let mut builder = MockChain::builder();

    let fungible_asset_0_double_amount = Asset::Fungible(
        FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).expect("id should be valid"),
            10,
        )
        .expect("fungible_asset_0 is invalid"),
    );

    let fungible_asset_0 = Asset::Fungible(
        FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).expect("id should be valid"),
            5,
        )
        .expect("fungible_asset_0 is invalid"),
    );
    let fungible_asset_1 = Asset::Fungible(
        FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).expect("id should be valid"),
            10,
        )
        .expect("fungible_asset_1 is invalid"),
    );

    let account = builder
        .add_existing_wallet_with_assets(
            miden_testing::Auth::BasicAuth,
            [fungible_asset_0_double_amount, fungible_asset_1],
        )
        .expect("failed to add account");

    let p2id_note_0_assets = builder
        .add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[],
            NoteType::Public,
        )
        .expect("note 0");
    let p2id_note_1_asset = builder
        .add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[fungible_asset_0],
            NoteType::Public,
        )
        .expect("note 1");
    let p2id_note_2_assets = builder
        .add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[fungible_asset_0, fungible_asset_1],
            NoteType::Public,
        )
        .expect("note 2");

    let _mock_chain = builder.build().expect("build mock chain");

    let code = r#"
        use miden::protocol::input_note

        begin
            push.0
            exec.input_note::get_inputs_info
            dropw drop
        end
    "#;

    let tx_script = CodeBuilder::default()
        .compile_tx_script(code)
        .expect("failed to compile tx script");

    let forests = [
        ("tx_script", tx_script.mast()),
        ("note_0_script", p2id_note_0_assets.script().mast()),
        ("note_1_script", p2id_note_1_asset.script().mast()),
        ("note_2_script", p2id_note_2_assets.script().mast()),
        ("account_code", account.code().mast()),
        ("kernel", TransactionKernel::kernel().mast_forest().clone()),
        ("kernel_lib", TransactionKernel::library().mast_forest().clone()),
        ("core_lib", CoreLibrary::default().mast_forest().clone()),
        ("protocol_lib", ProtocolLib::default().mast_forest().clone()),
        ("standards_lib", StandardsLib::default().mast_forest().clone()),
    ];

    for (label, forest) in forests {
        scan_forest(label, &forest, target, target_rev);
    }

    scan_library_exports(
        "standards_lib",
        StandardsLib::default().as_ref(),
        target,
        target_rev,
    );
}
