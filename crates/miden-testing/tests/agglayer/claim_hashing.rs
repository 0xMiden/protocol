use miden_processor::advice::AdviceInputs;
use miden_processor::{ContextId, StackInputs};
use miden_protocol::{Felt, Hasher, Word};
use miden_testing::executor::CodeExecutor;

#[tokio::test]
async fn claim_advice_map_hashing_matches_rust_and_preserves_caller_state() -> anyhow::Result<()> {
    // Compile the private helper and constants from the note itself, not a duplicate
    // implementation.
    let note = include_str!("../../../miden-agglayer/asm/agglayer/notes/claim.masm");
    let constants =
        note.split_once("# CONSTANTS").unwrap().1.split_once("# NOTE SCRIPT").unwrap().0;
    let helper = &note[note.find("proc write_claim_data_into_advice_map_by_key").unwrap()..];
    let source = format!(
        "use miden::core::crypto::hashes::eidos\ntype AdviceMapKey = word\n{constants}\n{helper}\n\
         begin\n\
             push.0 padw padw padw\n\
             repeat.72 adv_pipe end\n\
             dropw dropw dropw drop\n\
             exec.write_claim_data_into_advice_map_by_key\n\
             mem_storew_le.1024 dropw\n\
             mem_storew_le.1028 dropw\n\
         end"
    );
    // The extra eight Felts include the mint amount and guard the end of the hashed region.
    let memory: Vec<_> = (0..576)
        .map(|i| {
            Felt::new_unchecked(if i % 11 == 0 {
                0xffff_ffff_0000_0000
            } else {
                103 + i * 29
            })
        })
        .collect();
    let caller: Vec<_> = (1..=16).map(Felt::new_unchecked).collect();
    let entries = [
        (Hasher::hash_elements(&memory[..536]), memory[..536].to_vec(), 1024),
        (Hasher::hash_elements(&memory[536..568]), memory[536..568].to_vec(), 1028),
    ];
    let tail = vec![Felt::new_unchecked(101), Felt::new_unchecked(103)];
    let unrelated = (Word::from([Felt::new_unchecked(17); 4]), tail.clone());
    let mut advice_stack = memory.clone();
    advice_stack.extend_from_slice(&tail);
    let advice = AdviceInputs::default()
        .with_stack(advice_stack.into())
        .with_map([unrelated.clone()]);
    let conflicting_advice = advice.clone().with_map([(entries[0].0, vec![Felt::ZERO])]);
    let output = CodeExecutor::with_default_host()
        .stack_inputs(StackInputs::new(&caller)?)
        .extend_advice_inputs(advice)
        .run(&source)
        .await?;

    assert_eq!(output.stack.iter().copied().collect::<Vec<_>>(), caller);
    for (address, &value) in memory.iter().enumerate() {
        assert_eq!(
            output
                .memory
                .read_element(ContextId::root(), Felt::new_unchecked(address as u64))?,
            value
        );
    }
    let mut expected_advice = AdviceInputs::default().with_stack(tail.into()).with_map([unrelated]);
    for (key, values, address) in entries {
        for (i, &value) in key.iter().enumerate() {
            assert_eq!(
                output
                    .memory
                    .read_element(ContextId::root(), Felt::new_unchecked(address + i as u64))?,
                value
            );
        }
        expected_advice = expected_advice.with_map([(key, values)]);
    }
    let (stack, map, store) = output.advice.into_parts();
    assert_eq!(AdviceInputs::new(stack.into_iter().collect(), map, store), expected_advice);

    let error = CodeExecutor::with_default_host()
        .stack_inputs(StackInputs::new(&caller)?)
        .extend_advice_inputs(conflicting_advice)
        .run(&source)
        .await
        .expect_err("a conflicting advice-map entry must be rejected");
    assert!(error.to_string().contains("already present in the advice map"));
    Ok(())
}
