//! Tests for the Array utility `get` and `set` procedures.

use miden_protocol::account::{
    AccountBuilder,
    AccountComponent,
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::{Felt, FieldElement, Word};
use miden_standards::code_builder::CodeBuilder;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{Auth, TransactionContextBuilder};

/// The slot name used for testing the array component.
const TEST_ARRAY_SLOT: &str = "test::array::data";
const TEST_DOUBLE_WORD_ARRAY_SLOT: &str = "test::double_word_array::data";

/// Verify that, given an account component with a storage map to hold the array data,
/// we can use the array utility to:
/// 1. Retrieve the initial value via `get`
/// 2. Update the value via `set`
/// 3. Retrieve the updated value via `get`
#[tokio::test]
async fn test_array_get_and_set() -> anyhow::Result<()> {
    let slot_name = StorageSlotName::new(TEST_ARRAY_SLOT).expect("slot name should be valid");

    let wrapper_component_code = format!(
        r#"
        use miden::core::word
        use miden::standards::data_structures::array
        
        const ARRAY_SLOT_NAME = word("{slot_name}")

        #! Wrapper for array::get that uses exec internally.
        #! Inputs:  [index, pad(15)]
        #! Outputs: [VALUE, pad(12)]
        pub proc test_get
            push.ARRAY_SLOT_NAME[0..2]
            exec.array::get
        end
        
        #! Wrapper for array::set that uses exec internally.
        #! Inputs:  [index, VALUE, pad(11)]
        #! Outputs: [OLD_VALUE, pad(12)]
        pub proc test_set
            push.ARRAY_SLOT_NAME[0..2]
            exec.array::set
        end
        "#,
    );

    // Build the wrapper component by linking against the array library
    let wrapper_library = CodeBuilder::default()
        .compile_component_code("wrapper::component", wrapper_component_code)?;

    // Create the wrapper account component with a storage map to hold the array data
    let initial_value = Word::from([42u32, 42, 42, 42]);
    let wrapper_component = AccountComponent::new(
        wrapper_library.clone(),
        vec![StorageSlot::with_map(
            slot_name.clone(),
            StorageMap::with_entries([(
                Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
                initial_value,
            )])?,
        )],
    )?
    .with_supports_all_types();

    // Build an account with the wrapper component that uses the array utility
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(wrapper_component)
        .build_existing()?;

    // Verify the storage slot exists
    assert!(
        account.storage().get(&slot_name).is_some(),
        "Array data slot should exist in account storage"
    );

    // Transaction script that:
    // 1. Gets the initial value at index 0 (should be [42, 42, 42, 42])
    // 2. Sets index 0 to [43, 43, 43, 43]
    // 3. Gets the updated value at index 0 (should be [43, 43, 43, 43])
    let tx_script_code = r#"
        use wrapper::component->wrapper

        begin
            # Step 1: Get value at index 0 (should return [42, 42, 42, 42])
            push.0
            # => [index, pad(16)]
            call.wrapper::test_get
            # => [VALUE, pad(13)]

            # Verify value is [42, 42, 42, 42]
            push.42.42.42.42
            assert_eqw.err="get(0) should return [42, 42, 42, 42] initially"
            # => [pad(16)] (auto-padding)

            # Step 2: Set value at index 0 to [43, 43, 43, 43]
            push.43.43.43.43
            push.0
            # => [index, VALUE, pad(16)]
            call.wrapper::test_set
            # => [OLD_VALUE, pad(17)]
            dropw
            
            # Step 3: Get value at index 0 (should return [43, 43, 43, 43])
            push.0
            # => [index, pad(17)]
            call.wrapper::test_get
            # => [VALUE, pad(14)]
            
            # Verify value is [43, 43, 43, 43]
            push.43.43.43.43
            assert_eqw.err="get(0) should return [43, 43, 43, 43] after set"
            # => [pad(16)] (auto-padding)
        end
        "#;

    // Compile the transaction script with the wrapper library linked
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(&wrapper_library)?
        .compile_tx_script(tx_script_code)?;

    // Create transaction context and execute
    let tx_context = TransactionContextBuilder::new(account).tx_script(tx_script).build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Verify that the double-word array utility can store and retrieve two words per index.
#[tokio::test]
async fn test_double_word_array_get_and_set() -> anyhow::Result<()> {
    let slot_name =
        StorageSlotName::new(TEST_DOUBLE_WORD_ARRAY_SLOT).expect("slot name should be valid");
    let index = Felt::new(7);

    let wrapper_component_code = format!(
        r#"
        use miden::core::word
        use miden::standards::data_structures::double_word_array

        const ARRAY_SLOT_NAME = word("{slot_name}")

        #! Wrapper for double_word_array::get that uses exec internally.
        #! Inputs:  [index, pad(15)]
        #! Outputs: [VALUE_0, VALUE_1, pad(8)]
        pub proc test_get
            push.ARRAY_SLOT_NAME[0..2]
            exec.double_word_array::get
        end

        #! Wrapper for double_word_array::set that uses exec internally.
        #! Inputs:  [index, VALUE_0, VALUE_1, pad(7)]
        #! Outputs: [OLD_VALUE_0, OLD_VALUE_1, pad(8)]
        pub proc test_set
            push.ARRAY_SLOT_NAME[0..2]
            exec.double_word_array::set
        end
        "#,
    );

    let wrapper_library = CodeBuilder::default()
        .compile_component_code("wrapper::component", wrapper_component_code)?;

    let initial_value_0 = Word::from([1u32, 2, 3, 4]);
    let initial_value_1 = Word::from([5u32, 6, 7, 8]);
    let wrapper_component = AccountComponent::new(
        wrapper_library.clone(),
        vec![StorageSlot::with_map(
            slot_name.clone(),
            StorageMap::with_entries([
                (Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, index]), initial_value_0),
                (Word::from([Felt::ZERO, Felt::ZERO, Felt::ONE, index]), initial_value_1),
            ])?,
        )],
    )?
    .with_supports_all_types();

    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(wrapper_component)
        .build_existing()?;

    assert!(
        account.storage().get(&slot_name).is_some(),
        "Double-word array data slot should exist in account storage"
    );

    let updated_value_0 = Word::from([9u32, 9, 9, 9]);
    let updated_value_1 = Word::from([10u32, 10, 10, 10]);
    let tx_script_code = format!(
        r#"
        use wrapper::component->wrapper

        begin
            # Step 1: Get value at index {index} (should return the initial double-word)
            push.{index}
            call.wrapper::test_get

            push.{initial_value_0}
            assert_eqw.err="get(index) should return initial word 0"

            push.{initial_value_1}
            assert_eqw.err="get(index) should return initial word 1"

            # Step 2: Set the double-word at index {index} to the updated values
            push.{updated_value_1}
            push.{updated_value_0}
            push.{index}
            call.wrapper::test_set
            push.{initial_value_0}
            assert_eqw.err="set(index) should return the original double-word, left word"
            push.{initial_value_1}
            assert_eqw.err="set(index) should return the original double-word, right word"

            # Step 3: Get value at index {index} (should return the updated double-word)
            push.{index}
            call.wrapper::test_get

            push.{updated_value_0}
            assert_eqw.err="get(index) should return the updated double-word, left word"

            push.{updated_value_1}
            assert_eqw.err="get(index) should return the updated double-word, right word"

            repeat.8 drop end
        end
        "#,
    );

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(&wrapper_library)?
        .compile_tx_script(tx_script_code)?;

    let tx_context = TransactionContextBuilder::new(account).tx_script(tx_script).build()?;

    tx_context.execute().await?;

    Ok(())
}
