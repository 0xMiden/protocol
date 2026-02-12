# Format guidebook

A guidebook defining the format of documentation comments and regular comments for `masm` procedures.

## General

Entire procedure doc comment should be created using the `#!` pair of symbols as the commenting sign.

Doc comment for a procedure should have these blocks:

- Procedure description.
- Inputs and outputs.
- Description of the values used in the "Inputs and outputs" block (optional).
- Panic block (optional).
- Invocation hint (optional and will become redundant after the procedure annotations will be implemented).

Each block should be separated from the others with a blank line.

Example:

```masm
#! This procedure is executed somewhere in the execution pipeline. Its responsibility is:
#! 1. Do the first point of this list.
#! 2. Compute some extremely important values which will be used in future.
#! 3. Finally do the actions specified in the third point of this list.
#!
#! Inputs:
#!   Operand stack: [
#!     single_felt,
#!     [felt_1, 0, 0, felt_2],
#!     SOME_WORD,
#!     memory_value_ptr,
#!   ]
#!   Advice stack: [HASH_A, HASH_B, [ARRAY_OF_HASHES]]
#!   Advice map: {
#!      KEY_1: [VALUE_1],
#!      KEY_2: [VALUE_2],
#!   }
#! Outputs:
#!   Operand stack: []
#!   Advice stack: []
#!
#! Where:
#! - single_felt is the ordinary value placed on top of the stack.
#! - SOME_WORD is the word specifying maybe some hash.
#!
#! Panics if:
#! - something went wrong.
#! - some check is failed.
#!
#! Invocation: call
```

## Procedure description

Contains the general information about the purpose of the procedure and the way it works. May contain any other valuable information.

If some list is used for description, it should be formatted like so:

- The description of the list should not have a blank like between it and the list.
- The description of the list should have a colon at the end.
- Depending on what kind of sentences form a list, they should start with a capital letter and end with a period, or start with a lowercase letter and without period at the end.
- List should use a `-` symbol in case of unordered list or arabic numerals for ordered ones (for example, for the description of the execution steps).
- Nested list should follow the same format.

Some data could be formatted as a subparagraph, in that case a blank line should be used to separate them.

Example:

```masm
#! Transaction kernel program.
#!
#! This is the entry point of the transaction kernel, the program will perform the following
#! operations:
#! 1. Run the prologue to prepare the transaction's root context.
#! 2. Run all the notes' scripts.
#! 3. Run the transaction script.
#! 4. Run the epilogue to compute and validate the final state.
#!
#! See `prologue::prepare_transaction` for additional details on the VM's initial state, including 
#! the advice provider.
```

## Inputs and outputs

Each variable could represent a single value or a sequence of four values (a Word). Variable representing a single value should be written in lowercase, and a variable for the word should be written in uppercase.

Example:

```masm
#! Inputs: [single_value, SOME_WORD]
```

Variable, which represents a memory address, should have a `_ptr` suffix in its name. For example, `note_script_commitment_ptr`.

It is strongly not recommended to use a single-letter names for variables, with just an exception for the loop indexes (i.e. `i`). So, for example, instead of `H` a proper `HASH` or even more expanded version like `INIT_HASH` should be used.

### Inputs

Inputs block could contain three components: operand stack, advice stack and advice map. Description of the each container should be offset with two spaces relative to the start of the `Inputs` word. Each name of the container should be separated from its value by the colon (e.g. `Operand stack: [value_1]`).

Operand stack and advice stack should be presented as an array containing some data.

The lines which exceed 100 symbols should be formatted differently, it could be done in two different ways:

1. The line should be broken, and the end of the line should be moved to the new line with an offset such that the first symbol of the first element on the second line should be directly above the first symbol of the first element on the first line (see the value of the `FOREIGN_ACCOUNT_ID` in the example in `Formats` section).
2. The exceeded array should be formatted in a column, forming a Word or some other number of related elements on each line. Each new line should be offset with two spaces relative to the name of the container (see example below).

Example:

```masm
#! Inputs:
#!   Operand stack: []
#!   Advice stack: [
#!     account_id, 0, 0, account_nonce, 
#!     ACCOUNT_VAULT_ROOT, 
#!     ACCOUNT_STORAGE_COMMITMENT, 
#!     ACCOUNT_CODE_COMMITMENT
#!   ]
```

To show that some internal value array could have dynamic length, additional brackets should be used (see the `[VALUE_B]` in the advice stack in the example in `Formats` section).

In case some inputs are presented on the stack only if some condition is satisfied, such inputs should be placed in the "optional" box: inside the parentheses with a question mark at the end. Opening and closing brackets should be placed on a new line with the same offset as the other inputs, and values inside the brackets should be offset by two spaces.

Example:

```masm
#!   ...
#!   Advice stack: [
#!      NOTE_METADATA,
#!      assets_count,
#!      (
#!        block_num,
#!        BLOCK_SUB_COMMITMENT,
#!        NOTE_ROOT,
#!      )?
#!   ]
#!   ...
```

Advice map should be presented as a sequence of the key-value pairs in the curly brackets. Opening bracket should stay on the same line, and the closing bracket should be placed on the next line after the last key-value pair with the same offset as the `Advice map` phrase.

Each pair should start at the new line with additional two spaces offset relative to the start of the `Advice map` phrase. Pairs should be separated with comma. The same formatting rules as to the operand and advice stacks should be applied for the each key-value pair.

### Outputs

Outputs should show the final state of each container, used in the inputs, except for the advice map. Advice map should be specified in the outputs section only if it was modified.

Example:

```masm
#! Inputs:
#!   Operand stack: [OUTPUT_NOTES_COMMITMENT]
#! Outputs:
#!   Operand stack: [OUTPUT_NOTES_COMMITMENT]
#!   Advice map: {
#!      OUTPUT_NOTES_COMMITMENT: [mem[output_note_ptr]...mem[output_notes_end_ptr]],
#!   }
#!
#! Where:
#! - OUTPUT_NOTES_COMMITMENT is the note commitment computed from note's id and metadata.
#! - output_note_ptr is the start boundary of the output notes section.
#! - output_notes_end_ptr is the end boundary of the output notes section.
#! - mem[i] is the memory value stored at some address i.
```

### Formats

#### Full version

In case the values are provided not only through the operand stack, but also through any other container, the full version if the inputs should be used.

Notice that operand stack should be presented in any case, even if it is empty. Other components should be presented only if they have some values used in the describing function.

Example:

```masm
#! Inputs:
#!   Operand stack: []
#!   Advice stack: [VALUE_A, [VALUE_B]]
#!   Advice map: {
#!     FOREIGN_ACCOUNT_ID: [[foreign_account_id, 0, 0, account_nonce], VAULT_ROOT, STORAGE_ROOT, 
#!                          CODE_ROOT],
#!     STORAGE_ROOT: [[STORAGE_SLOT_DATA]],
#!     CODE_ROOT: [num_procs, [ACCOUNT_PROCEDURE_DATA]]
#!   }
#! Outputs:
#!   Operand stack: [value]
#!   Advice stack: []
```

#### Short version

In case the values are provided only through the operand stack, a short version of the inputs and outputs should be used. In that case only `Inputs` and `Outputs` components are used, representing the values on the operand stack.

Input values array should be offset by one space to be inline with the output values array (see the example).

Example:

```masm
#! Inputs:  [single_value, WORD_1]
#! Outputs: [WORD_2] 
```

## Description of the used values

If some value was used in the inputs and outputs block (and its meaning is not obvious) this value should be described.

Values description block should start with `Where` word with a colon at the end. Definitions should be represented as an unordered list constructed with `-` symbols, without any space offset. Each definition should start with the name of the variable followed by the `is/are the` phrase, after which the definition should be placed. At the end of each definition should be a period.

Example:

```masm
#! Where:
#! - tag is the tag to be included in the note.
#! - aux is the auxiliary metadata to be included in the note.
#! - note_type is the storage type of the note.
#! - execution_hint is the note's execution hint.
#! - RECIPIENT is the recipient of the note.
#! - note_idx is the index of the created note.
```

## Panic block

If the describing procedure could potentially panic, a panic block should be specified.

Panic block should start with `Panics if` phrase with a colon at the end. Panic cases should be represented as an unordered list constructed with `-` symbols, without any space offset. Definitions should start with lowercase letter, except for the cases which form the nested list (see example). Each case should end with a period.

Example:

```masm
#! Panics if:
#! - the transaction is not being executed against a faucet.
#! - the invocation of this procedure does not originate from the native account.
#! - the asset being burned is not associated with the faucet the transaction is being executed
#!   against.
#! - the asset is not well formed.
#! - For fungible faucets:
#!   - the amount being burned is greater than the total input to the transaction.
#! - For non-fungible faucets:
#!   - the non-fungible asset being burned does not exist or was not provided as input to the
#!     transaction via a note or the accounts vault.
```

## Invocation hint

Invocation hint is the temporary comment showing how the procedure is meant to be used. It will help to implement the procedure annotations in future.

The hint could show how this procedures is invoked:

- with `exec`
- with `call`/`syscall`
- is not used anywhere

Example:

```masm
#! Invocation: call
```
