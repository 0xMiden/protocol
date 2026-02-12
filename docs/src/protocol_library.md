---
sidebar_position: 8
---

# Miden Protocol Library

The Miden protocol library provides a set of procedures that wrap transaction kernel procedures to provide a more convenient interface for common operations. These can be invoked by account code, note scripts, and transaction scripts, though some have restriction from where they can be called. The procedures are organized into modules corresponding to different functional areas.

## Contexts

Here and in other places we use the notion of _active account_: it is the account which is currently being accessed.

The Miden VM contexts from which procedures can be called are:

- **Account**: Can only be called from native or foreign accounts.
  - **Native**: Can only be called when the active account is the native account.
  - **Auth**: Can only be called from the authentication procedure. Since it is called on the native account, it implies **Native** and **Account**.
  - **Faucet**: Can only be called when the active account is a faucet.
- **Note**: Can only be called from a note script.
- **Any**: Can be called from any context.

If a procedure has multiple context requirements they are combined using `&`. For instance, "Native & Account" means the procedure can only be called when the active account is the native one _and_ only from the account context.

## Implementation

Most procedures in the Miden protocol library are implemented as wrappers around underlying kernel procedures. They handle the necessary stack padding and cleanup operations required by the kernel interface, providing a more convenient API for developers.

The procedures maintain the same security and context restrictions as the underlying kernel procedures. When invoking these procedures, ensure that the calling context matches the requirements.

## Active account Procedures (`miden::protocol::active_account`)

Active account procedures can be used to read from storage, fetch or compute commitments or obtain other internal data of the active account. 

| Procedure                        | Description                   | Context                       |
| -------------------------------- | ----------------------------- | ----------------------------- |
| `get_id`                         | Returns the ID of the active account.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[account_id_prefix, account_id_suffix]`                                                                                | Any              |
| `get_nonce`                      | Returns the nonce of the active account. Always returns the initial nonce as it can only be incremented in auth procedures.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[nonce]`                         | Any              |
| `get_initial_commitment`         | Returns the active account commitment at the beginning of the transaction.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[INIT_COMMITMENT]`                                                                 | Any              |
| `compute_commitment`             | Computes and returns the account commitment from account data stored in memory.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[ACCOUNT_COMMITMENT]`                                                         | Any              |
| `get_code_commitment`            | Gets the account code commitment of the active account.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[CODE_COMMITMENT]`                                                                                   | Account          |
| `get_initial_storage_commitment` | Returns the storage commitment of the active account at the beginning of the transaction.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[INIT_STORAGE_COMMITMENT]`                                          | Any              |
| `compute_storage_commitment`     | Computes the latest account storage commitment of the active account.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[STORAGE_COMMITMENT]`                                                                  | Account          |
| `get_item`                       | Gets an item from the account storage.<br/><br/>**Inputs:** `[slot_id_prefix, slot_id_suffix]`<br/>**Outputs:** `[VALUE]`                                                                                                          | Account          |
| `get_initial_item`               | Gets the initial item from the account storage slot as it was at the beginning of the transaction.<br/><br/>**Inputs:** `[slot_id_prefix, slot_id_suffix]`<br/>**Outputs:** `[VALUE]`                                              | Account          |
| `get_map_item`                   | Returns the VALUE located under the specified KEY within the map contained in the given account storage slot.<br/><br/>**Inputs:** `[slot_id_prefix, slot_id_suffix, KEY]`<br/>**Outputs:** `[VALUE]`                              | Account          |
| `get_initial_map_item`           | Gets the initial VALUE from the account storage map as it was at the beginning of the transaction.<br/><br/>**Inputs:** `[slot_id_prefix, slot_id_suffix, KEY]`<br/>**Outputs:** `[VALUE]`                                         | Account          |
| `get_balance`                    | Returns the balance of the fungible asset associated with the provided faucet_id in the active account's vault.<br/><br/>**Inputs:** `[faucet_id_prefix, faucet_id_suffix]`<br/>**Outputs:** `[balance]` | Any              |
| `get_initial_balance`            | Returns the balance of the fungible asset associated with the provided faucet_id in the active account's vault at the beginning of the transaction.<br/><br/>**Inputs:** `[faucet_id_prefix, faucet_id_suffix]`<br/>**Outputs:** `[init_balance]` | Any              |
| `has_non_fungible_asset`         | Returns a boolean indicating whether the non-fungible asset is present in the active account's vault.<br/><br/>**Inputs:** `[ASSET]`<br/>**Outputs:** `[has_asset]`                                      | Any              |
| `get_initial_vault_root`         | Returns the vault root of the active account at the beginning of the transaction.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[INIT_VAULT_ROOT]`                                                          | Any              |
| `get_vault_root`                 | Returns the vault root of the active account.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[VAULT_ROOT]`                                                                                                  | Any              |
| `get_num_procedures`             | Returns the number of procedures in the active account.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[num_procedures]`                                                                                     | Any              |
| `get_procedure_root`             | Returns the procedure root for the procedure at the specified index.<br/><br/>**Inputs:** `[index]`<br/>**Outputs:** `[PROC_ROOT]`                                                                         | Any              |
| `has_procedure`                  | Returns the binary flag indicating whether the procedure with the provided root is available on the active account.<br/><br/>**Inputs:** `[PROC_ROOT]`<br/>**Outputs:** `[is_procedure_available]`                           | Any |

## Native account Procedures (`miden::protocol::native_account`)

Native account procedures can be used to write to storage, add or remove assets from the vault and compute delta commitment of the native account. 

| Procedure                      | Description                    | Context                        |
| ------------------------------ | ------------------------------ | ------------------------------ |
| `get_id`                       | Returns the ID of the native account of the transaction.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[account_id_prefix, account_id_suffix]`                                                              | Any              |
| `incr_nonce`                   | Increments the nonce of the native account by one and returns the new nonce. Can only be called from auth procedures.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[final_nonce]`                                        | Auth             |
| `compute_delta_commitment`     | Computes the commitment to the native account's delta. Can only be called from auth procedures.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[DELTA_COMMITMENT]`                                           | Auth             |
| `set_item`                     | Sets an item in the native account storage.<br/><br/>**Inputs:** `[slot_id_prefix, slot_id_suffix, VALUE]`<br/>**Outputs:** `[OLD_VALUE]`                                                                                                 | Native & Account |
| `set_map_item`                 | Sets VALUE under the specified KEY within the map contained in the given native account storage slot.<br/><br/>**Inputs:** `[slot_id_prefix, slot_id_suffix, KEY, VALUE]`<br/>**Outputs:** `[OLD_VALUE]`                | Native & Account |
| `add_asset`                    | Adds the specified asset to the vault. For fungible assets, returns the total after addition.<br/><br/>**Inputs:** `[ASSET]`<br/>**Outputs:** `[ASSET']`                                                  | Native & Account |
| `remove_asset`                 | Removes the specified asset from the vault.<br/><br/>**Inputs:** `[ASSET]`<br/>**Outputs:** `[ASSET]`                                                                                                     | Native & Account |
| `was_procedure_called`         | Returns 1 if a native account procedure was called during transaction execution, and 0 otherwise.<br/><br/>**Inputs:** `[PROC_ROOT]`<br/>**Outputs:** `[was_called]`                                                     | Any              |

## Active Note Procedures (`miden::protocol::active_note`)

Active note procedures can be used to fetch data from the note that is currently being processed by the transaction kernel.

| Procedure               | Description                                                                                                                                                     | Context |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `get_assets`            | Writes the [assets](note.md#assets) of the active note into memory starting at the specified address.<br/><br/>**Inputs:** `[dest_ptr]`<br/>**Outputs:** `[num_assets, dest_ptr]` | Note    |
| `get_recipient`         | Returns the [recipient](note.md#note-recipient-restricting-consumption) of the active note.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[RECIPIENT]`                                                              | Note    |
| `get_storage`            | Writes the note's [inputs](note.md#inputs) to the specified memory address.<br/><br/>**Inputs:** `[dest_ptr]`<br/>**Outputs:** `[num_storage_items, dest_ptr]`                           | Note    |
| `get_metadata`          | Returns the [metadata](note.md#metadata) of the active note.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[METADATA]`                                                              | Note    |
| `get_sender`            | Returns the sender of the active note.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[sender_id_prefix, sender_id_suffix]`                                        | Note    |
| `get_serial_number`     | Returns the [serial number](note.md#serial-number) of the active note.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[SERIAL_NUMBER]`                                                      | Note    |
| `get_script_root`       | Returns the [script root](note.md#script) of the active note.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[SCRIPT_ROOT]`                                                          | Note    |

## Input Note Procedures (`miden::protocol::input_note`)

Input note procedures can be used to fetch data on input notes consumed by the transaction.

| Procedure           | Description                                                                                                                                                                                                                    | Context |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- |
| `get_assets_info`   | Returns the information about [assets](note.md#assets) in the input note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[ASSETS_COMMITMENT, num_assets]`                                         | Any     |
| `get_assets`        | Writes the [assets](note.md#assets) of the input note with the specified index into memory starting at the specified address.<br/><br/>**Inputs:** `[dest_ptr, note_index]`<br/>**Outputs:** `[num_assets, dest_ptr, note_index]` | Any     |
| `get_recipient`     | Returns the [recipient](note.md#note-recipient-restricting-consumption) of the input note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[RECIPIENT]`                                            | Any     |
| `get_metadata`      | Returns the [metadata](note.md#metadata) of the input note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[METADATA]`                                                                            | Any     |
| `get_sender`        | Returns the sender of the input note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[sender_id_prefix, sender_id_suffix]`                                                                      | Any     |
| `get_storage_info`   | Returns the [inputs](note.md#inputs) commitment and length of the input note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[NOTE_STORAGE_COMMITMENT, num_storage_items]`                                | Any     |
| `get_script_root`   | Returns the [script root](note.md#script) of the input note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[SCRIPT_ROOT]`                                                                        | Any     |
| `get_serial_number` | Returns the [serial number](note.md#serial-number) of the input note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[SERIAL_NUMBER]`                                                             | Any     |

## Output Note Procedures (`miden::protocol::output_note`)

Output note procedures can be used to fetch data on output notes created by the transaction.

| Procedure         | Description                                                                                                                                                                                                      | Context          |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| `create`          | Creates a new output note and returns its index.<br/><br/>**Inputs:** `[tag, note_type, RECIPIENT]`<br/>**Outputs:** `[note_idx]`                                                           | Native & Account |
| `get_assets_info` | Returns the information about assets in the output note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[ASSETS_COMMITMENT, num_assets]`                                         | Any              |
| `get_assets`      | Writes the assets of the output note with the specified index into memory starting at the specified address.<br/><br/>**Inputs:** `[dest_ptr, note_index]`<br/>**Outputs:** `[num_assets, dest_ptr, note_index]` | Any              |
| `add_asset`       | Adds the `ASSET` to the output note specified by the index.<br/><br/>**Inputs:** `[ASSET, note_idx]`<br/>**Outputs:** `[]`                                                                        | Native           |
| `set_attachment`  | Sets the attachment of the note specified by the index. <br/><br/> If attachment_kind == Array, there must be an advice map entry for ATTACHMENT. <br/><br/>**Inputs:**<br/>`Operand Stack: [note_idx, attachment_scheme, attachment_kind, ATTACHMENT]`<br/>`Advice map: { ATTACHMENT?: [[ATTACHMENT_ELEMENTS]] }`<br/>**Outputs:** `[]`                                                                        | Native           |
| `set_array_attachment`  | Sets the attachment of the note specified by the note index to the provided ATTACHMENT which commits to an array of felts. <br/><br/>**Inputs:**<br/>`Operand Stack: [note_idx, attachment_scheme, ATTACHMENT]`<br/>`Advice map: { ATTACHMENT: [[ATTACHMENT_ELEMENTS]] }`<br/>**Outputs:** `[]`                                                                        | Native           |
| `set_word_attachment`   | Sets the attachment of the note specified by the note index to the provided word.<br/><br/>**Inputs:** `[note_idx, attachment_scheme, ATTACHMENT]`<br/>**Outputs:** `[]`                             |
| `get_recipient`   | Returns the [recipient](note#note-recipient-restricting-consumption) of the output note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[RECIPIENT]`                             | Any              |
| `get_metadata`    | Returns the [metadata](note#metadata) of the output note with the specified index.<br/><br/>**Inputs:** `[note_index]`<br/>**Outputs:** `[METADATA]`                                                             | Any              |

## Note Utility Procedures (`miden::protocol::note`)

Note utility procedures can be used to compute the required utility data or write note data to memory.

| Procedure                   | Description                                                                                                                                                                                                             | Context |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `compute_storage_commitment` | Computes the commitment to the output note storage starting at the specified memory address.<br/><br/>**Inputs:** `[storage_ptr, num_storage_items]`<br/>**Outputs:** `[STORAGE_COMMITMENT]`                                      | Any     |
| `write_assets_to_memory`    | Writes the assets data stored in the advice map to the memory specified by the provided destination pointer.<br/><br/>**Inputs:** `[ASSETS_COMMITMENT, num_assets, dest_ptr]`<br/>**Outputs:** `[num_assets, dest_ptr]` | Any     |
| `build_recipient_hash`      | Returns the `RECIPIENT` for a specified `SERIAL_NUM`, `SCRIPT_ROOT`, and storage commitment.<br/><br/>**Inputs:** `[SERIAL_NUM, SCRIPT_ROOT, STORAGE_COMMITMENT]`<br/>**Outputs:** `[RECIPIENT]`                           | Any     |
| `build_recipient`           | Builds the recipient hash from note storage, script root, and serial number.<br/><br/>**Inputs:** `[storage_ptr, num_storage_items, SERIAL_NUM, SCRIPT_ROOT]`<br/>**Outputs:** `[RECIPIENT]`                                     | Any     |
| `extract_sender_from_metadata` | Extracts the sender ID from the provided metadata word.<br/><br/>**Inputs:** `[METADATA]`<br/>**Outputs:** `[sender_id_prefix, sender_id_suffix]` | Any     |

## Transaction Procedures (`miden::protocol::tx`)

Transaction procedures manage transaction-level operations including note creation, context switching, and reading transaction metadata.

| Procedure                       | Description                                                                                                                                                                                                    | Context |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `get_block_number`              | Returns the block number of the transaction reference block.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[num]`                                                                                                | Any     |
| `get_block_commitment`          | Returns the block commitment of the reference block.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[BLOCK_COMMITMENT]`                                                                                           | Any     |
| `get_block_timestamp`           | Returns the timestamp of the reference block for this transaction.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[timestamp]`                                                                                    | Any     |
| `get_input_notes_commitment`    | Returns the input notes commitment hash.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[INPUT_NOTES_COMMITMENT]`                                                                                                 | Any     |
| `get_output_notes_commitment`   | Returns the output notes commitment hash.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[OUTPUT_NOTES_COMMITMENT]`                                                                                               | Any     |
| `get_num_input_notes`           | Returns the total number of input notes consumed by this transaction.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[num_input_notes]`                                                                           | Any     |
| `get_num_output_notes`          | Returns the current number of output notes created in this transaction.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[num_output_notes]`                                                                        | Any     |
| `execute_foreign_procedure`     | Executes the provided procedure against the foreign account.<br/><br/>**Inputs:** `[foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, <inputs>, pad(n)]`<br/>**Outputs:** `[<outputs>]` | Any     |
| `get_expiration_block_delta`    | Returns the transaction expiration delta, or 0 if not set.<br/><br/>**Inputs:** `[]`<br/>**Outputs:** `[block_height_delta]`                                                                                   | Any     |
| `update_expiration_block_delta` | Updates the transaction expiration delta.<br/><br/>**Inputs:** `[block_height_delta]`<br/>**Outputs:** `[]`                                                                                                    | Any     |

## Faucet Procedures (`miden::protocol::faucet`)

Faucet procedures allow reading and writing to faucet accounts to mint and burn assets.

| Procedure                      | Description                                                                                                                                                                | Context                   |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `create_fungible_asset`        | Creates a fungible asset for the faucet the transaction is being executed against.<br/><br/>**Inputs:** `[amount]`<br/>**Outputs:** `[ASSET]`                              | Faucet                    |
| `create_non_fungible_asset`    | Creates a non-fungible asset for the faucet the transaction is being executed against.<br/><br/>**Inputs:** `[DATA_HASH]`<br/>**Outputs:** `[ASSET]`                       | Faucet                    |
| `mint`                         | Mint an asset from the faucet the transaction is being executed against.<br/><br/>**Inputs:** `[ASSET]`<br/>**Outputs:** `[ASSET]`                                         | Native & Account & Faucet |
| `burn`                         | Burn an asset from the faucet the transaction is being executed against.<br/><br/>**Inputs:** `[ASSET]`<br/>**Outputs:** `[ASSET]`                                         | Native & Account & Faucet |

## Asset Procedures (`miden::protocol::asset`)

Asset procedures provide utilities for creating fungible and non-fungible assets.

| Procedure                  | Description                                                                                                                                                          | Context |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `build_fungible_asset`     | Builds a fungible asset for the specified fungible faucet and amount.<br/><br/>**Inputs:** `[faucet_id_prefix, faucet_id_suffix, amount]`<br/>**Outputs:** `[ASSET]` | Any     |
| `build_non_fungible_asset` | Builds a non-fungible asset for the specified non-fungible faucet and data hash.<br/><br/>**Inputs:** `[faucet_id_prefix, DATA_HASH]`<br/>**Outputs:** `[ASSET]`     | Any     |
