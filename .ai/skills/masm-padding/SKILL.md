---
name: masm-padding
description: Enforce stack padding conventions for Miden Assembly (.masm) procedures based on invocation type (call vs exec). Use when editing, reviewing, or creating .masm procedures, especially those with Invocation annotations.
---

# MASM Padding Conventions

## Overview

Padding requirements differ based on procedure invocation type:

| Invocation | Padding Required | Input/Output Elements |
|------------|------------------|----------------------|
| `call`     | Explicit padding in comments | Exactly 16 |
| `exec`     | No explicit padding | No requirement |

## Call Procedures

Procedures invoked with `call` must have explicit padding in:
1. **Doc comments** (`#!`) for Inputs/Outputs
2. **Inline comments** (`#`) showing stack state

### Doc Comment Format

Use `pad(N)` notation where N + other elements = 16:

```masm
#! Inputs:  [ASSET, pad(12)]
#! Outputs: [pad(16)]
#!
#! Invocation: call
pub proc receive_asset
```

### Inline Comment Format

Track padding through the procedure:

```masm
exec.native_account::set_item
# => [OLD_VALUE, pad(12)]

dropw
# => [pad(16)] auto-padded to 16 elements    
```

### Auto-Padding Behavior

If the stack falls below 16 elements for a `call` procedure, Miden auto-pads to 16. This is acceptable and should be documented in the output as the padded result.

## Exec Procedures

Procedures invoked with `exec` should NOT have explicit padding:

```masm
#! Inputs:  [PUB_KEY]
#! Outputs: []
#!
#! Invocation: exec
pub proc authenticate_transaction
```

### Why No Padding for Exec

`exec` procedures share the caller's stack directly. Explicit padding would be misleading because:
- The actual stack may have additional elements from the caller
- The procedure may consume caller's stack elements

### Danger Zone

If an `exec` procedure's stack falls below the specified stack elements, it will consume stack items from its caller, potentially leading to unexpected behavior. This is a bug and should be fixed by ensuring the procedure maintains sufficient stack depth and avoiding dropping more stack elements than available.

### Example of Dangerous Behavior

```masm
# => [num_approvers, threshold]
dropw # dropw drops 4 elements, which will result in "negative" stack consumption (consuming 2 elements from the caller's stack)
```


## Intermediate States

Inside a procedure, the stack may temporarily exceed 16 elements:

```masm
# => [num_approvers, threshold, MULTISIG_CONFIG, pad(12)]
#     ^--- 18 elements total, must be reduced before return
```

These extra elements must be explicitly dropped before the procedure returns (directly or via called procedures).

## Validation Checklist

For `call` procedures:
- [ ] Inputs doc comment shows exactly 16 elements with `pad(N)`
- [ ] Outputs doc comment shows exactly 16 elements with `pad(N)`
- [ ] Inline comments use `# =>` format with `pad(N)` notation
- [ ] All intermediate states track the full stack including padding

For `exec` procedures:
- [ ] No `pad(N)` in Inputs/Outputs doc comments
- [ ] No explicit padding in inline stack state comments
- [ ] Verify stack never drops below safe depth
