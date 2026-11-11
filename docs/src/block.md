---
sidebar_position: 7
---

# Blocks

## Public transaction logs

A block body preserves transaction headers grouped by batch and contains public transaction logs
in the same batch and transaction order. The [batch log rules](batch.md#public-transaction-logs)
govern log inclusion, emission order, and association with transaction headers.

The block transaction commitment binds the ordered transaction IDs and, through them, the log
commitments.

The public log content-word budget applies to the combined logs of all batches in the block.
