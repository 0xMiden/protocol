# Transaction logs

An authenticated account procedure emits a transaction log with `miden::protocol::tx::add_log`:

```text
Stack: [topic_suffix, topic_prefix, PAYLOAD_COMMITMENT]
Advice map: PAYLOAD_COMMITMENT => payload field elements
```

The kernel checks the payload and uses the active account as emitter. Note and transaction
scripts must call an account procedure. Named topics use the first two felts of `word(name)`.

Individual transaction log commitments are hashed in emission order; `TransactionLogs` defines the
commitment preimage. The kernel caches the aggregate until another log is appended. It is bound to
transaction outputs, IDs, proofs and signing summaries. Emit all transaction logs before constructing
the summary that authorizes them.

Visibility follows the native account: the account against which the transaction executes. A public
native account submits complete transaction logs; a private native account submits only their
commitment. This also applies during FPI, regardless of the emitting account's visibility.

Public and private transaction logs use the same deterministic commitment. Keeping log contents
private does not prevent observers from guessing a predictable complete log list and comparing its
commitment with the published value. Applications that need protection against guessing can include
fresh, secret randomness in their log contents, for example by appending a random log before
constructing the signing summary. That log counts toward the usual limits and must be retained for
proving. Empty transaction logs commit to zero, so the presence of transaction logs is visible.

Local execution data and signing summaries retain complete transaction logs, including in debug
output. Protobuf transaction effects also retain them. Remote provers and validators that decrypt
execution witnesses can access this data.

A transaction allows 64 transaction logs, 256 words per payload and 512 total payload words, excluding
metadata. Transaction logs alone do not make an otherwise empty transaction valid.

Batches and blocks carry one transaction log data entry per transaction header, validating visibility
and commitments. Transaction IDs bind transaction logs through the existing batch and block
commitments.

| Aggregate limit | Batch | Block |
| --- | ---: | ---: |
| Transaction log data entries, including private and empty entries | 1,024 | 65,536 |
| Public transaction logs | 4,096 | 65,536 |
| Public transaction log payload words | 65,536 | 524,288 |
| Canonical protobuf bytes, including metadata | 4 MiB | 32 MiB |
