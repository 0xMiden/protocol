# Transaction logs

An authenticated account procedure emits a log with `miden::protocol::tx::add_log`:

```text
Stack: [topic_0, topic_1, PAYLOAD_COMMITMENT]
Advice map: PAYLOAD_COMMITMENT => payload field elements
```

The kernel checks the payload and records the active account as emitter. Note and transaction
scripts must call an account procedure. Named topics use the first two felts of `word(name)`.

Individual log commitments are hashed in emission order; `TransactionLogs` defines the encoding.
The aggregate is cached until another log is appended and is bound to transaction outputs, IDs,
proofs and signing summaries. Emit all logs before constructing the summary that authorizes them.

Visibility follows the native account, including through FPI. Public transactions submit records;
private transactions keep records and their secret opening locally and submit a salted commitment.
See `TransactionLogs::commitment_for_account` for private salt requirements. Empty collections
commit to zero, so the presence of logs is visible. Remote provers and validators that decrypt
execution witnesses can access private records and openings.

A transaction allows 64 logs, 256 words per payload and 512 total payload words, excluding metadata.
Logs alone do not make an otherwise empty transaction valid.
