# EIP-712 Solidity compatibility test

This Foundry test generates the OpenZeppelin-compatible EIP-712 transaction-summary fixture used
by the Miden standards tests.

Initialize the repository submodules, install Foundry, and run:

```bash
cd crates/miden-testing/tests/standards/solidity-compat
forge test --match-test test_generateEip712TransactionSummaryVector
```

The test writes `../test-vectors/eip712_transaction_summary.json` and verifies the generated
signature with OpenZeppelin before writing it.
