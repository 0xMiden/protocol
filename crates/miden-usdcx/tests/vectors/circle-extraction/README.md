# Circle DepositIntent ground-truth extraction (provenance for `circle-depositintent-groundtruth.json`)

The differential fixture `../circle-depositintent-groundtruth.json` is **not** a file shipped by
Circle and was **not** copied from Circle's repository. It was **locally generated / reconstructed
from Circle source** at commit `a571cbe12fa7cede3dfd48bc4fedb74739c04377` of
`https://github.com/circlefin/evm-xreserve-contracts`, by running the extraction script in this
directory (`ExtractDepositIntentGroundTruth.s.sol`).

## What the script is — and is not

- It is an **agent-authored** Foundry script. It is **NOT part of Circle's repository**: at
  `a571cbe`, Circle's tracked tree contains **no golden-hex blob and no extraction script** for
  DepositIntent (its own tests assert via decode round-trip + length, not a literal byte blob).
  It is reproduced here only so this repo's provenance is self-contained and re-derivable.
- It produces the bytes using **Circle's own encoder**,
  `DepositIntentLib.encodeDepositIntent` (`src/lib/DepositIntentLib.sol`, an
  `abi.encodePacked`) — the same function `xReserve.encodeDepositIntent` (`src/xReserve.sol:154-155`)
  and Circle's `deploy-contracts/GenerateDepositIntentAttestation.s.sol` call. The input field
  values are the hardcoded constants in the script.
- For each of the four intents it self-asserts every DC-1 byte offset and round-trips the bytes
  back through Circle's own `DepositIntentLib.decodeDepositIntent`, then logs the encoded bytes
  and their keccak256.
- Two of the four carry OPAQUE bytes32 identifiers and two carry Miden account ids in the
  right-aligned packaging. Circle's encoding permits both and produces an identical envelope for
  both, which is exactly what makes the pair useful: the Miden decoder must accept the account-id
  rows and refuse the opaque ones, and the differential test asserts both verdicts against bytes
  this encoder produced.

It does **not** compile standalone in this repo — it depends on Circle's Solidity. It runs only
inside a clone of `evm-xreserve-contracts`.

## How the fixture was generated (reproduction recipe)

```
git clone https://github.com/circlefin/evm-xreserve-contracts
cd evm-xreserve-contracts && git checkout a571cbe12fa7cede3dfd48bc4fedb74739c04377
git submodule update --init --recursive
# place this script under script/ , then:
forge script script/ExtractDepositIntentGroundTruth.s.sol -vvv --skip 'test/**'
```

Environment notes (do not affect the emitted bytes; verify independently): `forge 1.7.1`,
`solc 0.8.29`; the CCTP test-helper deps pin `solc =0.7.6` (no macOS-arm64 build), hence
`--skip 'test/**'`; the repo's `.gitmodules` uses SSH for `lib/evm-gateway-contracts` (rewrite to
HTTPS in a no-SSH environment with
`git config url."https://github.com/".insteadOf "git@github.com:"` before `submodule update`).
The logged `console.logBytes` output is what populates `bytes_hex` in the fixture.

The script has been re-run on Linux since the original macOS run, when the two account-id rows were
added. The two pre-existing rows came back byte-for-byte identical, keccak hashes included — so the
recipe reproduces, and the bytes that were already committed are confirmed.

## Scope

This validates the DepositIntent **envelope** (magic, version, offsets, sizes, endianness, tight
packing, length rule). It says nothing about how a Miden AccountId *should* pack into the
`remoteToken` / `remoteRecipient` `bytes32` fields — that is DEV-10 / Q-CRY-3/4, still OPEN. The
account-id rows use the packaging Miden currently ships, and are evidence about this repo's decoder
rather than about Circle's registration.
