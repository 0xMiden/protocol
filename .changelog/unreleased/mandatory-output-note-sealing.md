[BREAKING] The transaction epilogue now rejects a transaction with an unsealed output note, and the standard note and transaction scripts, fee and auth components and agglayer bridge seal the notes they create.
[BREAKING] `fee::pay_fee` and `fees::create_network_note_sponsorships` now reject a sealed TX_FEE or FEE_SPONSORSHIP note that carries attachments.
