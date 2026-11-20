Added the `TokenSupplyRestriction` faucet component and the `SUPPLY_RESTRICTION_CONFIG` note to freeze, unfreeze and confiscate amounts of a holder's balance, with confiscation decreasing the token supply.
[BREAKING] Renamed `ERR_FAUCET_BURN_AMOUNT_EXCEEDS_TOKEN_SUPPLY` to `ERR_FAUCET_SUPPLY_DECREASE_EXCEEDS_TOKEN_SUPPLY`, now also raised by `fungible::decrease_token_supply`.
