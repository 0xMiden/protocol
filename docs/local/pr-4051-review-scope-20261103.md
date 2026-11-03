# Eidos review scope

The account-delta layout marker will be version 1. Its content remains unchanged: for `N > 0` changed asset IDs, the vault section contains `N + 2` double words, including both operation trailers. For `N = 0`, the vault section remains empty. The final committed-length check remains mandatory.

The review touch-ups change no other encoding. In particular, sealing-key discriminant renumbering stays in the answer sheet for review. Readability cleanup can proceed separately from encoding decisions.

The version-only reset will have its own commit, separate from the remaining readability nits.
