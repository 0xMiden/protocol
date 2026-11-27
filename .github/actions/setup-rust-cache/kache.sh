#!/bin/bash

# cc-rs recognizes the kache filename stem and sends native compilations through this wrapper.
# Bash preserves Cargo's environment variables with hyphenated binary names.

# These libraries embed MASM packages whose debug info contains absolute source paths.
# Keying them by path lets kache reuse them on CI runners with the same directory layout.
# https://github.com/0xMiden/miden-vm/issues/4250
case "${CARGO_CRATE_NAME:-}" in
    miden_core_lib|miden_protocol|miden_standards|miden_agglayer|miden_usdcx)
        export KACHE_RUSTC_PATH_NORMALIZE=0
        ;;
esac

exec kache "$@"
