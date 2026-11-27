# Miden Protocol Build Utils

Build-time helpers shared by the `build.rs` scripts of the Miden protocol crates.

Provides utilities for locating and copying MASM sources, extracting MASM error constants into generated Rust files, and assembling and writing MAST packages.

## Reusing compiled packages

By default, each crate’s build script assembles its packages into Cargo’s `OUT_DIR/assets`. To reuse packages from a previous build, set the crate’s `<CRATE>_MASP_DIR` variable to the directory **containing** `assets/`. For example, `MIDEN_PROTOCOL_MASP_DIR` can point to a previous `miden-protocol` output directory. It must contain all packages needed by the requested features, including the test-only packages when `testing` is enabled.

CI builds the packages with all features and caches each crate’s `assets/` tree separately. The restore action derives the variable name from the Cargo package name by uppercasing it and replacing hyphens with underscores. A new crate can use the same convention in its build script. Preserve file timestamps when copying the packages into `OUT_DIR` so Cargo can reuse binaries that embed them.

## License

This project is [MIT licensed](../../LICENSE).
