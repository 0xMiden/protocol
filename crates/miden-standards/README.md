# Miden Standards

This crate contains the code of Miden's standardized smart contracts.

## Build cache

To reuse assembled standards packages across Cargo configurations in one checkout, set
`MIDEN_STANDARDS_MASP_CACHE_DIR` to a fresh temporary directory for the build session. Use the
same assembler, dependency resolution, and build-helper code throughout that session. The build
script keys entries by MASM sources and manifests, checkout path, assembly profile, build script,
and the serialized upstream packages. With the variable unset it assembles directly in Cargo's
output directory.

## Status

At this point, all implementations listed above are considered to be experimental and are subject to change.

## License

This project is [MIT licensed](../../LICENSE).
