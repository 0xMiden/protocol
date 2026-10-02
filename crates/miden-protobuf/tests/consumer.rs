#![cfg(feature = "build")]

#[test]
fn consumer_example_builds_and_decodes() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Do not reuse the parent's target directory: Cargo holds its build lock while testing.
    let target = manifest_dir.join("../../target/protobuf-consumer");
    let output = std::process::Command::new(env!("CARGO"))
        .args(["test", "--offline", "--quiet", "--manifest-path"])
        .arg(manifest_dir.join("examples/consumer/Cargo.toml"))
        .arg("--target-dir")
        .arg(target)
        .env_remove("CARGO_TARGET_TMPDIR")
        .output()
        .expect("run consumer example");
    assert!(
        output.status.success(),
        "consumer example failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
