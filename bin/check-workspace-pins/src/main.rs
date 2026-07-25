//! Checks that every intra-workspace dependency of every publishable workspace
//! member carries an exact (`=`) version requirement matching the sibling
//! crate's workspace version, together with a `path`.
//!
//! A caret requirement lets cargo resolve a higher already-published version of
//! a sibling crate (including a newer pre-release line, e.g. 0.16.0-beta.1 when
//! publishing 0.16.0-alpha.5) during `cargo publish` verification and for
//! downstream consumers. The `=` pins prevent that and must survive version
//! bumps.
//!
//! The check is driven by `cargo metadata`, so it sees the post-inheritance
//! requirements of every member manifest (not just `[workspace.dependencies]`).
//! Dependencies are matched by workspace member name, and a missing `path` is
//! itself a violation: without it the sibling resolves from the registry
//! instead of the workspace, so publish verification would no longer exercise
//! the crate actually being shipped. The check fails closed: finding no
//! publishable members or no intra-workspace dependencies to verify is an
//! error.
//!
//! The only exemption is a dev-dependency declared with a `path` and no
//! `version` key (e.g. the `path = "."` self dev-deps), which cargo strips
//! from the published manifest. Whether an entry is versionless is read from
//! the member's manifest TOML: `cargo metadata` reports `"*"` for both a
//! missing `version` key and an explicit `version = "*"`, and cargo does NOT
//! strip the latter - it would ship a wildcard requirement that crates.io
//! rejects mid-way through the sequential workspace upload.
//!
//! Dependencies on non-publishable members are skipped; they can never be
//! satisfied on crates.io and `cargo publish` rejects them on its own.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    manifest_path: String,
    /// Registries the package may be published to; `None` means unrestricted
    /// and an empty list means `publish = false`.
    publish: Option<Vec<String>>,
    dependencies: Vec<Dependency>,
}

impl Package {
    fn is_publishable(&self) -> bool {
        self.publish.as_ref().is_none_or(|registries| !registries.is_empty())
    }
}

#[derive(Deserialize)]
struct Dependency {
    name: String,
    req: String,
    /// `None` for normal dependencies, `"dev"` or `"build"` otherwise.
    kind: Option<String>,
    path: Option<String>,
    /// The manifest key when the dependency is renamed (`key = { package = .. }`).
    rename: Option<String>,
}

impl Dependency {
    fn manifest_key(&self) -> &str {
        self.rename.as_deref().unwrap_or(&self.name)
    }
}

/// Per package name, the manifest keys of `[dev-dependencies]` entries that
/// have a `path` but no `version` key. Cargo strips these from the published
/// manifest, so they are exempt from the pin requirement.
type VersionlessDevDeps = BTreeMap<String, BTreeSet<String>>;

fn versionless_dev_dep_keys(manifest: &str) -> Result<BTreeSet<String>> {
    let manifest: toml::Table = manifest.parse().context("failed to parse manifest TOML")?;
    let mut keys = BTreeSet::new();
    if let Some(dev_deps) = manifest.get("dev-dependencies").and_then(|deps| deps.as_table()) {
        for (key, entry) in dev_deps {
            if let Some(entry) = entry.as_table()
                && entry.contains_key("path")
                && !entry.contains_key("version")
            {
                keys.insert(key.clone());
            }
        }
    }
    Ok(keys)
}

fn collect_versionless_dev_deps(metadata: &Metadata) -> Result<VersionlessDevDeps> {
    let mut versionless = VersionlessDevDeps::new();
    for package in metadata.packages.iter().filter(|package| package.is_publishable()) {
        let manifest = std::fs::read_to_string(&package.manifest_path)
            .with_context(|| format!("failed to read {}", package.manifest_path))?;
        let keys = versionless_dev_dep_keys(&manifest)
            .with_context(|| format!("failed to parse {}", package.manifest_path))?;
        versionless.insert(package.name.clone(), keys);
    }
    Ok(versionless)
}

#[derive(Debug)]
struct Report {
    checked: usize,
    publishable_crates: usize,
    violations: BTreeSet<String>,
}

fn check(metadata: &Metadata, versionless_dev_deps: &VersionlessDevDeps) -> Result<Report> {
    let publishable: Vec<&Package> =
        metadata.packages.iter().filter(|package| package.is_publishable()).collect();
    if publishable.is_empty() {
        bail!("no publishable workspace members found");
    }
    let version_by_member: BTreeMap<&str, &str> = publishable
        .iter()
        .map(|package| (package.name.as_str(), package.version.as_str()))
        .collect();

    let mut checked = 0usize;
    let mut violations = BTreeSet::new();
    for package in &publishable {
        for dep in &package.dependencies {
            let Some(dep_version) = version_by_member.get(dep.name.as_str()) else {
                continue;
            };
            let is_stripped_dev_dep = dep.kind.as_deref() == Some("dev")
                && dep.path.is_some()
                && versionless_dev_deps
                    .get(package.name.as_str())
                    .is_some_and(|keys| keys.contains(dep.manifest_key()));
            if is_stripped_dev_dep {
                continue;
            }
            checked += 1;
            let kind = dep.kind.as_deref().unwrap_or("normal");
            let expected_req = format!("={dep_version}");
            if dep.path.is_none() {
                violations.insert(format!(
                    "{}: {kind} dependency {} has no path (intra-workspace deps must be path \
                     dependencies)",
                    package.name, dep.name
                ));
            } else if dep.req != expected_req {
                violations.insert(format!(
                    "{}: {kind} dependency {} has req \"{}\" (expected \"{expected_req}\")",
                    package.name, dep.name, dep.req
                ));
            }
        }
    }

    if checked == 0 {
        bail!("found no intra-workspace dependencies to verify");
    }
    Ok(Report {
        checked,
        publishable_crates: publishable.len(),
        violations,
    })
}

fn load_workspace_metadata() -> Result<Metadata> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .context("failed to run cargo metadata")?;
    if !output.status.success() {
        bail!("cargo metadata failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata output")
}

fn main() -> Result<()> {
    let metadata = load_workspace_metadata()?;
    let versionless_dev_deps = collect_versionless_dev_deps(&metadata)?;

    let report = check(&metadata, &versionless_dev_deps)?;
    if !report.violations.is_empty() {
        eprintln!("error: intra-workspace dependencies must be exact-pinned:");
        for violation in &report.violations {
            eprintln!("  {violation}");
        }
        std::process::exit(1);
    }

    println!(
        "Verified {} intra-workspace dependency requirements across {} publishable crates: all \
         exact-pinned.",
        report.checked, report.publishable_crates
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(json: &str) -> Metadata {
        serde_json::from_str(json).expect("fixture should parse")
    }

    fn no_exemptions() -> VersionlessDevDeps {
        VersionlessDevDeps::new()
    }

    #[test]
    fn all_pinned_workspace_passes() {
        let report = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.1.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": null, "dependencies":
                        [{"name": "b", "req": "=0.1.0", "kind": null, "path": "/ws/b"}]},
                    {"name": "b", "version": "0.1.0", "manifest_path": "/ws/b/Cargo.toml",
                     "publish": null, "dependencies": []}
                ]}"#,
            ),
            &no_exemptions(),
        )
        .expect("check should succeed");
        assert_eq!(report.checked, 1);
        assert_eq!(report.publishable_crates, 2);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn caret_requirement_is_rejected() {
        let report = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.1.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": null, "dependencies":
                        [{"name": "b", "req": "^0.1.0", "kind": null, "path": "/ws/b"}]},
                    {"name": "b", "version": "0.1.0", "manifest_path": "/ws/b/Cargo.toml",
                     "publish": null, "dependencies": []}
                ]}"#,
            ),
            &no_exemptions(),
        )
        .expect("check should succeed");
        assert_eq!(
            report.violations.iter().collect::<Vec<_>>(),
            ["a: normal dependency b has req \"^0.1.0\" (expected \"=0.1.0\")"]
        );
    }

    #[test]
    fn stale_pin_after_version_bump_is_rejected() {
        let report = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.2.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": null, "dependencies":
                        [{"name": "b", "req": "=0.1.0", "kind": null, "path": "/ws/b"}]},
                    {"name": "b", "version": "0.2.0", "manifest_path": "/ws/b/Cargo.toml",
                     "publish": null, "dependencies": []}
                ]}"#,
            ),
            &no_exemptions(),
        )
        .expect("check should succeed");
        assert_eq!(
            report.violations.iter().collect::<Vec<_>>(),
            ["a: normal dependency b has req \"=0.1.0\" (expected \"=0.2.0\")"]
        );
    }

    #[test]
    fn pathless_dependency_is_rejected() {
        let report = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.1.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": null, "dependencies":
                        [{"name": "b", "req": "=0.1.0", "kind": "dev", "path": null}]},
                    {"name": "b", "version": "0.1.0", "manifest_path": "/ws/b/Cargo.toml",
                     "publish": null, "dependencies": []}
                ]}"#,
            ),
            &no_exemptions(),
        )
        .expect("check should succeed");
        assert_eq!(
            report.violations.iter().collect::<Vec<_>>(),
            ["a: dev dependency b has no path (intra-workspace deps must be path dependencies)"]
        );
    }

    #[test]
    fn versionless_path_dev_dependency_is_exempt() {
        let exemptions =
            VersionlessDevDeps::from([("a".into(), BTreeSet::from(["a".to_string()]))]);
        let report = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.1.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": null, "dependencies":
                        [{"name": "a", "req": "*", "kind": "dev", "path": "/ws/a"},
                         {"name": "b", "req": "=0.1.0", "kind": null, "path": "/ws/b"}]},
                    {"name": "b", "version": "0.1.0", "manifest_path": "/ws/b/Cargo.toml",
                     "publish": null, "dependencies": []}
                ]}"#,
            ),
            &exemptions,
        )
        .expect("check should succeed");
        assert_eq!(report.checked, 1);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn explicit_wildcard_dev_dependency_is_rejected() {
        // An explicit `version = "*"` dev-dep is not in the versionless set:
        // cargo does not strip it, so it must be pinned like any other dep.
        let report = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.1.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": null, "dependencies":
                        [{"name": "b", "req": "*", "kind": "dev", "path": "/ws/b"}]},
                    {"name": "b", "version": "0.1.0", "manifest_path": "/ws/b/Cargo.toml",
                     "publish": null, "dependencies": []}
                ]}"#,
            ),
            &no_exemptions(),
        )
        .expect("check should succeed");
        assert_eq!(
            report.violations.iter().collect::<Vec<_>>(),
            ["a: dev dependency b has req \"*\" (expected \"=0.1.0\")"]
        );
    }

    #[test]
    fn restricted_registry_member_is_still_checked() {
        let report = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.1.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": ["my-registry"], "dependencies":
                        [{"name": "b", "req": "^0.1.0", "kind": null, "path": "/ws/b"}]},
                    {"name": "b", "version": "0.1.0", "manifest_path": "/ws/b/Cargo.toml",
                     "publish": null, "dependencies": []}
                ]}"#,
            ),
            &no_exemptions(),
        )
        .expect("check should succeed");
        assert_eq!(
            report.violations.iter().collect::<Vec<_>>(),
            ["a: normal dependency b has req \"^0.1.0\" (expected \"=0.1.0\")"]
        );
    }

    #[test]
    fn non_publishable_members_are_ignored() {
        // The unpublishable helper's own caret dep is not checked, and the
        // publishable crate's dep on the helper is skipped.
        let report = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.1.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": null, "dependencies":
                        [{"name": "b", "req": "=0.1.0", "kind": null, "path": "/ws/b"},
                         {"name": "helper", "req": "*", "kind": "dev", "path": "/ws/helper"}]},
                    {"name": "b", "version": "0.1.0", "manifest_path": "/ws/b/Cargo.toml",
                     "publish": null, "dependencies": []},
                    {"name": "helper", "version": "0.1.0",
                     "manifest_path": "/ws/helper/Cargo.toml", "publish": [], "dependencies":
                        [{"name": "b", "req": "^0.1.0", "kind": null, "path": "/ws/b"}]}
                ]}"#,
            ),
            &no_exemptions(),
        )
        .expect("check should succeed");
        assert_eq!(report.checked, 1);
        assert_eq!(report.publishable_crates, 2);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn no_publishable_members_fails() {
        let result = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.1.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": [], "dependencies": []}
                ]}"#,
            ),
            &no_exemptions(),
        );
        assert!(result.unwrap_err().to_string().contains("no publishable workspace members"));
    }

    #[test]
    fn no_intra_workspace_dependencies_fails() {
        let result = check(
            &metadata(
                r#"{"packages": [
                    {"name": "a", "version": "0.1.0", "manifest_path": "/ws/a/Cargo.toml",
                     "publish": null, "dependencies":
                        [{"name": "external", "req": "^1.0", "kind": null, "path": null}]}
                ]}"#,
            ),
            &no_exemptions(),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no intra-workspace dependencies to verify")
        );
    }

    #[test]
    fn versionless_dev_dep_keys_only_match_path_entries_without_version() {
        let keys = versionless_dev_dep_keys(
            r#"
            [package]
            name = "a"

            [dev-dependencies]
            stripped = { path = "." }
            explicit-wildcard = { path = ".", version = "*" }
            versioned = { path = "../b", version = "=0.1.0" }
            registry = "1.0"
            inherited = { workspace = true }
            "#,
        )
        .expect("manifest should parse");
        assert_eq!(keys.iter().collect::<Vec<_>>(), ["stripped"]);
    }

    #[test]
    fn real_workspace_has_no_violations() {
        // Exercises the real `cargo metadata` schema and manifests, so schema
        // drift or a genuinely unpinned dependency fails in PR CI rather than
        // in the release job.
        let metadata = load_workspace_metadata().expect("cargo metadata should succeed");
        let versionless = collect_versionless_dev_deps(&metadata).expect("manifests should parse");
        let report = check(&metadata, &versionless).expect("check should succeed");
        assert!(report.violations.is_empty(), "violations: {:?}", report.violations);
    }
}
