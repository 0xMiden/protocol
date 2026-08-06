#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
workspace_version="$(
    awk '
        /^\[workspace.package\]/ { in_workspace_package = 1; next }
        /^\[/ { in_workspace_package = 0 }
        in_workspace_package && /^version[[:space:]]*=/ {
            gsub(/"/, "", $3)
            print $3
            exit
        }
    ' "$repo_root/Cargo.toml"
)"

parse_version() {
    local version="$1"
    local prefix="$2"
    local major minor patch

    IFS=. read -r major minor patch <<<"$version"
    if [[ ! "$major" =~ ^[0-9]+$ || ! "$minor" =~ ^[0-9]+$ || ! "$patch" =~ ^[0-9]+$ ]]; then
        echo "::error::could not parse semantic version '$version'"
        exit 1
    fi

    eval "${prefix}_major=\$major"
    eval "${prefix}_minor=\$minor"
    eval "${prefix}_patch=\$patch"
}

cargo_incompatible_release_line_changed() {
    (( baseline_major != current_major )) ||
        (( baseline_major == 0 && baseline_minor != current_minor )) ||
        (( baseline_major == 0 && baseline_minor == 0 && baseline_patch != current_patch ))
}

# Exclude tags pointing at HEAD (--no-contains) so we compare against the previous release
latest_release_tag_on_head() {
    git -C "$repo_root" tag --merged HEAD --no-contains HEAD --list 'v[0-9]*.[0-9]*.[0-9]*' \
        | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -V \
        | tail -n1 \
        || true
}

# Escape hatch, for when the root changes are intended: it names the single version it applies to,
# so a value that is left behind goes stale instead of disabling the check for every later release.
if [[ -n "${SKIP_MASM_ROOT_CHECK_FOR_VERSION:-}" ]]; then
    if [[ "$SKIP_MASM_ROOT_CHECK_FOR_VERSION" == "$workspace_version" ]]; then
        echo "SKIP_MASM_ROOT_CHECK_FOR_VERSION is set to the version being released (${workspace_version}); skipping MAST root stability check"
        exit 0
    fi

    echo "::warning::ignoring stale SKIP_MASM_ROOT_CHECK_FOR_VERSION: it is set to ${SKIP_MASM_ROOT_CHECK_FOR_VERSION} but the version being released is ${workspace_version}"
fi

# Skip check for pre-release versions
if [[ "$workspace_version" == *[-+]* ]]; then
    echo "workspace version ${workspace_version} is a pre-release; skipping MAST root stability check"
    exit 0
fi

parse_version "$workspace_version" current

# Release CI checks out with `fetch-depth: 0` (tags already present) and `persist-credentials:
# false`, so tolerate a failing fetch and fall back to the tags from the checkout.
git -C "$repo_root" fetch --tags origin || true

baseline_tag="$(latest_release_tag_on_head)"
if [[ -z "$baseline_tag" ]]; then
    echo "No release tag found on the current branch history; skipping MAST root stability check"
    exit 0
fi

baseline_version="${baseline_tag#v}"
parse_version "$baseline_version" baseline

if cargo_incompatible_release_line_changed; then
    echo "workspace version changed Cargo-incompatible release line from ${baseline_version} to ${workspace_version}; skipping MAST root stability check"
    exit 0
fi

check_script="$repo_root/scripts/.check-masm-export-digests.${baseline_tag}.$$.rs"

cleanup() {
    rm -f "$check_script"
}
trap cleanup EXIT

sed -E "s/tag = \"v[0-9]+\\.[0-9]+\\.[0-9]+\"/tag = \"${baseline_tag}\"/g" \
    "$repo_root/scripts/check-masm-export-digests.rs" >"$check_script"
chmod +x "$check_script"

echo "Checking MAST root stability against $baseline_tag"
if ! RUSTC_WRAPPER= rustup run nightly cargo -Zscript "$check_script"; then
    echo "::error::MAST roots changed since ${baseline_tag}; if releasing them is intended, set the SKIP_MASM_ROOT_CHECK_FOR_VERSION repository variable to ${workspace_version} and re-run the release"
    exit 1
fi

echo "MAST roots are stable against $baseline_tag"
