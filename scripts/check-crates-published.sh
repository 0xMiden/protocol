#!/bin/bash
set -euo pipefail

# Pre-flight check for workspace releases.
#
# crates.io refuses to create a *new* crate from a Trusted Publishing (OIDC)
# token: the first version of any crate name must be pushed manually with a
# personal API token. `cargo publish --dry-run` never contacts the registry to
# reserve a name, so a newly added workspace member looks perfectly healthy
# right up until the tagged release fails mid-publish with:
#
#   403 Forbidden: Trusted Publishing tokens do not support creating new
#   crates. Publish the crate manually, first
#
# This asserts that every publishable workspace member already has its name
# registered on crates.io.
#
# SCOPE: a hit proves only that the name is registered by *someone*. It does
# not prove that we own the crate, that Trusted Publishing is configured for
# it, or that the version being released is free - all of which still surface
# as a failure at publish time. Treat a pass as "no brand-new crate names",
# not "the release will succeed".

check_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: Required command '$1' is not installed or not in PATH" >&2
    exit 1
  fi
}

check_command "cargo"
check_command "jq"
check_command "curl"

# The sparse index is the registry's machine-readable surface: CDN-backed, no
# rate limits, and no crawler policy to honour (unlike the crates.io API).
# Deliberately not overridable: this gates a release, and an env var pointing
# it at a host that answers 200 would make the check pass vacuously.
INDEX_BASE="https://index.crates.io"
USER_AGENT="miden-protocol-ci (https://github.com/0xMiden/protocol)"

# Map a crate name to its sparse-index path, per the registry's prefix rules.
# `tr` rather than `${name,,}` for the bash 3.2 that ships on macOS.
index_path() {
  local name
  name=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "${#name}" in
    1) echo "1/$name" ;;
    2) echo "2/$name" ;;
    3) echo "3/${name:0:1}/$name" ;;
    *) echo "${name:0:2}/${name:2:2}/$name" ;;
  esac
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR/.."

# Capture into a variable rather than piping into the loop: a process
# substitution discards the exit status, so a failed or truncated read would
# silently yield a partial crate list that passes the check.
#
# `--no-deps` restricts the list to workspace members. A member is publishable
# when `publish` is unset (null) or names the crates-io registry;
# `publish = false` surfaces as an empty array.
crate_list=$(
  cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[]
           | select(.publish == null
                    or ((.publish | type) == "array"
                        and (.publish | index("crates-io")) != null))
           | .name' \
  | sort
)

if [[ -z "$crate_list" ]]; then
  echo "ERROR: No publishable workspace members found - is this a cargo workspace?" >&2
  exit 1
fi

echo "Checking publishable workspace members against crates.io..."
echo ""

missing=""

while IFS= read -r crate; do
  [[ -n "$crate" ]] || continue
  url="$INDEX_BASE/$(index_path "$crate")"

  # --head: only the status is consumed. No --location: a redirect ending in
  # an unrelated 200 must not look like proof the crate exists.
  http_code=$(
    curl --silent --show-error --head \
         --retry 3 --retry-delay 2 --retry-max-time 40 \
         --retry-connrefused --max-time 15 \
         --user-agent "$USER_AGENT" \
         --output /dev/null --write-out '%{http_code}\n' \
         "$url" \
    | tail -n 1
  ) || http_code="" # tail: older curl writes the status once per retry attempt

  case "${http_code:-000}" in
    200)
      echo "OK: $crate"
      ;;
    # Cargo's sparse-registry client treats all three as "not in index".
    404 | 410 | 451)
      echo "MISSING: $crate"
      missing="$missing"$'\n'"   - $crate"
      ;;
    *)
      echo "ERROR: could not verify '$crate' (HTTP ${http_code:-000} from $url)" >&2
      echo "       Refusing to guess - retry the job." >&2
      exit 1
      ;;
  esac
done <<< "$crate_list"

echo ""

if [[ -n "$missing" ]]; then
  echo "The following crates have never been published to crates.io:$missing"
  echo ""
  echo "Trusted Publishing tokens cannot create new crates, so a release would"
  echo "fail partway through - after publishing some crates but not others."
  echo ""
  echo "TO FIX (needs a crates.io account with publish rights):"
  echo "   1. Claim the name with a placeholder, built OUTSIDE this workspace so"
  echo "      it inherits none of its versions or path dependencies, using a"
  echo "      personal API token rather than CI:"
  echo "         dir=\$(mktemp -d) && cargo new --lib \"\$dir/claim\""
  echo "         cd \"\$dir/claim\""
  echo "         # set name = \"<crate-name>\", version = \"0.0.0\", and the"
  echo "         # description + license fields crates.io requires"
  echo "         cargo publish"
  echo "      Use 0.0.0, not the version about to be released: claiming it at"
  echo "      the release version makes the release job fail with 'already"
  echo "      exists on crates.io index', and would leave a locally built"
  echo "      tarball as the official artifact for that version."
  echo ""
  echo "      Publishing from the workspace instead would need --allow-dirty,"
  echo "      which bakes untracked files into a permanently public artifact,"
  echo "      plus hand-pinning every workspace dependency to a released"
  echo "      version. The placeholder avoids both; the real code ships in the"
  echo "      normal release."
  echo "   2. Give the org ownership, or whoever ran step 1 is the sole owner:"
  echo "         cargo owner --add github:0xMiden:<team> <crate-name>"
  echo "   3. On crates.io, open the crate's Settings -> Trusted Publishing and"
  echo "      add this repository (0xMiden/protocol), workflow"
  echo "      'workspace-publish.yml', environment 'release'. This is per-crate:"
  echo "      without it, CI cannot publish later versions either."
  echo ""
  exit 1
fi

echo "All publishable workspace members are registered on crates.io."
echo "(This means no brand-new crate names - not that the release will succeed."
echo " Ownership, per-crate Trusted Publishing config and version collisions"
echo " still only surface at publish time.)"
