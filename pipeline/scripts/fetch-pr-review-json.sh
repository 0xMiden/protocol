#!/usr/bin/env bash
set -euo pipefail

OWNER="0xMiden"
REPO="protocol"

# Fetch review feedback for each requested PR and write it as a JSON array.
main() {
    parse_args "$@"
    expand_pr_range

    local total="${#prs[@]}"
    echo "processing $total requested numbers: ${prs[*]}" >&2

    local skipped=0
    local fetched=0

    declare -g tmp out_tmp
    tmp="$(mktemp)"
    out_tmp="$(mktemp)"
    trap 'rm -f "$tmp" "$out_tmp"' EXIT

    local count=0
    for pr in "${prs[@]}"; do
        count=$((count + 1))
        echo "fetching $pr ($count/$total)..." >&2
        if fetch_pull_request "$pr" "$tmp"; then
            fetched=$((fetched + 1))
        else
            skipped=$((skipped + 1))
            echo "warning: skipped $pr" >&2
        fi
    done

    assemble_array "$tmp" "$out_tmp"
    deliver "$out_tmp" "$fetched" "$skipped"
}

# Print usage to stderr and exit 1.
usage() {
    echo "usage: $0 PR_RANGE [OUTPUT]
  PR_RANGE: a number, an inclusive range 'a-b' or 'a..b', or a comma-separated list
  OUTPUT:   optional file to save to (default: stdout)" >&2
    exit 1
}

# Parse the arguments into INPUT (PR range) and OUTPUT (optional file, default
# stdout).
parse_args() {
    INPUT=""
    OUTPUT=""
    for arg in "$@"; do
        if [[ -z "$INPUT" ]]; then
            INPUT="$arg"
        elif [[ -z "$OUTPUT" ]]; then
            OUTPUT="$arg"
        else
            echo "unexpected argument: $arg" >&2
            exit 1
        fi
    done
    if [[ -z "$INPUT" ]]; then
        usage
    fi
}

# Expand INPUT into prs[], deduped and in input order.
expand_pr_range() {
    prs=()
    seen=()
    for part in ${INPUT//,/ }; do
        if [[ "$part" =~ ^[0-9]+$ ]]; then
            nums=("$part")
        elif [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]] || [[ "$part" =~ ^([0-9]+)\.\.([0-9]+)$ ]]; then
            low="${BASH_REMATCH[1]}"
            high="${BASH_REMATCH[2]}"
            step="1"
            if ((low > high)); then
                step="-1"
            fi
            mapfile -t nums < <(seq "$low" "$step" "$high")
        else
            echo "invalid range element: $part" >&2
            exit 1
        fi
        for n in "${nums[@]}"; do
            if [[ " ${seen[*]} " != *" $n "* ]]; then
                prs+=("$n")
                seen+=("$n")
            fi
        done
    done
}

# Fetch one PR's reviews/comments into out_file; return 1 if the number is not
# a pull request.
fetch_pull_request() {
    local pr="$1"
    local out_file="$2"
    local resp

    resp="$(gh api graphql \
        -F owner="$OWNER" -F repo="$REPO" -F pr="$pr" \
        -f query='
query($owner: String!, $repo: String!, $pr: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $pr) {
      number
      title
      state
      mergedAt
      reviews(first: 100) { nodes { author { login } state submittedAt body } }
      reviewThreads(first: 100) {
        nodes { id path line comments(first: 30) { nodes { author { login } createdAt body } } }
      }
      comments(first: 50) { nodes { author { login } createdAt body } }
    }
  }
}' --jq '.data.repository.pullRequest' 2>/dev/null)" || return 1

    printf '%s\n' "$resp" >>"$out_file"
}

# Wrap the per-PR JSON documents into a single JSON array.
assemble_array() {
    local in_file="$1"
    local out_file="$2"
    local first

    {
        printf '['
        first=1
        while IFS= read -r line; do
            if [[ "$first" -eq 0 ]]; then
                printf ','
            fi
            first=0
            printf '%s' "$line"
        done <"$in_file"
        printf ']\n'
    } >"$out_file"
}

deliver() {
    local out_file="$1"
    local fetched="$2"
    local skipped="$3"
    local dest="stdout"
    local plural
    local summary
    local notes=""

    if [[ "$fetched" -eq 1 ]]; then
        plural=""
    else
        plural="s"
    fi
    summary="$fetched PR$plural"

    if ((skipped == 1)); then
        notes+="; 1 skipped"
    elif ((skipped > 1)); then
        notes+="; $skipped skipped"
    fi

    if [[ -n "$OUTPUT" ]]; then
        mv "$out_file" "$OUTPUT"
        dest="$OUTPUT"
    else
        cat "$out_file"
    fi
    echo "wrote $dest ($summary$notes)" >&2
}

main "$@"
