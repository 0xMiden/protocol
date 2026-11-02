#!/bin/bash
# Moves the `.changelog/unreleased/` entries into `.changelog/<tag>/<PR>.md`, adding their PR links. The PR of
# an entry is its file name if that is a number, and otherwise the `(#N)` that GitHub appends to the subject
# of the squash commit that added the file. A file holding just the name of another entry adds its PR to the
# links of that entry instead.
set -euo pipefail

TAG="$1"
SRC=".changelog/unreleased"
DST=".changelog/${TAG}"
PR_URL="https://github.com/0xMiden/protocol/pull"

shopt -s nullglob
files=("${SRC}"/*.md)
if [ ${#files[@]} -eq 0 ]; then
    >&2 echo "No changelog entries found in ${SRC}/"
    exit 1
fi

declare -A pr_of
for file in "${files[@]}"; do
    name=$(basename "${file}" .md)
    if [[ "${name}" =~ ^[0-9]+$ ]]; then
        pr_of[${name}]=${name}
        continue
    fi
    subject=$(git log --no-renames --diff-filter=A --format=%s -- "${file}" | sed -n 1p)
    if [[ ! "${subject}" =~ \(#([0-9]+)\)$ ]]; then
        >&2 echo "No PR number in \"${subject}\", the commit that added ${file}. Rename it to <PR number>.md."
        exit 1
    fi
    pr_of[${name}]=${BASH_REMATCH[1]}
done

# Every entry collects its own PR and the PRs of the files referencing it.
declare -A prs refs
for file in "${files[@]}"; do
    name=$(basename "${file}" .md)
    target=$(<"${file}")
    if [ -z "${target}" ] || [ -z "${pr_of[${target}]:-}" ]; then
        target=${name}
    else
        refs[${name}]=1
    fi
    prs[${target}]="${prs[${target}]:+${prs[${target}]} }${pr_of[${name}]}"
done

mkdir -p "${DST}"
for file in "${files[@]}"; do
    name=$(basename "${file}" .md)
    if [ -n "${refs[${name}]:-}" ]; then
        continue
    fi
    links=$(tr ' ' '\n' <<< "${prs[${name}]}" | sort -nu \
        | awk -v url="${PR_URL}" '{ printf "%s[#%s](%s/%s)", (NR > 1 ? ", " : ""), $1, url, $1 }')
    while IFS= read -r line || [ -n "${line}" ]; do
        if [ -n "${line}" ]; then
            echo "- ${line%.} (${links})."
        fi
    done < "${file}" >> "${DST}/${pr_of[${name}]}.md"
done

git rm -q "${files[@]}"
git add "${DST}"
