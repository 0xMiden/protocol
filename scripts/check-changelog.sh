#!/bin/bash
set -uo pipefail

CHANGELOG_DIR=".changelog/unreleased"

if [ "${NO_CHANGELOG_LABEL}" = "true" ]; then
    # 'no changelog' set, so finish successfully
    echo "\"no changelog\" label has been set"
    exit 0
else
    # a changelog check is required
    # fail if no entry was added
    if [ -z "$(git diff --name-only --diff-filter=A "origin/${BASE_REF}" -- ":(glob)${CHANGELOG_DIR}/*.md")" ]; then
        >&2 echo "Changes should come with an entry in \"${CHANGELOG_DIR}/\" (see
\".changelog/README.md\"). This behavior can be overridden by using the \"no changelog\"
label, which is used for changes that are trivial / explicitly stated not to require a
changelog entry."
        exit 1
    fi

    echo "The ${CHANGELOG_DIR} directory has been updated."
fi
