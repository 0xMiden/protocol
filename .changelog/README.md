# Changelog entries

Every PR that changes behavior adds a file to `unreleased/` named after the change (e.g. the branch name), with
one line per entry:

```markdown
[BREAKING] Renamed `Foo` to `Bar`.
```

The PR link is added at release. A PR that extends an entry still in `unreleased/` can instead add a file holding
just that entry's file name without `.md` (e.g. `code-tree`), which adds its PR link to that entry.

PRs that don't need an entry get the `no changelog` label.

## Release

Before creating the GitHub release, run the following and commit the result:

```sh
./scripts/prepare-changelog.sh <tag>
```

It moves the entries into `.changelog/<tag>/<PR>.md` and adds their PR links, taking each PR number from the
`(#N)` suffix of the commit that added the file. The publish workflow replaces the release page's notes with these
entries, and a final release also includes the entries of its pre-releases.

`unreleased/.gitkeep` keeps the directory alive: without it, git treats the release as a rename of `unreleased/`
and moves entries added on `next` in the meantime into the release directory when the release branch is merged
back.

After merging a release branch back into `next`, delete any `unreleased/` entry that already shipped in a release
directory (e.g. a cherry-picked fix).

Entries of earlier releases are in [`CHANGELOG.md`](../CHANGELOG.md).
