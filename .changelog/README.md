# Changelog entries

Every PR that changes behavior adds `unreleased/<PR number>.md` with one line per entry:

```markdown
- [BREAKING] Renamed `Foo` to `Bar` ([#1234](https://github.com/0xMiden/protocol/pull/1234)).
```

PRs that don't need an entry get the `no changelog` label.

To release, move the entries into a directory named after the tag before creating the GitHub release:

```sh
mkdir .changelog/<tag> && git mv .changelog/unreleased/*.md .changelog/<tag>/
```

Keep `unreleased/` itself (it holds a `.gitkeep`): if the whole directory is renamed, git moves entries
added on `next` in the meantime into the release directory when the release branch is merged back. The
publish workflow replaces the release page's notes with the tag's entries, and a final release also
includes the entries of its pre-releases.

After merging a release branch back into `next`, delete any `unreleased/` entry that already shipped in
a release directory (e.g. a cherry-picked fix).

Entries of earlier releases are in [`CHANGELOG.md`](../CHANGELOG.md).
