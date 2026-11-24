---
name: release
description: Cut a fistpumpd release - work out the version bump from what changed since the last tag, write the release notes, then tag and push so the release workflow tests, builds and publishes the binaries. Use when asked to "make a release", "cut a release", "release fistpumpd" or "tag a version".
---

# Cutting a release

A release is an `X.Y.Z` tag on main, with no `v` prefix. Pushing that tag runs
`.github/workflows/release.yml`: it checks the tag, runs the tests, builds
static binaries for `linux/amd64` and `linux/arm64`, and publishes them as that
tag's GitHub release together with a `SHA256SUMS` file. Everything this skill
does happens locally until the final push, so every decision can be changed
before anything is public.

There is no bot and no API key in CI: you read the changes and decide the bump
yourself. The release body is the annotated tag's message, so the notes you
write here are what users read.

## 1. Check the preconditions

Stop and report if either of these fails rather than working around it:

- The working tree is clean and the branch is `main`.
- `git fetch origin` then `git status -sb` shows main level with
  `origin/main`. Release what is pushed, never a local-only commit.

Then look at what CI has already said about the commit being released:

```bash
gh run list --commit "$(git rev-parse HEAD)" \
  --json workflowName,status,conclusion --jq '.[] | "\(.workflowName) \(.status) \(.conclusion // "")"'
```

**Never wait for a run that is still going.** The release job runs the tests on
the tagged commit itself, so an in-flight run is not a reason to hold the
release.

A run that has already **completed and failed** on that commit is worth
pausing for: name the workflow that failed and ask whether to release anyway.
Release on a yes. A red run is the user's call, not a veto, though the release
job will stop on its own failing tests.

## 2. Find what is being released

```bash
last=$(git describe --tags --match '[0-9]*' --abbrev=0 2>/dev/null)
```

With no version tag yet this is the first release: use the whole history, and
see the first-release note in section 4.

Read all three of these before deciding anything:

```bash
git log --format='%h %s%n%b' "$last..HEAD"
git diff --stat "$last..HEAD"
git diff "$last..HEAD" -- cluster/ cmd/ testdata/ docs/ Makefile .github/
```

The subjects alone are not enough: nothing in a subject says whether a change
is breaking. Read the diff.

## 3. Decide the bump

What this project publishes is a daemon that members of a cluster run side by
side, so its compatibility surface is what a member of the previous release
exchanges with a member of this one, what it left on disk, and what operators
and other units depend on.

**Breaking**: something that ran the previous release stops working, or needs
changing to keep working:

- the log's wire format changed: canonical JSON, entry hashes, signatures, the
  quorum rule, the RPC methods or their payloads, so that members on the two
  releases cannot verify or accept each other's entries (`testdata/vectors.json`
  changing is the tell)
- a `genesis.json`, topology or policy file that was valid is refused or means
  something else
- the state in `/var/lib/fistpumpd` (the log, the vote locks, the identity keys,
  the tokens) is read differently, so an existing member cannot restart
- the attestation procedure changed (TPM handles, the PCRs quoted, the binding
  of the qualifying data), so that a node of one release fails the other's check
- a CLI command or flag, or the control socket, was removed or renamed
- what the daemon writes for other units changed in a way that needs the
  operator to act: `/run/fistpumpd/k3s-ready`, the keepalived and k3s files, the
  machine tags, the unit and path names

**Feature**: something new that an old user does not notice: a fact or selector
operator, a command, an optional configuration key, a new published file.

**Fix**: everything else: a corrected check, a timing fix, docs, tests, CI,
refactors.

Then map that to a version. **While the version is `0.x`, the minor field is
the incompatible slot**, so both breaking and feature bump it:

| Verdict  | `0.1.0` becomes |
|----------|-----------------|
| breaking | `0.2.0`         |
| feature  | `0.2.0`         |
| fix      | `0.1.1`         |

Say in the summary which of the two a minor bump came from: the notes carry the
detail that the number cannot. Cutting `1.0.0` is a deliberate decision: never
do it on your own reading, only when the user asks for it by name.

Two things override your reading, in this order:

1. **What the user said.** "make a patch release" settles it; classify only
   when they did not say.
2. **A trailer on any commit in the range.** `Breaking-change: <what>` forces
   breaking, `Feature: <what>` forces at least feature. Normal commits need no
   trailer: the default is a fix.

## 4. Write the notes

Match the repository's voice: plain, direct, no emoji, no praise, no
"What's New". Present tense, saying what the release does rather than what was
committed.

Structure:

- One or two sentences saying what this release is, when there is a theme.
- Grouped bullets under `### ` headings by area (`Protocol`, `Attestation`,
  `Roles`, `Host configuration`, `CLI`, `Build and release`). Skip an empty
  group.
- A `### Breaking` section first, whenever there is one, saying what to change
  and in what order to roll it out across members.
- Leave out pure-CI, formatting and revert-of-an-unreleased-commit churn.
- Mark file names, paths, commands, flags and JSON keys as inline code.
- Do not paste addresses, keys or tokens from a real cluster.

The workflow appends what each published file is and how to verify it, so
leave that out of the notes. For the first release, describe what the daemon is
and what it does today rather than listing the whole history.

## 5. Show the user, then apply

Print the proposed version, one line on why that bump, and the full notes.
Wait for approval before touching anything.

**A release makes no commit.** The version lives in the tag alone: the binary's
`fistpumpd version` is the tag, set by the build, so there is nothing to bump.
Tag the commit that is already there:

```bash
version=X.Y.Z
git tag -a --cleanup=verbatim -F notes.md "$version"
```

`--cleanup=verbatim` is not optional: git's default cleanup strips every line
starting with `#` from a tag message, which would silently eat the notes'
Markdown headings. The tag must be annotated, because the release body is its
message.

Leave the build to CI: the release job builds the tagged commit, so there is no
need to run `make build` first.

## 6. Push

Pushing the tag publishes a release. **Always ask before pushing, even when the
user has already approved the version and the notes.** Show exactly what will be
pushed:

```bash
git push origin "$version"
```

Only the tag: main is already pushed, which section 1 checked.

If the user declines, leave the tag in place and say how to undo it
(`git tag -d $version`).

## 7. Watch the build

```bash
gh run watch "$(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
```

When it finishes, check the release carries `fistpumpd-amd64`,
`fistpumpd-arm64` and `SHA256SUMS`, and report the release URL.

If it fails, the tag stays and the release is absent or incomplete. Fix the
cause on main and cut the next patch version rather than moving the tag: a
moved tag breaks anyone who already fetched it.
