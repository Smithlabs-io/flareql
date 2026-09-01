# Contributing to flareql

## Filing an issue

Search existing issues first. Include:

- The command you ran (redact `--token`/zone IDs if you'd rather not share them)
- What you expected vs. what happened, with the actual error text
- Output of `flareql --zone <zone> --inspect` if it's a field/dataset-access question —
  most "field X doesn't work" reports turn out to be plan/entitlement gating, and
  `--inspect` proves that in one step

## Making a change

1. Branch from `main`.
2. Write the change with tests. The suite is fully offline (all HTTP mocked):
   ```sh
   python3 -m unittest test_flareql.py -v
   python3 -m coverage run -m unittest test_flareql.py && python3 -m coverage report -m
   ```
   CI posts your coverage % as a PR comment; the project currently sits at 100%, so a
   PR that drops it needs a good reason (untestable defensive code gets `pragma: no
   cover`, not a skipped test).
3. Keep to the project's existing style: stdlib only (`flareql.py` takes no pip
   dependencies — that's a stated goal, not an accident), no comments explaining *what*
   code does, only non-obvious *why*.
4. **Update `CHANGELOG.md` if the change is user-facing** — a new/changed flag, field,
   output shape, or behavior. Add a bullet under `## [Unreleased]`, in the matching
   [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) category (`Added`,
   `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`) — create the category
   heading if `[Unreleased]` doesn't have one yet. Skip this for internal-only changes
   (refactors, test-only changes, CI/workflow edits, typo fixes).
5. Open a PR against `main`. The `Tests` workflow runs automatically.
6. Address review feedback. Once approved and merged, your change is on `main` — see
   below for what happens next.

## Releases

Merging to `main` does **not** create a release. Releases are cut deliberately, on
demand — not automatically per merge — so a version number keeps meaning "we chose to
ship this," not "someone pressed the merge button." See
[docs/adr/0001-release-cadence.md](docs/adr/0001-release-cadence.md) for the reasoning.

Practically:

- `main` can carry several merged PRs' worth of `[Unreleased]` entries before anyone
  cuts a release. That's expected, not a backlog to clear urgently.
- When it's time to release: on `main`, rename `## [Unreleased]` in `CHANGELOG.md` to
  `## [vX.Y.Z] - YYYY-MM-DD` (pick the version per [Semantic Versioning](https://semver.org/):
  patch for fixes, minor for backward-compatible additions, major for breaking changes),
  then add a fresh empty `## [Unreleased]` above it. Commit that to `main` (directly or
  via a small "chore: release vX.Y.Z" PR).
- Run the **Release** workflow from the Actions tab (`workflow_dispatch` — no inputs).
  It reads the version and release notes straight from that dated `CHANGELOG.md`
  section, builds Linux amd64/arm64 binaries, tags the commit, and publishes the GitHub
  Release. It refuses to run if `CHANGELOG.md` has no new dated section above
  `[Unreleased]`, if that section is empty, or if the tag already exists — so a release
  can't happen by accident or get double-published.
