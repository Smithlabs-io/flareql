# Changelog

All notable changes to flareql are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]


## [1.0.2] - 2026-10-16

### Added

- `content` field (`edgeResponseContentTypeName`) — filter/dim on Cloudflare's bucketed
  content-type category (`html`, `javascript`, `image`, ...). No wirefilter equivalent2
  exists for this field; see README's "`--where` isn't real wirefilter" section.
- `attackclass` field (`wafAttackScoreClass`), with wirefilter alias `cf.waf.score.class`
  — was already a `--dims` lens, now also filterable via `--where`.

### Changed

- `--where` now emits a one-time stderr notice when a Cloudflare-deprecated wirefilter
  spelling (`ip.geoip.asnum`, `ip.geoip.country`) is used, naming the current replacement
  (`ip.src.asnum`, `ip.src.country`). Both spellings keep translating identically — this
  is a visibility change, not a behavior change. See README's "Deprecated wirefilter
  spellings" section for Cloudflare's own (undated) deprecation status.

### Fixed

- `cf.verified_bot` / `cf.bot_management.verified_bot` filters failed on every run with
  `unknown arg verifiedBot`: the GraphQL API has no boolean `verifiedBot` argument. The
  field now maps to `verifiedBotCategory` (`eq true` -> `verifiedBotCategory_neq: ""`,
  `eq false` -> `verifiedBotCategory: ""`). It is the closest available signal and can
  differ slightly from the `verified_bot` bot score source (`--dims botsrc`).
- `--where` that can't be applied to any selected dataset now exits 1 with an error
  instead of exiting 0 with an empty-looking output.

## [1.0.1] - 2026-08-19

- See git history — predates this changelog.

## [1.0.0] - 2026-08-17

- Initial release.

[Unreleased]: https://github.com/Smithlabs-io/flareql/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Smithlabs-io/flareql/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Smithlabs-io/flareql/releases/tag/v1.0.0
