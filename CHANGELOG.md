# Changelog

All notable changes to flareql are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `content` field (`edgeResponseContentTypeName`) — filter/dim on Cloudflare's bucketed
  content-type category (`html`, `javascript`, `image`, ...). No wirefilter equivalent
  exists for this field; see README's "`--where` isn't real wirefilter" section.
- `attackclass` field (`wafAttackScoreClass`), with wirefilter alias `cf.waf.score.class`
  — was already a `--dims` lens, now also filterable via `--where`.

### Changed

- `--where` now emits a one-time stderr notice when a Cloudflare-deprecated wirefilter
  spelling (`ip.geoip.asnum`, `ip.geoip.country`) is used, naming the current replacement
  (`ip.src.asnum`, `ip.src.country`). Both spellings keep translating identically — this
  is a visibility change, not a behavior change. See README's "Deprecated wirefilter
  spellings" section for Cloudflare's own (undated) deprecation status.

## [1.0.1]

- See git history — predates this changelog.

## [1.0.0]

- Initial release.
