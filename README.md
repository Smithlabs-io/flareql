# flareql

**Query Cloudflare analytics like you write WAF rules.**

Pulls the Cloudflare dashboard's Security Analytics / Security Events "top N" panels
(top 150 ASNs, IPs, user agents, paths, hosts, JA4s, bot-score distribution, WAF attack
scores, rules fired, actions) via the GraphQL Analytics API — the views that have no
export/print button in the web UI. Stdlib only, no pip installs.

## Auth

Create an API token at dash.cloudflare.com → My Profile → API Tokens with:

- **Zone → Analytics → Read** (required)
- **Zone → Zone → Read** (needed to resolve zone names to IDs; skip if you always pass a 32-hex zone ID)

Then either:

```sh
export CLOUDFLARE_API_TOKEN=xxxx
# or per-run:
./flareql.py --token xxxx --zone smithlabs.io ...
```

Legacy global key also works: `--auth-email` / `--auth-key` or `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY`.

`--zone` is required: a zone name (`smithlabs.io`) or a 32-hex zone ID.

## Datasets

| Flag | GraphQL node | Dashboard equivalent | Dimensions |
|------|--------------|----------------------|------------|
| `--dataset http` | `httpRequestsAdaptiveGroups` | Security → Analytics (sampled traffic) | asn, ip, ua, country, host, path, ja4, botscore, status, botsrc, attackclass, security, cache (+opt-in: attackscore, sqli, xss, rce) |
| `--dataset firewall` | `firewallEventsAdaptiveGroups` | Security → Events (mitigations) | asn, ip, ua, country, host, path, ja4, action, rule |
| `--dataset both` (default) | both | both | all of the above |

Both datasets are **sampled** — each row reports raw `samples` plus `est_requests`
(samples × avg sampleInterval), which is what the dashboard shows. Percentages are
share of the whole filtered window.

### Dashboard "analysis tab" equivalents

| Dashboard tab | How to pull it |
|---------------|----------------|
| Request rate analysis | `--timeseries minute\|5min\|15min\|hour\|day` — request counts per bucket (console shows an ASCII rate chart + peak/avg req/s; full series in `--out`). Respects all filters, so `--asn 64496 --timeseries 5min` charts just that slice. |
| Bot analysis | `--dims botscore,botsrc,ja4` — score distribution, score source (machine_learning / heuristics / verified_bot...), fingerprints. Filter with `--bot-score-min/max` or `--where 'botscore lt 30'`. |
| Attack analysis | `--dims attackclass,security` for the class breakdown (attack / likely_attack / likely_clean / clean); add `--dims attackscore,sqli,xss,rce` for raw 1-99 score distributions (opt-in, not in `all`). Filter with `--where 'cf.waf.score lt 20'`. |
| Traffic analysis | `--dims security,cache,status` — what mitigated requests (securityAction + securitySource), served-by-cache vs origin (cacheStatus), response codes. |

Note: bot/attack scores exist only on the http dataset — firewall events carry rule
IDs and actions instead. For "what happened to scored traffic", use the http dataset's
`security` dim; use the firewall dataset for rule-ID detail, sliced by ASN/IP/JA4/path.

## `--inspect`: what can YOUR zone actually see?

Dataset and field access varies by zone plan and entitlements (firewall events need a
paid plan; `botscore`/`botsrc`/`ja4` need Bot Management; attack scores need WAF attack
scoring), and so does history retention. Cloudflare publishes no per-plan matrix, and
schema introspection can't answer this either — introspection reflects everything the
*token* can see across all its accounts, not what one zone's plan will actually serve.

`--inspect` checks the only authoritative way: it runs live `limit: 1` queries and
reads the API's refusals, dropping each field the error names until a query succeeds,
then reads the dataset's `settings` node for plan limits.

```sh
flareql --zone smithlabs.io --inspect                    # human-readable report
flareql --zone smithlabs.io --inspect --out report.json  # also write machine-readable
```

Example output for a free zone:

```
=== flareql inspect | smithlabs.io | plan: Free Website ===

[http] httpRequestsAdaptiveGroups: AVAILABLE
  limits:     history: 1d back max | window per query: 1d max | fields per query: 30 | rows per page: 10,000
  fields exposed on this zone (same names work as --dims, filter flags, and --where):
    cache           yes
    country         yes
    host            yes
    ip              yes
    method          yes
    path            yes
    status          yes
    ua              yes
    asn             no
    attackclass     no
    attackscore     no
    botscore        no
    botsrc          no
    ja4             no
    rce             no
    security        no
    securityaction  no
    sqli            no
    xss             no
  timeseries: minute, 5min, 15min, hour, day

[firewall] firewallEventsAdaptiveGroups: NOT AVAILABLE — plan-gated on this zone
```

Reading it:

- **limits › history** is how far back this zone's plan lets you query — a `--last`
  beyond it errors (the tool appends a hint pointing back here when that happens).
- **fields** is one unified list: the same short names drive `--dims`, the filter
  flags, and `--where`, and a field gated for one is gated for all of them. `partial`
  means only a secondary field is missing (e.g. ASN names) and flareql degrades
  automatically. If a name shows under `no`, no token permission change adds it —
  that's the zone's plan talking. (Token problems look different: inspect reports the
  permission error itself.)
- `--inspect` runs standalone: query flags like `--dims`/`--last`/filters are ignored
  with a warning; `--out` writes the JSON report (`--format csv` doesn't apply).

Cost: 3 queries per dataset on a fully-enabled zone, +1 per gated field.

## Timeframe

- Relative: `--last 6h`, `--last 3d`, `--last 2w` (default `24h`)
- Explicit: `--from 2026-08-11T00:00:00Z --to 2026-08-12T00:00:00Z` (bare dates OK: `--from 2026-08-11`)

## Filters (combine freely, all AND)

`--bot-score-min/--bot-score-max` (http only) · `--asn 64496` / `--asn AS64496` /
`--asn 64496,64497` · `--country RU` / `--country RU,VN` · `--host api.smithlabs.io` ·
`--path-contains /login` · `--ip 192.0.2.7` · `--ja4 t13d...` · `--action managed_challenge` (firewall only)

## `--where` expressions (OR logic the web UI can't do)

The GraphQL API doesn't take Cloudflare's WAF/wirefilter expression language directly,
but its filter objects support nested `AND`/`OR` — so `--where` parses a WAF-rule-style
expression and translates it. It combines (AND) with any other filter flags.

```sh
--where "asn in {64496 64497} or (botscore lt 30 and country eq RU)"
--where 'ip.geoip.asnum eq 64496 or cf.bot_management.score le 29'   # wirefilter names work
--where 'not (country eq US or country eq CA) and path starts_with "/login"'
--where 'path wildcard /user/*/settings and ua contains python'
```

- **Operators:** `and` `or` `not`, parens, `eq ne lt le gt ge` (or `== != < <= > >=`),
  `in {a b c}` (or `in (a, b, c)`), `contains`, `wildcard` (`*` → any), `starts_with`, `ends_with`
- **Fields:** `asn`, `country`, `ip`, `host`, `path`, `ua`, `ja4`, `botscore`, `status`,
  `method`, `botsrc`, `attackscore`, `sqli`, `xss`, `rce`, `securityaction`, `cache` (http)
  · `action`, `ruleid` (firewall) — plus wirefilter spellings (`ip.geoip.asnum`,
  `ip.geoip.country`, `http.host`, `http.request.uri.path`, `http.user_agent`,
  `cf.bot_management.score`, `cf.bot_management.ja4`, `cf.waf.score[.sqli|.xss|.rce]`, `ip.src`)
- **Not supported:** `matches` (regex) — the Analytics API has no regex operator; use
  `contains`/`wildcard`. Fields outside the list above (headers, cookies, TLS details)
  aren't exposed by these datasets.
- `not` is handled by operator negation (De Morgan), since the API has no NOT — so any
  `not` you write works, it just compiles to `_neq`/`_notin`/`_notlike`/flipped ranges.
- Precedence matches WAF rules: `and` binds tighter than `or`; use parens to override.
- If an expression references a field a dataset doesn't have (e.g. `botscore` on
  firewall), that dataset is skipped with a warning rather than silently dropping the
  condition.

## Recipes

```sh
# First run on a new zone: see what its plan exposes and how far back it can query
./flareql.py --zone smithlabs.io --inspect

# Everything, last 3 days, console tables
./flareql.py --zone smithlabs.io --last 3d

# One ASN's traffic, every lens
./flareql.py --zone smithlabs.io --last 3d --asn 64496 --dims ip,ua,path,host,country,botscore

# Low bot scores, raw JSON for further analysis
./flareql.py --zone smithlabs.io --last 3d --bot-score-max 29 --out band.json

# Which rules actually fired against two ASNs
./flareql.py --zone smithlabs.io --last 3d --asn 64496,64497 --dataset firewall --dims rule,action,ip

# CSVs, one file per dimension (http_asn.csv, firewall_rule.csv, ... + meta.json)
./flareql.py --zone smithlabs.io --last 3d --format csv --out ./pull/

# Complex slice with OR logic
./flareql.py --zone smithlabs.io --last 3d --dims ip,ua,ja4,path \
  --where "asn in {64496 64497} or (botscore lt 30 and country eq RU)"

# Request-rate curve for one ASN (5-minute buckets) + who scored its traffic
./flareql.py --zone smithlabs.io --last 3d --asn 64496 --timeseries 5min --dims botscore,botsrc,security
```

`--quiet` suppresses console tables when you only want the file output.

## Feeding DuckDB

```sql
-- JSON: one table per dimension
SELECT d.dimensions.clientAsn, d.dimensions.clientASNDescription,
       d.count AS samples, d.count * d.avg.sampleInterval AS est_requests
FROM (
  SELECT unnest(datasets.http.dims.asn.rows) AS d
  FROM read_json_auto('band.json')
);

-- CSV: direct
SELECT * FROM read_csv('pull/http_asn.csv');
```

## Installing as a command

The script is stdlib-only with a shebang, so a symlink is all it takes:

```sh
ln -sf "$(pwd)/flareql.py" ~/.local/bin/flareql
flareql --zone smithlabs.io --last 3d --asn 64496
```

No PyInstaller/zipapp needed unless you want to hand a single no-Python-required
binary to someone else — in that case `pipx run pyinstaller --onefile flareql.py`
produces one (~12MB).

## Tests

```sh
python3 -m unittest test_flareql.py -v          # run the suite
python3 -m coverage run -m unittest test_flareql.py && python3 -m coverage report -m
```

The suite is fully offline — all HTTP is mocked. Coverage is 100% of statements
(three defensive/entrypoint lines are `pragma: no cover`).

## Notes

- If a dimension errors (e.g. a zone/plan without JA4), the script warns and keeps
  going — you still get every other dimension.
- `clientAsn` is numeric in the http dataset and a string in firewall events; the
  script detects and flips automatically on the first query.
- Retention on adaptive datasets is plan-dependent (~30 days on Enterprise); windows
  past retention return an API error.
- API budget is ~300 GraphQL queries/5 min; a full `--dataset both --dims all` run
  costs ~25 queries.
