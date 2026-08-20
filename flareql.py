#!/usr/bin/env python3
"""
flareql.py — Pull "top N" Security Analytics views from Cloudflare's GraphQL API.

Reproduces the dashboard panels that have no export button — top ASNs, top client IPs,
top user agents, top paths/hosts/JA4s, bot-score distribution (Security > Analytics),
and top rules/actions (Security > Events) — as console tables, JSON, or CSV.

Datasets:
  http     -> httpRequestsAdaptiveGroups   (sampled HTTP traffic: botScore, ASN, IP, UA, JA4...)
  firewall -> firewallEventsAdaptiveGroups (mitigation/log events: action, ruleId, source...)

Auth (either):
  --token TOKEN            or env CLOUDFLARE_API_TOKEN / CF_API_TOKEN
  --auth-email/--auth-key  or env CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY (legacy global key)
  Token needs Zone > Analytics:Read (+ Zone:Read to resolve zone names to IDs).

Timeframe (either):
  --last 6h | 3d | 2w            relative window ending now (h/d/w suffixes)
  --from/--to ISO timestamps     e.g. --from 2026-08-11T00:00:00Z --to 2026-08-12T00:00:00Z

Examples:
  # Top 150 everything, last 3 days, human-readable
  flareql.py --zone smithlabs.io --last 3d

  # Only low bot scores, JSON out
  flareql.py --zone smithlabs.io --last 3d --bot-score-max 29 --out band.json

  # Top IPs/UAs/paths inside one ASN
  flareql.py --zone smithlabs.io --last 3d --asn 64496 --dims ip,ua,path,botscore

  # What firewall rules actually fired on that slice
  flareql.py --zone smithlabs.io --last 3d --asn 64496 --dataset firewall --dims rule,action,ip

  # WAF-style expression with OR (the web UI can't do this)
  flareql.py --zone smithlabs.io --last 3d \
      --where "asn in {64496 64497} or (botscore lt 30 and country eq RU)"

  # Request-rate curve for a slice + CSVs (one per dimension) into a directory
  flareql.py --zone smithlabs.io --last 3d --timeseries 5min --format csv --out ./pull/

  # What can THIS zone's plan actually see, and how far back? (plan gating is per zone)
  flareql.py --zone smithlabs.io --inspect
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

API_BASE = "https://api.cloudflare.com/client/v4"
GRAPHQL_URL = API_BASE + "/graphql"

DATASETS = {
    "http": "httpRequestsAdaptiveGroups",
    "firewall": "firewallEventsAdaptiveGroups",
}

# dim key -> (graphql dimension fields, human title)
HTTP_DIMS = {
    "asn": (["clientAsn", "clientASNDescription"], "Top ASNs"),
    "ip": (["clientIP"], "Top client IPs"),
    "ua": (["userAgent"], "Top user agents"),
    "country": (["clientCountryName"], "Top countries"),
    "host": (["clientRequestHTTPHost"], "Top hosts"),
    "path": (["clientRequestPath"], "Top paths"),
    "ja4": (["ja4"], "Top JA4 fingerprints"),
    "botscore": (["botScore"], "Bot score distribution"),
    "status": (["edgeResponseStatus"], "Edge response status codes"),
    # dashboard "Bot analysis" tab
    "botsrc": (["botScoreSrcName"], "Bot score sources"),
    # dashboard "Attack analysis" tab
    "attackclass": (["wafAttackScoreClass"], "WAF attack score classes"),
    "attackscore": (["wafAttackScore"], "WAF attack score distribution"),
    "sqli": (["wafSqliAttackScore"], "SQLi attack score distribution"),
    "xss": (["wafXssAttackScore"], "XSS attack score distribution"),
    "rce": (["wafRceAttackScore"], "RCE attack score distribution"),
    # dashboard "Traffic analysis" tab
    "security": (["securityAction", "securitySource"], "Security actions applied"),
    "cache": (["cacheStatus"], "Cache status"),
}

# raw per-point score distributions are opt-in, not part of --dims all
DEFAULT_SKIP_DIMS = {"attackscore", "sqli", "xss", "rce"}
# distributions that read better sorted by value than by count
NUMERIC_SORT_DIMS = {"botscore", "attackscore", "sqli", "xss", "rce"}

TIMESERIES_BUCKETS = {
    "minute": ("datetimeMinute", 60),
    "5min": ("datetimeFiveMinutes", 300),
    "15min": ("datetimeFifteenMinutes", 900),
    "hour": ("datetimeHour", 3600),
    "day": ("date", 86400),
}

FIREWALL_DIMS = {
    "asn": (["clientAsn", "clientASNDescription"], "Top ASNs"),
    "ip": (["clientIP"], "Top client IPs"),
    "ua": (["userAgent"], "Top user agents"),
    "country": (["clientCountryName"], "Top countries"),
    "host": (["clientRequestHTTPHost"], "Top hosts"),
    "path": (["clientRequestPath"], "Top paths"),
    "ja4": (["ja4"], "Top JA4 fingerprints"),
    "action": (["action"], "Actions taken"),
    "rule": (["ruleId", "source"], "Top rules fired"),
}

TRUNCATE = {"userAgent": 100, "clientRequestPath": 90, "clientRequestHTTPHost": 60}


def warn(msg):
    print(f"[warn] {msg}", file=sys.stderr)


def die(msg):
    print(f"[error] {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- auth / http

def build_headers(args):
    token = args.token or os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN")
    email = args.auth_email or os.environ.get("CLOUDFLARE_EMAIL")
    key = args.auth_key or os.environ.get("CLOUDFLARE_API_KEY")
    headers = {"Content-Type": "application/json", "User-Agent": "flareql/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif email and key:
        headers["X-Auth-Email"] = email
        headers["X-Auth-Key"] = key
    else:
        die("no credentials: pass --token, or set CLOUDFLARE_API_TOKEN, "
            "or use --auth-email/--auth-key (CLOUDFLARE_EMAIL/CLOUDFLARE_API_KEY)")
    return headers


def http_json(url, headers, body=None, timeout=60, max_tries=4):
    data = json.dumps(body).encode() if body is not None else None
    last_err = None
    for attempt in range(max_tries):
        req = urlrequest.Request(url, data=data, headers=headers,
                                 method="POST" if data else "GET")
        try:
            with urlrequest.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except urlerror.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode(errors="replace")[:600]
            except Exception:
                pass
            if e.code in (429, 500, 502, 503, 504) and attempt < max_tries - 1:
                wait = 2 ** attempt
                warn(f"HTTP {e.code}, retrying in {wait}s...")
                time.sleep(wait)
                last_err = f"HTTP {e.code}: {detail}"
                continue
            die(f"HTTP {e.code} from {url}: {detail}")
        except urlerror.URLError as e:
            if attempt < max_tries - 1:
                time.sleep(2 ** attempt)
                last_err = str(e)
                continue
            die(f"network error talking to {url}: {e}")
    die(f"exhausted retries: {last_err}")  # pragma: no cover — loop always returns or dies


def gql(headers, query, timeout):
    payload = http_json(GRAPHQL_URL, headers, body={"query": query}, timeout=timeout)
    return payload.get("data"), payload.get("errors") or []


# ---------------------------------------------------------------- zone lookup

def resolve_zone(headers, zone_arg, timeout):
    """Return (zone_id, zone_name, plan_name). Accepts a 32-hex zone ID or a zone
    name; plan_name is None when the zone is passed as a bare ID."""
    if re.fullmatch(r"[0-9a-f]{32}", zone_arg):
        return zone_arg, zone_arg, None
    name = zone_arg
    resp = http_json(f"{API_BASE}/zones?name={urlparse.quote(name)}", headers, timeout=timeout)
    result = resp.get("result") or []
    if result:
        plan = (result[0].get("plan") or {}).get("name")
        return result[0]["id"], result[0]["name"], plan
    # Not found — list what the token can see to help the user correct the name
    resp = http_json(f"{API_BASE}/zones?per_page=50", headers, timeout=timeout)
    names = ", ".join(z["name"] for z in (resp.get("result") or [])) or "(none visible)"
    die(f"zone '{name}' not found. Zones this token can see: {names}")


# ---------------------------------------------------------------- timeframe

def parse_timestamp(s):
    s = s.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        s += "T00:00:00+00:00"
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        die(f"can't parse timestamp '{s}' — use ISO 8601, e.g. 2026-08-11T00:00:00Z")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_window(args):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if args.from_ts or args.to_ts:
        if not (args.from_ts and args.to_ts):
            die("--from and --to must be given together")
        start, end = parse_timestamp(args.from_ts), parse_timestamp(args.to_ts)
    else:
        m = re.fullmatch(r"(\d+)\s*(h|hr|hrs|hour|hours|d|day|days|w|wk|week|weeks)",
                         args.last.strip().lower())
        if not m:
            die(f"can't parse --last '{args.last}' — use forms like 6h, 24hr, 3d, 2w")
        n, unit = int(m.group(1)), m.group(2)[0]
        delta = {"h": timedelta(hours=n), "d": timedelta(days=n), "w": timedelta(weeks=n)}[unit]
        start, end = now - delta, now
    if start >= end:
        die("start of window must be before end")
    if end - start > timedelta(days=25):
        warn("window exceeds ~25 days — Cloudflare may reject it depending on plan retention")
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return start.strftime(fmt), end.strftime(fmt)


# ---------------------------------------------------------------- filters

def to_gql_literal(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(to_gql_literal(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{k}: {to_gql_literal(x)}" for k, x in v.items()) + "}"
    return json.dumps(str(v))


def split_multi(raw):
    return [p.strip() for p in raw.split(",") if p.strip()]


def build_filter(args, dataset_key, since, until, asn_as_string):
    f = {"datetime_geq": since, "datetime_leq": until}
    if args.asn:
        asns = [re.sub(r"(?i)^as", "", a) for a in split_multi(args.asn)]
        for a in asns:
            if not a.isdigit():
                die(f"--asn value '{a}' is not numeric (accepts 64496 or AS64496, comma-separated)")
        vals = [a if asn_as_string else int(a) for a in asns]
        if len(vals) == 1:
            f["clientAsn"] = vals[0]
        else:
            f["clientAsn_in"] = vals
    if args.country:
        countries = [c.upper() for c in split_multi(args.country)]
        if len(countries) == 1:
            f["clientCountryName"] = countries[0]
        else:
            f["clientCountryName_in"] = countries
    if args.host:
        f["clientRequestHTTPHost"] = args.host
    if args.path_contains:
        f["clientRequestPath_like"] = f"%{args.path_contains}%"
    if args.ip:
        f["clientIP"] = args.ip
    if args.ja4:
        f["ja4"] = args.ja4
    if dataset_key == "http":
        if args.bot_score_min is not None:
            f["botScore_geq"] = args.bot_score_min
        if args.bot_score_max is not None:
            f["botScore_leq"] = args.bot_score_max
    if dataset_key == "firewall" and args.action:
        f["action"] = args.action
    return f


# ---------------------------------------------------------------- --where expressions
#
# The GraphQL API doesn't accept Cloudflare's wirefilter/WAF expression language,
# but its filter objects support AND/OR arrays and negated operators — so we parse
# a WAF-rule-style subset and translate. Supported: and/or/not, parens,
# eq ne lt le gt ge == != < <= > >=, `in {a b c}`, contains, wildcard,
# starts_with, ends_with. `matches` (regex) has no API equivalent.

class ExprError(Exception):
    pass


# canonical field -> (graphql field, type, datasets it exists on)
WHERE_FIELDS = {
    "asn":      ("clientAsn", "asn", ("http", "firewall")),
    "country":  ("clientCountryName", "str", ("http", "firewall")),
    "ip":       ("clientIP", "str", ("http", "firewall")),
    "host":     ("clientRequestHTTPHost", "str", ("http", "firewall")),
    "path":     ("clientRequestPath", "str", ("http", "firewall")),
    "ua":       ("userAgent", "str", ("http", "firewall")),
    "ja4":      ("ja4", "str", ("http", "firewall")),
    "botscore": ("botScore", "int", ("http",)),
    "status":   ("edgeResponseStatus", "int", ("http",)),
    "method":   ("clientRequestHTTPMethodName", "str", ("http",)),
    "botsrc":   ("botScoreSrcName", "str", ("http",)),
    "attackscore": ("wafAttackScore", "int", ("http",)),
    "sqli":     ("wafSqliAttackScore", "int", ("http",)),
    "xss":      ("wafXssAttackScore", "int", ("http",)),
    "rce":      ("wafRceAttackScore", "int", ("http",)),
    "securityaction": ("securityAction", "str", ("http",)),
    "cache":    ("cacheStatus", "str", ("http",)),
    "verifiedbot": ("verifiedBot", "bool", ("http",)),
    "action":   ("action", "str", ("firewall",)),
    "ruleid":   ("ruleId", "str", ("firewall",)),
}

# wirefilter names (as used in WAF rule expressions) -> canonical
WHERE_ALIASES = {
    "ip.geoip.asnum": "asn", "ip.src.asnum": "asn",
    "ip.geoip.country": "country", "ip.src.country": "country",
    "ip.src": "ip",
    "http.host": "host",
    "http.request.uri.path": "path", "uri.path": "path",
    "http.user_agent": "ua", "useragent": "ua",
    "cf.bot_management.ja4": "ja4",
    "cf.bot_management.score": "botscore", "score": "botscore",
    "http.response.code": "status",
    "http.request.method": "method",
    "cf.waf.score": "attackscore", "waf.score": "attackscore",
    "cf.waf.score.sqli": "sqli", "cf.waf.score.xss": "xss", "cf.waf.score.rce": "rce",
    "cf.bot_management.verified_bot": "verifiedbot",
    "cf.verified_bot": "verifiedbot",
}

KEYWORDS = {"and", "or", "not", "in", "eq", "ne", "lt", "le", "gt", "ge",
            "contains", "matches", "wildcard", "starts_with", "ends_with"}

OP_NORMALIZE = {"eq": "eq", "==": "eq", "ne": "neq", "!=": "neq",
                "lt": "lt", "<": "lt", "le": "leq", "<=": "leq",
                "gt": "gt", ">": "gt", "ge": "geq", ">=": "geq",
                "in": "in", "contains": "contains", "wildcard": "wildcard",
                "starts_with": "starts", "ends_with": "ends"}

OP_NEGATE = {"eq": "neq", "neq": "eq", "lt": "geq", "geq": "lt",
             "leq": "gt", "gt": "leq", "in": "notin", "notin": "in",
             "contains": "notcontains", "notcontains": "contains",
             "wildcard": "notwildcard", "notwildcard": "wildcard",
             "starts": "notstarts", "notstarts": "starts",
             "ends": "notends", "notends": "ends"}

_WHERE_TOKEN = re.compile(r"""
    (?P<lparen>\() | (?P<rparen>\)) |
    (?P<lbrace>\{) | (?P<rbrace>\}) |
    (?P<comma>,) |
    (?P<op>==|!=|<=|>=|<|>) |
    (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*') |
    (?P<word>[\w./*][\w.:*/\-]*)
""", re.X)


def tokenize_where(s):
    toks, i, n = [], 0, len(s)
    while i < n:
        if s[i].isspace():
            i += 1
            continue
        m = _WHERE_TOKEN.match(s, i)
        if not m:
            raise ExprError(f"unexpected character at position {i}: {s[i:i+15]!r}")
        kind, val = m.lastgroup, m.group(m.lastgroup)
        if kind == "word" and val.lower() in KEYWORDS:
            toks.append(("kw", val.lower()))
        elif kind == "string":
            toks.append(("value", re.sub(r"\\(.)", r"\1", val[1:-1])))
        elif kind == "word":
            toks.append(("word", val))
        else:
            toks.append((kind, val))
        i = m.end()
    return toks


class WhereParser:
    """Recursive descent over: or := and ('or' and)* ; and := unary ('and' unary)* ;
    unary := 'not' unary | '(' or ')' | comparison"""

    def __init__(self, tokens):
        self.toks = tokens
        self.i = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def advance(self):
        tok = self.peek()
        self.i += 1
        return tok

    def parse(self):
        if not self.toks:
            raise ExprError("empty expression")
        node = self.parse_or()
        if self.i < len(self.toks):
            raise ExprError(f"unexpected trailing input near {self.toks[self.i][1]!r}")
        return node

    def parse_or(self):
        parts = [self.parse_and()]
        while self.peek() == ("kw", "or"):
            self.advance()
            parts.append(self.parse_and())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def parse_and(self):
        parts = [self.parse_unary()]
        while self.peek() == ("kw", "and"):
            self.advance()
            parts.append(self.parse_unary())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def parse_unary(self):
        kind, val = self.peek()
        if (kind, val) == ("kw", "not"):
            self.advance()
            return ("not", self.parse_unary())
        if kind == "lparen":
            self.advance()
            node = self.parse_or()
            if self.advance()[0] != "rparen":
                raise ExprError("missing closing ')'")
            return node
        # function-call form: starts_with(field, value) / ends_with(field, value)
        if kind == "kw" and val in ("starts_with", "ends_with"):
            self.advance()
            if self.peek()[0] != "lparen":
                raise ExprError(
                    f"'{val}' used as a function requires '(' — "
                    f"or use infix form: field {val} value"
                )
            self.advance()  # consume (
            fkind, field = self.advance()
            if fkind != "word":
                raise ExprError(f"expected a field name as first argument to {val}()")
            if self.advance()[0] != "comma":
                raise ExprError(f"expected ',' after field name in {val}(field, value)")
            vkind, value = self.advance()
            if vkind not in ("word", "value"):
                raise ExprError(f"expected a string value as second argument to {val}()")
            if self.advance()[0] != "rparen":
                raise ExprError(f"expected ')' to close {val}()")
            op = "starts" if val == "starts_with" else "ends"
            return ("cmp", field, op, [value])
        return self.parse_cmp()

    def parse_cmp(self):
        kind, field = self.advance()
        if kind != "word":
            raise ExprError(f"expected a field name, got {field!r}")
        # standalone boolean: cf.bot_management.verified_bot (no operator follows)
        # wirefilter allows bare boolean fields as truthy checks — de-sugar to `field eq true`
        next_kind, next_val = self.peek()
        is_operator = (next_kind == "op") or (next_kind == "kw" and next_val in OP_NORMALIZE)
        if not is_operator:
            try:
                canon = resolve_where_field(field)
                if WHERE_FIELDS[canon][1] == "bool":
                    return ("cmp", field, "eq", ["true"])
            except ExprError:
                pass
        kind, op = self.advance()
        if kind == "op" or (kind == "kw" and op in OP_NORMALIZE):
            op = OP_NORMALIZE[op]
        elif (kind, op) == ("kw", "matches"):
            raise ExprError("'matches' (regex) isn't supported by the Analytics API — "
                            "use contains or wildcard")
        else:
            raise ExprError(f"expected an operator after '{field}', got {op!r}")
        if op == "in":
            kind, _ = self.advance()
            if kind not in ("lbrace", "lparen"):
                raise ExprError(f"'in' expects a {{a b c}} list after '{field}'")
            closer = "rbrace" if kind == "lbrace" else "rparen"
            values = []
            while True:
                kind, val = self.advance()
                if kind == closer:
                    break
                if kind == "comma":
                    continue
                if kind in ("word", "value"):
                    values.append(val)
                else:
                    raise ExprError(f"bad value in 'in' list for '{field}': {val!r}")
            if not values:
                raise ExprError(f"'in' list for '{field}' is empty")
            return ("cmp", field, "in", values)
        kind, val = self.advance()
        if kind not in ("word", "value"):
            raise ExprError(f"expected a value after '{field} {op}', got {val!r}")
        return ("cmp", field, op, [val])


def resolve_where_field(name):
    key = name.lower()
    key = WHERE_ALIASES.get(key, key)
    if key not in WHERE_FIELDS:
        known = ", ".join(sorted(set(WHERE_FIELDS) | set(WHERE_ALIASES)))
        raise ExprError(f"unknown field '{name}' — known fields: {known}")
    return key


def where_cmp_to_filter(field, op, values, dataset_key, asn_as_string):
    canon = resolve_where_field(field)
    gql_field, typ, datasets = WHERE_FIELDS[canon]
    if dataset_key not in datasets:
        hint = ""
        if dataset_key == "firewall":
            hint = (" (firewall events carry no bot/attack scores — the http dataset's "
                    "'security' dim shows mitigation outcomes for scored traffic instead)")
        raise ExprError(f"field '{field}' doesn't exist on the {dataset_key} dataset{hint}")

    def coerce(v):
        if typ == "bool":
            if str(v).lower() in ("true", "1"):
                return True
            if str(v).lower() in ("false", "0"):
                return False
            raise ExprError(f"'{field}' is a boolean field — use 'true' or 'false', got {v!r}")
        if typ == "asn":
            v = re.sub(r"(?i)^as", "", str(v))
            if not v.isdigit():
                raise ExprError(f"ASN value {v!r} is not numeric")
            return v if asn_as_string else int(v)
        if typ == "int":
            try:
                return int(v)
            except ValueError:
                raise ExprError(f"'{field}' expects a number, got {v!r}")
        return str(v)

    if op in ("in", "notin"):
        return {f"{gql_field}_{'in' if op == 'in' else 'notin'}": [coerce(v) for v in values]}
    v = values[0]
    if op == "eq":
        return {gql_field: coerce(v)}
    if op == "neq":
        # boolean fields: flip the value instead of using _neq (API doesn't support it for bools)
        if typ == "bool":
            return {gql_field: not coerce(v)}
        return {f"{gql_field}_neq": coerce(v)}
    if op in ("lt", "leq", "gt", "geq"):
        if typ == "str":
            raise ExprError(f"'{op}' isn't valid for string field '{field}'")
        return {f"{gql_field}_{op}": coerce(v)}
    # string pattern ops -> _like / _notlike (% is the wildcard)
    if typ != "str":
        raise ExprError(f"'{op}' isn't valid for numeric field '{field}'")
    s = str(v)
    patterns = {"contains": f"%{s}%", "notcontains": f"%{s}%",
                "starts": f"{s}%", "notstarts": f"{s}%",
                "ends": f"%{s}", "notends": f"%{s}",
                "wildcard": s.replace("*", "%"), "notwildcard": s.replace("*", "%")}
    suffix = "_notlike" if op.startswith("not") else "_like"
    return {gql_field + suffix: patterns[op]}


def translate_where(node, dataset_key, asn_as_string, negate=False):
    kind = node[0]
    if kind == "not":
        return translate_where(node[1], dataset_key, asn_as_string, not negate)
    if kind in ("and", "or"):
        # De Morgan under negation: not(a and b) == (not a) or (not b)
        effective = ("or" if kind == "and" else "and") if negate else kind
        children = [translate_where(c, dataset_key, asn_as_string, negate) for c in node[1]]
        return {effective.upper(): children}
    _, field, op, values = node
    if negate:
        op = OP_NEGATE[op]
    return where_cmp_to_filter(field, op, values, dataset_key, asn_as_string)


# ---------------------------------------------------------------- queries

def build_query(zone_id, dataset_node, fields, flt, limit, include_avg, order_by):
    sel = ["count"]
    if include_avg:
        sel.append("avg { sampleInterval }")
    if fields:
        sel.append("dimensions { " + " ".join(fields) + " }")
    order = f", orderBy: [{order_by}]" if order_by else ""
    return (
        "{ viewer { zones(filter: {zoneTag: %s}) { result: %s(limit: %d, filter: %s%s) { %s } } } }"
        % (json.dumps(zone_id), dataset_node, limit, to_gql_literal(flt), order, " ".join(sel))
    )


def extract_rows(data):
    zones = ((data or {}).get("viewer") or {}).get("zones") or []
    if not zones:
        return None
    return zones[0].get("result") or []


def query_grouped(headers, zone_id, dataset_node, fields, flt, limit, timeout, order_by="count_DESC"):
    """Run one grouped query. Returns (rows, error_message). Retries with degraded
    field sets when the schema rejects an optional field (e.g. zones without a
    given field, or datasets lacking clientASNDescription/ja4)."""
    fields = list(fields) if fields else []
    include_avg = True
    for _ in range(4):
        q = build_query(zone_id, dataset_node, fields, flt, limit, include_avg, order_by if fields else None)
        data, errors = gql(headers, q, timeout)
        if not errors:
            rows = extract_rows(data)
            if rows is None:
                return None, "no zones in response — token likely lacks Analytics:Read on this zone"
            return rows, None
        msg = "; ".join(e.get("message", "") for e in errors)
        if "clientASNDescription" in msg and "clientASNDescription" in fields:
            fields.remove("clientASNDescription")
            continue
        if "sampleInterval" in msg and include_avg:
            include_avg = False
            continue
        return None, msg
    return None, "gave up after repeated schema fallbacks"  # pragma: no cover — each fallback fires at most once


def estimated_requests(row):
    count = row.get("count", 0)
    avg = (row.get("avg") or {}).get("sampleInterval")
    if avg:
        return int(round(count * avg))
    return count


# ---------------------------------------------------------------- --inspect (capability probing)
#
# Cloudflare enforces dataset/field access per zone plan + entitlements at QUERY
# time and publishes no per-plan matrix. Schema introspection is not authoritative
# for this: it reflects the token's whole view (a token spanning an Enterprise and
# a Free account introspects the union), so a field can introspect fine yet refuse
# at query time. The only reliable check is running real queries and reading the
# refusals — --inspect issues limit-1 queries over a 15-minute window, dropping
# each field the API names as inaccessible until a query succeeds, then reads the
# dataset's settings node for plan limits (retention, max window, query caps).

_GATED_FIELD_RES = (
    re.compile(r"does not have access to the field '([^']+)'"),
    re.compile(r'[Cc]annot query field "([^"]+)"'),
    re.compile(r'[Ff]ield "([^"]+)" is not defined'),
)

SETTINGS_FIELDS = ["enabled", "maxDuration", "maxNumberOfFields", "maxPageSize",
                   "notOlderThan"]


def parse_gated_field(msg):
    for rx in _GATED_FIELD_RES:
        m = rx.search(msg)
        if m:
            return m.group(1)
    return None


def error_hint(err):
    """Append a plain-language hint to raw API errors users repeatedly hit."""
    if "older than" in err:
        return err + " [hint: the zone plan's retention limit — shorten --last; run --inspect to see this zone's limits]"
    if "does not have access" in err:
        return err + " [hint: plan/entitlement gating — run --inspect to see what this zone exposes]"
    return err


def fmt_secs(s):
    if s % 86400 == 0:
        return f"{s // 86400}d"
    if s % 3600 == 0:
        return f"{s // 3600}h"
    return f"{s}s"


def inspect_dataset(headers, zone_id, ds_key, node, timeout):
    """Execution-probe one dataset. Returns (status, ok_fields, gated_fields, err)
    where status is one of: ok, unavailable, error."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    base_flt = {"datetime_geq": (now - timedelta(minutes=15)).strftime(fmt),
                "datetime_leq": now.strftime(fmt)}
    q = build_query(zone_id, node, [], base_flt, 1, False, None)
    data, errors = gql(headers, q, timeout)
    if errors:
        return "unavailable", set(), [], "; ".join(e.get("message", "") for e in errors)
    if extract_rows(data) is None:
        return "unavailable", set(), [], ("no zones in response — token likely lacks "
                                          "Analytics:Read on this zone")

    registry = HTTP_DIMS if ds_key == "http" else FIREWALL_DIMS
    candidates = {f for fields, _title in registry.values() for f in fields}
    candidates |= {f for f, _secs in TIMESERIES_BUCKETS.values()}
    # --where-only fields (e.g. method) are valid dimensions too — probe them the same way
    candidates |= {gf for gf, _typ, dsets in WHERE_FIELDS.values() if ds_key in dsets}
    active, gated = set(candidates), []
    while True:
        q = build_query(zone_id, node, sorted(active), base_flt, 1, False, None)
        data, errors = gql(headers, q, timeout)
        if not errors:
            return "ok", active, gated, None
        msg = "; ".join(e.get("message", "") for e in errors)
        name = (parse_gated_field(msg) or "").lower()
        match = next((f for f in active if f.lower() == name), None)
        if not match:
            return "error", active, gated, msg
        active.remove(match)
        gated.append(match)


def get_dataset_settings(headers, zone_id, node, timeout):
    """Fetch the dataset's settings node (plan limits: retention, max window, caps).
    Degrades field-by-field like the probe; returns a dict or None."""
    fields = list(SETTINGS_FIELDS)
    while fields:
        q = ("{ viewer { zones(filter: {zoneTag: %s}) { settings { %s { %s } } } } }"
             % (json.dumps(zone_id), node, " ".join(fields)))
        data, errors = gql(headers, q, timeout)
        if errors:
            msg = "; ".join(e.get("message", "") for e in errors)
            name = (parse_gated_field(msg) or "").lower()
            match = next((f for f in fields if f.lower() == name), None)
            if not match:
                return None
            fields.remove(match)
            continue
        zones = ((data or {}).get("viewer") or {}).get("zones") or []
        if not zones:
            return None
        return (zones[0].get("settings") or {}).get(node)
    return None


def run_inspect(headers, zone_id, zone_name, zone_plan, timeout, out_path=None, quiet=False):
    def say(line):
        if not quiet:
            print(line)

    report = {"zone": zone_name, "zone_id": zone_id, "plan": zone_plan, "datasets": {}}
    say(f"=== flareql inspect | {zone_name}"
        + (f" | plan: {zone_plan}" if zone_plan else "") + " ===")
    for ds_key, node in DATASETS.items():
        registry = HTTP_DIMS if ds_key == "http" else FIREWALL_DIMS
        status, ok_fields, gated, err = inspect_dataset(headers, zone_id, ds_key, node, timeout)
        if status == "unavailable":
            reason = "plan-gated on this zone" if "not have access" in err else err
            say(f"\n[{ds_key}] {node}: NOT AVAILABLE — {reason}")
            report["datasets"][ds_key] = {"available": False, "error": err}
            continue
        if status == "error":
            warn(f"[{ds_key}] inspect aborted on an unrecognized error: {err}")
            say(f"\n[{ds_key}] {node}: AVAILABLE (inspect incomplete — see warning)")
            report["datasets"][ds_key] = {"available": True, "error": err,
                                          "gated_graphql_fields": gated}
            continue
        say(f"\n[{ds_key}] {node}: AVAILABLE")
        settings = get_dataset_settings(headers, zone_id, node, timeout)
        if settings:
            parts = []
            if settings.get("notOlderThan"):
                parts.append(f"history: {fmt_secs(settings['notOlderThan'])} back max")
            if settings.get("maxDuration"):
                parts.append(f"window per query: {fmt_secs(settings['maxDuration'])} max")
            if settings.get("maxNumberOfFields"):
                parts.append(f"fields per query: {settings['maxNumberOfFields']}")
            if settings.get("maxPageSize"):
                parts.append(f"rows per page: {settings['maxPageSize']:,}")
            if parts:
                say("  limits:     " + " | ".join(parts))
        names, missing_by_name = {}, {}
        for dim_key, (fields, _title) in registry.items():
            missing = [f for f in fields if f not in ok_fields]
            names[dim_key] = ("yes" if not missing
                              else "partial" if fields[0] in ok_fields else "no")
            missing_by_name[dim_key] = missing
        for wname, (gf, _typ, dsets) in WHERE_FIELDS.items():
            if ds_key in dsets and wname not in names:
                names[wname] = "yes" if gf in ok_fields else "no"
                missing_by_name[wname] = [] if gf in ok_fields else [gf]
        say("  fields exposed on this zone (same names work as --dims, filter flags, and --where):")
        width = max(len(n) for n in names)
        status_rank = {"yes": 0, "partial": 1, "no": 2}
        for n in sorted(names, key=lambda k: (status_rank[names[k]], k)):
            label = names[n]
            if label == "partial":
                label = (f"partial (missing {', '.join(missing_by_name[n])} "
                         "— flareql degrades automatically)")
            say(f"    {n.ljust(width)}  {label}")
        ts_ok = [k for k, (f, _s) in TIMESERIES_BUCKETS.items() if f in ok_fields]
        say("  timeseries: " + (", ".join(ts_ok) or "(none)"))
        report["datasets"][ds_key] = {
            "available": True, "settings": settings,
            "fields": {n: {"status": names[n], "missing": missing_by_name[n]} for n in names},
            "timeseries": ts_ok, "gated_graphql_fields": gated,
        }
    say("\nNotes: results come from live limit-1 queries (schema introspection reflects the"
        "\ntoken's whole account view, not this zone's plan, so it can't answer this)."
        "\nNOT AVAILABLE = the zone's plan lacks the dataset entirely. 'no' fields = plan or"
        "\nentitlement gating (botscore/botsrc/ja4 need Bot Management; attack scores need"
        "\nWAF attack scoring) — no token permission change adds them. 'history' is how far"
        "\nback this zone's plan lets you query; --last beyond it will error.")
    if out_path:
        with open(out_path, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"Wrote inspect report to {out_path}", file=sys.stderr)


# ---------------------------------------------------------------- output

def truncate(field, value):
    limit = TRUNCATE.get(field)
    s = str(value)
    if limit and len(s) > limit:
        return s[: limit - 1] + "…"
    return s


def print_timeseries(bucket, tfield, tsecs, rows):
    print(f"\n-- Request rate (per {bucket}) --")
    if not rows:
        print("  (no data)")
        return
    rates = [(r.get("dimensions", {}).get(tfield, ""), r.get("count", 0),
              estimated_requests(r)) for r in rows]
    peak = max(rates, key=lambda x: x[2])
    avg_rps = sum(x[2] for x in rates) / (len(rates) * tsecs)
    print(f"  buckets: {len(rates)} | avg ~{avg_rps:,.1f} req/s | "
          f"peak {peak[2]:,} reqs ({peak[2] / tsecs:,.1f} req/s) at {peak[0]}")
    if len(rates) > 96:
        print(f"  (too many buckets to print — full series in --out output)")
        return
    width = max(len(f"{est:,}") for _, _, est in rates)
    max_est = peak[2] or 1
    for ts, samples, est in rates:
        bar = "#" * max(1, int(40 * est / max_est)) if est else ""
        print(f"  {ts}  {est:>{width},}  {bar}")


def print_table(title, fields, rows, total_est, limit):
    print(f"\n-- {title} (top {limit}) --")
    if not rows:
        print("  (no data)")
        return
    headers = fields + ["samples", "est_requests", "pct"]
    table = []
    for i, r in enumerate(rows, 1):
        dims = r.get("dimensions") or {}
        est = estimated_requests(r)
        pct = f"{100.0 * est / total_est:.2f}%" if total_est else "-"
        table.append([str(i)] + [truncate(f, dims.get(f, "")) for f in fields]
                     + [f"{r.get('count', 0):,}", f"{est:,}", pct])
    headers = ["#"] + headers
    widths = [max(len(h), *(len(row[i]) for row in table)) for i, h in enumerate(headers)]
    print("  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    for row in table:
        print("  " + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))


def write_csvs(outdir, results):
    os.makedirs(outdir, exist_ok=True)
    written = []
    for ds_key, ds in results["datasets"].items():
        ts = ds.get("timeseries")
        if ts and ts.get("rows") and not ts.get("error"):
            path = os.path.join(outdir, f"{ds_key}_timeseries.csv")
            with open(path, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["time", "samples", "est_requests", "req_per_sec"])
                for r in ts["rows"]:
                    est = estimated_requests(r)
                    w.writerow([r.get("dimensions", {}).get(ts["field"], ""),
                                r.get("count", 0), est,
                                round(est / ts["bucket_seconds"], 3)])
            written.append(path)
        for dim_key, dim in ds["dims"].items():
            if dim.get("error") or not dim.get("rows"):
                continue
            path = os.path.join(outdir, f"{ds_key}_{dim_key}.csv")
            fields = dim["fields"]
            total_est = ds.get("total", {}).get("estimated_requests") or 0
            with open(path, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["rank"] + fields + ["samples", "est_requests", "pct_of_window"])
                for i, r in enumerate(dim["rows"], 1):
                    dims = r.get("dimensions") or {}
                    est = estimated_requests(r)
                    pct = round(100.0 * est / total_est, 4) if total_est else ""
                    w.writerow([i] + [dims.get(f, "") for f in fields]
                               + [r.get("count", 0), est, pct])
            written.append(path)
    meta_path = os.path.join(outdir, "meta.json")
    with open(meta_path, "w") as fh:
        json.dump(results["meta"], fh, indent=2)
    written.append(meta_path)
    return written


# ---------------------------------------------------------------- main

def parse_args():
    p = argparse.ArgumentParser(
        description="Pull top-N Cloudflare Security Analytics views via the GraphQL API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[1] if "Examples:" in __doc__ else None)
    p.add_argument("--token", help="API token (or env CLOUDFLARE_API_TOKEN / CF_API_TOKEN)")
    p.add_argument("--auth-email", help="legacy auth email (or env CLOUDFLARE_EMAIL)")
    p.add_argument("--auth-key", help="legacy global API key (or env CLOUDFLARE_API_KEY)")
    p.add_argument("--zone", required=True,
                   help="zone name (e.g. smithlabs.io) or 32-hex zone ID")
    p.add_argument("--last", default="24h",
                   help="relative window: 1-24h, 1-12d, 1-3w (default: 24h)")
    p.add_argument("--from", dest="from_ts", help="explicit window start (ISO 8601)")
    p.add_argument("--to", dest="to_ts", help="explicit window end (ISO 8601)")
    p.add_argument("--dataset", choices=["http", "firewall", "both"], default="both",
                   help="http = sampled traffic (Security Analytics); firewall = mitigation "
                        "events (Security Events); default both")
    p.add_argument("--dims", default="all",
                   help="comma list of dimensions to pull, or 'all'. "
                        f"http: {','.join(HTTP_DIMS)} | firewall: {','.join(FIREWALL_DIMS)}")
    p.add_argument("--limit", type=int, default=150, help="top N per dimension (default 150)")
    p.add_argument("--timeseries", choices=list(TIMESERIES_BUCKETS),
                   help="also pull request counts bucketed by time (dashboard 'Request "
                        "rate analysis') — respects all filters")
    p.add_argument("--inspect", action="store_true",
                   help="probe the zone with live queries and report which datasets/"
                        "fields this zone's plan actually exposes, plus its limits "
                        "(retention, max query window), then exit. Runs standalone — "
                        "other query flags are ignored (--out writes the report as JSON)")
    # filters
    p.add_argument("--bot-score-min", type=int, help="min botScore (http dataset only)")
    p.add_argument("--bot-score-max", type=int, help="max botScore (http dataset only)")
    p.add_argument("--asn", help="filter to ASN(s), e.g. 64496 or AS64496 or 64496,64497")
    p.add_argument("--country", help="filter to country code(s), e.g. RU or RU,VN")
    p.add_argument("--host", help="filter to exact request host")
    p.add_argument("--path-contains", help="filter paths containing this substring")
    p.add_argument("--ip", help="filter to a single client IP")
    p.add_argument("--ja4", help="filter to a JA4 fingerprint")
    p.add_argument("--action", help="filter to a firewall action (firewall dataset only), "
                                    "e.g. block, managed_challenge, log")
    p.add_argument("--where",
                   help="WAF-rule-style filter expression, AND'd with the other flags. "
                        "Supports and/or/not, parens, eq ne lt le gt ge == != < <= > >=, "
                        "in {a b c}, contains, wildcard, starts_with, ends_with. "
                        "Fields: asn, country, ip, host, path, ua, ja4, botscore, status, "
                        "method (http) / action, ruleid (firewall) — or wirefilter names "
                        "like ip.geoip.asnum, cf.bot_management.score. Example: "
                        "\"asn in {64496 64497} or (botscore lt 30 and country eq RU)\"")
    # output
    p.add_argument("--out", help="write results to this path (json file, or directory for csv)")
    p.add_argument("--format", choices=["json", "csv"], default="json",
                   help="output format for --out (default json)")
    p.add_argument("--quiet", action="store_true", help="suppress console tables")
    p.add_argument("--timeout", type=int, default=60, help="per-request timeout seconds")
    return p.parse_args()


def main():
    args = parse_args()
    headers = build_headers(args)
    zone_id, zone_name, zone_plan = resolve_zone(headers, args.zone, args.timeout)

    if args.inspect:
        ignored = [flag for flag, given in (
            ("--dims", args.dims != "all"),
            ("--dataset", args.dataset != "both"),
            ("--timeseries", bool(args.timeseries)),
            ("--limit", args.limit != 150),
            ("--last/--from/--to", args.last != "24h" or bool(args.from_ts) or bool(args.to_ts)),
            ("--where", bool(args.where)),
            ("filter flags", any(v is not None for v in (
                args.bot_score_min, args.bot_score_max, args.asn, args.country,
                args.host, args.path_contains, args.ip, args.ja4, args.action))),
        ) if given]
        if ignored:
            warn("--inspect runs standalone; ignoring: " + ", ".join(ignored))
        if args.out and args.format == "csv":
            warn("--inspect reports are JSON; ignoring --format csv")
        run_inspect(headers, zone_id, zone_name, zone_plan, args.timeout,
                    out_path=args.out, quiet=args.quiet)
        return

    since, until = parse_window(args)
    dataset_keys = ["http", "firewall"] if args.dataset == "both" else [args.dataset]
    if args.bot_score_min is not None or args.bot_score_max is not None:
        if "http" not in dataset_keys:
            warn("--bot-score-* only applies to the http dataset; firewall events carry no botScore")
    if args.action and "firewall" not in dataset_keys:
        warn("--action only applies to the firewall dataset; ignoring")

    active_filters = {k: v for k, v in vars(args).items()
                      if k in ("bot_score_min", "bot_score_max", "asn", "country", "host",
                               "path_contains", "ip", "ja4", "action", "where") and v is not None}

    where_ast = None
    if args.where:
        try:
            where_ast = WhereParser(tokenize_where(args.where)).parse()
        except ExprError as e:
            die(f"--where: {e}")

    def make_filter(ds_key, asn_as_string):
        flt = build_filter(args, ds_key, since, until, asn_as_string)
        if where_ast is not None:
            flt = {"AND": [flt, translate_where(where_ast, ds_key, asn_as_string)]}
        return flt

    results = {
        "meta": {
            "zone": zone_name,
            "zone_id": zone_id,
            "window": {"from": since, "to": until},
            "filters": active_filters,
            "limit": args.limit,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "note": "adaptive datasets are SAMPLED; est_requests = samples x avg sampleInterval",
        },
        "datasets": {},
    }

    for ds_key in dataset_keys:
        node = DATASETS[ds_key]
        dim_registry = HTTP_DIMS if ds_key == "http" else FIREWALL_DIMS
        if args.dims == "all":
            dim_keys = [d for d in dim_registry if d not in DEFAULT_SKIP_DIMS]
        else:
            dim_keys = []
            for d in split_multi(args.dims):
                if d in dim_registry:
                    dim_keys.append(d)
                else:
                    warn(f"dimension '{d}' not available on {ds_key} dataset — skipping "
                         f"there (still pulled on any dataset that has it)")

        # Window total first — validates the filter and gives us a % denominator.
        # clientAsn is numeric on http and a string on firewall events; if the first
        # guess errors on type, flip quoting and retry.
        asn_as_string = ds_key == "firewall"
        try:
            flt = make_filter(ds_key, asn_as_string)
        except ExprError as e:
            warn(f"[{ds_key}] --where: {e} — skipping this dataset")
            results["datasets"][ds_key] = {"total": {"error": str(e)}, "dims": {}}
            continue
        rows, err = query_grouped(headers, zone_id, node, [], flt, 1, args.timeout)
        if err and "clientAsn" in err:
            asn_as_string = not asn_as_string
            flt = make_filter(ds_key, asn_as_string)
            rows, err = query_grouped(headers, zone_id, node, [], flt, 1, args.timeout)
        if err:
            warn(f"[{ds_key}] window-total query failed: {error_hint(err)}")
            results["datasets"][ds_key] = {"total": {"error": err}, "dims": {}}
            continue

        total_row = rows[0] if rows else {}
        total_est = estimated_requests(total_row) if rows else 0
        ds_result = {
            "total": {
                "samples": total_row.get("count", 0),
                "estimated_requests": total_est,
            },
            "dims": {},
        }

        if not args.quiet:
            label = "HTTP requests (sampled)" if ds_key == "http" else "Firewall events"
            print(f"\n=== {zone_name} | {label} | {since} -> {until} ===")
            if active_filters:
                print(f"Filters: {json.dumps(active_filters)}")
            print(f"Window total: {total_row.get('count', 0):,} samples "
                  f"~= {total_est:,} requests")

        if args.timeseries:
            tfield, tsecs = TIMESERIES_BUCKETS[args.timeseries]
            fmt = "%Y-%m-%dT%H:%M:%SZ"
            window_secs = (datetime.strptime(until, fmt) - datetime.strptime(since, fmt)).total_seconds()
            ts_limit = min(10000, int(window_secs / tsecs) + 5)
            ts_rows, ts_err = query_grouped(headers, zone_id, node, [tfield], flt,
                                            ts_limit, args.timeout, order_by=f"{tfield}_ASC")
            if ts_err:
                warn(f"[{ds_key}/timeseries] query failed: {error_hint(ts_err)}")
            ds_result["timeseries"] = {"bucket": args.timeseries, "field": tfield,
                                       "bucket_seconds": tsecs,
                                       "rows": ts_rows or [], "error": ts_err}
            if not args.quiet and not ts_err:
                print_timeseries(args.timeseries, tfield, tsecs, ts_rows)

        for dim_key in dim_keys:
            fields, title = dim_registry[dim_key]
            rows, err = query_grouped(headers, zone_id, node, fields, flt,
                                      args.limit, args.timeout)
            if err:
                warn(f"[{ds_key}/{dim_key}] query failed: {error_hint(err)}")
                ds_result["dims"][dim_key] = {"title": title, "fields": fields,
                                              "rows": [], "error": err}
                continue
            if dim_key in NUMERIC_SORT_DIMS:
                rows.sort(key=lambda r: (r.get("dimensions") or {}).get(fields[0]) or 0)
            ds_result["dims"][dim_key] = {"title": title, "fields": fields,
                                          "rows": rows, "error": None}
            if not args.quiet:
                print_table(title, fields, rows, total_est, args.limit)

        results["datasets"][ds_key] = ds_result

    if args.out:
        if args.format == "csv":
            written = write_csvs(args.out, results)
            print(f"\nWrote {len(written)} files to {args.out}", file=sys.stderr)
        else:
            with open(args.out, "w") as fh:
                json.dump(results, fh, indent=2)
            print(f"\nWrote JSON to {args.out}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    main()
