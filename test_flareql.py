#!/usr/bin/env python3
"""Offline test suite for flareql.py — all HTTP is mocked.

Run:    python3 -m unittest test_flareql.py -v
Cover:  coverage run -m unittest test_flareql.py && coverage report -m
"""

import argparse
import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock
from urllib import error as urlerror

import flareql as m

ZONE_ID = "f" * 32


def ns(**kw):
    return argparse.Namespace(**kw)


def http_error(code, body=b"boom", with_fp=True):
    fp = io.BytesIO(body) if with_fp else None
    err = urlerror.HTTPError("https://x", code, "err", {}, fp)
    if not with_fp:
        err.read = mock.Mock(side_effect=OSError("body gone"))
    return err


def ok_response(payload):
    cm = mock.MagicMock()
    cm.__enter__.return_value = io.BytesIO(json.dumps(payload).encode())
    cm.__exit__.return_value = False
    return cm


@contextlib.contextmanager
def captured():
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


# Values a fake API returns per GraphQL dimension field. Two rows are returned,
# deliberately out of numeric order so NUMERIC_SORT_DIMS sorting is exercised.
NUMERIC_FIELDS = {"botScore", "wafAttackScore", "wafSqliAttackScore",
                  "wafXssAttackScore", "wafRceAttackScore", "edgeResponseStatus",
                  "clientAsn"}


class FakeAPI:
    """Stands in for flareql.http_json. Routes on URL/query content."""

    def __init__(self, fail_substrings=(), flip_asn=False, zone_result=None,
                 gated_datasets=(), gated_fields=(), empty_zones=False,
                 fail_message=None):
        self.fail_substrings = tuple(fail_substrings)
        self.flip_asn = flip_asn
        self.zone_result = (zone_result if zone_result is not None
                            else [{"id": ZONE_ID, "name": "smithlabs.io",
                                   "plan": {"name": "Free Website"}}])
        self.gated_datasets = tuple(gated_datasets)
        self.gated_fields = tuple(gated_fields)
        self.empty_zones = empty_zones
        self.fail_message = fail_message
        self.queries = []

    def __call__(self, url, headers, body=None, timeout=60, max_tries=4):
        if "/zones?" in url:
            return {"result": self.zone_result}
        q = body["query"]
        self.queries.append(q)
        if self.empty_zones:
            return {"data": {"viewer": {"zones": []}}}
        for node in self.gated_datasets:
            if node in q:
                return {"data": None, "errors": [{"message":
                        f"zone '{ZONE_ID}' does not have access to the path. "
                        "Refer to https://developers.cloudflare.com/analytics/"
                        "graphql-api/errors/"}]}
        hits = [(mm.start(), f) for f in self.gated_fields
                for mm in re.finditer(r"\b" + re.escape(f) + r"\b", q)]
        if hits:
            field = min(hits)[1]
            return {"data": None, "errors": [{"message":
                    f"zone '{ZONE_ID}' does not have access to the field "
                    f"'{field.lower()}' from the path"}]}
        for s in self.fail_substrings:
            if s in q:
                return {"data": None, "errors": [{"message":
                        self.fail_message or f"injected failure on {s}"}]}
        if self.flip_asn and 'clientAsn: "' in q:
            return {"data": None,
                    "errors": [{"message": "wrong value type for filter field clientAsn"}]}
        if "settings {" in q:
            node = ("httpRequestsAdaptiveGroups" if "httpRequestsAdaptiveGroups" in q
                    else "firewallEventsAdaptiveGroups")
            requested = re.search(r"settings \{ \w+ \{ ([^}]+) \}", q).group(1).split()
            full = {"enabled": True, "maxDuration": 2678400, "maxNumberOfFields": 30,
                    "maxPageSize": 10000, "notOlderThan": 2678400}
            return {"data": {"viewer": {"zones": [{"settings": {node:
                    {k: v for k, v in full.items() if k in requested}}}]}}}
        mdim = re.search(r"dimensions \{ ([^}]+) \}", q)
        if not mdim:
            rows = [{"count": 1000, "avg": {"sampleInterval": 10}}]
        else:
            fields = mdim.group(1).split()
            rows = []
            for i, nums in enumerate(((30, "va", "2026-08-13T01:00:00Z"),
                                      (2, "vb", "2026-08-13T00:00:00Z"))):
                dims = {}
                for f in fields:
                    if f in NUMERIC_FIELDS:
                        dims[f] = nums[0]
                    elif f.startswith("datetime") or f == "date":
                        dims[f] = nums[2]
                    elif f == "userAgent":
                        dims[f] = "u" * 150
                    else:
                        dims[f] = nums[1]
                rows.append({"count": 50 - i, "avg": {"sampleInterval": 10},
                             "dimensions": dims})
        return {"data": {"viewer": {"zones": [{"result": rows}]}}}


def run_main(argv, fake=None):
    fake = fake or FakeAPI()
    with mock.patch.object(m, "http_json", fake), \
         mock.patch.object(m.sys, "argv", ["flareql.py"] + argv), \
         captured() as (out, err):
        m.main()
    return out.getvalue(), err.getvalue(), fake


BASE = ["--token", "t", "--zone", "smithlabs.io"]


# ---------------------------------------------------------------- small helpers

class TestHelpers(unittest.TestCase):
    def test_warn_and_die(self):
        with captured() as (_, err):
            m.warn("careful")
        self.assertIn("[warn] careful", err.getvalue())
        with captured() as (_, err), self.assertRaises(SystemExit):
            m.die("nope")
        self.assertIn("[error] nope", err.getvalue())

    def test_to_gql_literal(self):
        self.assertEqual(m.to_gql_literal(True), "true")
        self.assertEqual(m.to_gql_literal(False), "false")
        self.assertEqual(m.to_gql_literal(5), "5")
        self.assertEqual(m.to_gql_literal(1.5), "1.5")
        self.assertEqual(m.to_gql_literal([1, "a"]), '[1, "a"]')
        self.assertEqual(m.to_gql_literal({"k": "v"}), '{k: "v"}')

    def test_split_multi(self):
        self.assertEqual(m.split_multi(" a, b ,,c "), ["a", "b", "c"])

    def test_truncate(self):
        self.assertEqual(m.truncate("clientIP", "1.2.3.4"), "1.2.3.4")
        long_ua = "u" * 150
        cut = m.truncate("userAgent", long_ua)
        self.assertEqual(len(cut), 100)
        self.assertTrue(cut.endswith("…"))

    def test_estimated_requests(self):
        self.assertEqual(m.estimated_requests({"count": 10, "avg": {"sampleInterval": 2.5}}), 25)
        self.assertEqual(m.estimated_requests({"count": 10}), 10)
        self.assertEqual(m.estimated_requests({}), 0)


# ---------------------------------------------------------------- auth

class TestBuildHeaders(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def args(self, **kw):
        base = {"token": None, "auth_email": None, "auth_key": None}
        base.update(kw)
        return ns(**base)

    def test_token_flag(self):
        h = m.build_headers(self.args(token="abc"))
        self.assertEqual(h["Authorization"], "Bearer abc")

    def test_token_env(self):
        os.environ["CLOUDFLARE_API_TOKEN"] = "envtok"
        self.assertEqual(m.build_headers(self.args())["Authorization"], "Bearer envtok")

    def test_token_alt_env(self):
        os.environ["CF_API_TOKEN"] = "alt"
        self.assertEqual(m.build_headers(self.args())["Authorization"], "Bearer alt")

    def test_legacy_key(self):
        h = m.build_headers(self.args(auth_email="a@smithlabs.io", auth_key="k"))
        self.assertEqual(h["X-Auth-Email"], "a@smithlabs.io")
        self.assertEqual(h["X-Auth-Key"], "k")

    def test_no_creds_dies(self):
        with captured(), self.assertRaises(SystemExit):
            m.build_headers(self.args())


# ---------------------------------------------------------------- http layer

class TestHttpJson(unittest.TestCase):
    def test_get_success(self):
        with mock.patch.object(m.urlrequest, "urlopen",
                               return_value=ok_response({"ok": 1})) as u:
            self.assertEqual(m.http_json("https://x", {}), {"ok": 1})
        req = u.call_args[0][0]
        self.assertEqual(req.get_method(), "GET")

    def test_post_with_body(self):
        with mock.patch.object(m.urlrequest, "urlopen",
                               return_value=ok_response({"ok": 2})) as u:
            self.assertEqual(m.http_json("https://x", {}, body={"q": 1}), {"ok": 2})
        self.assertEqual(u.call_args[0][0].get_method(), "POST")

    def test_retryable_http_error_then_success(self):
        with mock.patch.object(m.urlrequest, "urlopen",
                               side_effect=[http_error(429), ok_response({"ok": 3})]), \
             mock.patch.object(m.time, "sleep") as slept, captured() as (_, err):
            self.assertEqual(m.http_json("https://x", {}), {"ok": 3})
        self.assertTrue(slept.called)
        self.assertIn("HTTP 429", err.getvalue())

    def test_fatal_http_error_dies(self):
        with mock.patch.object(m.urlrequest, "urlopen", side_effect=http_error(400)), \
             captured() as (_, err), self.assertRaises(SystemExit):
            m.http_json("https://x", {})
        self.assertIn("HTTP 400", err.getvalue())

    def test_http_error_unreadable_body(self):
        with mock.patch.object(m.urlrequest, "urlopen",
                               side_effect=http_error(400, with_fp=False)), \
             captured(), self.assertRaises(SystemExit):
            m.http_json("https://x", {})

    def test_url_error_retry_then_success(self):
        with mock.patch.object(m.urlrequest, "urlopen",
                               side_effect=[urlerror.URLError("nope"), ok_response({"ok": 4})]), \
             mock.patch.object(m.time, "sleep"):
            self.assertEqual(m.http_json("https://x", {}), {"ok": 4})

    def test_url_error_exhausted_dies(self):
        with mock.patch.object(m.urlrequest, "urlopen",
                               side_effect=urlerror.URLError("down")), \
             mock.patch.object(m.time, "sleep"), captured(), \
             self.assertRaises(SystemExit):
            m.http_json("https://x", {})

    def test_gql(self):
        with mock.patch.object(m, "http_json",
                               return_value={"data": {"a": 1}, "errors": None}):
            data, errs = m.gql({}, "{q}", 60)
        self.assertEqual(data, {"a": 1})
        self.assertEqual(errs, [])


# ---------------------------------------------------------------- zone lookup

class TestResolveZone(unittest.TestCase):
    def test_hex_id_passthrough(self):
        self.assertEqual(m.resolve_zone({}, ZONE_ID, 60), (ZONE_ID, ZONE_ID, None))

    def test_name_found(self):
        fake = FakeAPI()
        with mock.patch.object(m, "http_json", fake):
            self.assertEqual(m.resolve_zone({}, "smithlabs.io", 60),
                             (ZONE_ID, "smithlabs.io", "Free Website"))

    def test_name_found_without_plan(self):
        fake = FakeAPI(zone_result=[{"id": ZONE_ID, "name": "smithlabs.io"}])
        with mock.patch.object(m, "http_json", fake):
            self.assertEqual(m.resolve_zone({}, "smithlabs.io", 60),
                             (ZONE_ID, "smithlabs.io", None))

    def test_name_not_found_lists_zones(self):
        responses = [{"result": []},
                     {"result": [{"id": "x", "name": "other.smithlabs.io"}]}]
        with mock.patch.object(m, "http_json", side_effect=responses), \
             captured() as (_, err), self.assertRaises(SystemExit):
            m.resolve_zone({}, "missing.example", 60)
        self.assertIn("other.smithlabs.io", err.getvalue())

    def test_name_not_found_none_visible(self):
        with mock.patch.object(m, "http_json", side_effect=[{"result": []}, {"result": []}]), \
             captured() as (_, err), self.assertRaises(SystemExit):
            m.resolve_zone({}, "missing.example", 60)
        self.assertIn("(none visible)", err.getvalue())


# ---------------------------------------------------------------- timeframe

class TestTimeframe(unittest.TestCase):
    def test_parse_timestamp_forms(self):
        self.assertEqual(m.parse_timestamp("2026-08-11").isoformat(),
                         "2026-08-11T00:00:00+00:00")
        self.assertEqual(m.parse_timestamp("2026-08-11T05:00:00Z").hour, 5)
        naive = m.parse_timestamp("2026-08-11T05:00:00")
        self.assertIsNotNone(naive.tzinfo)

    def test_parse_timestamp_bad(self):
        with captured(), self.assertRaises(SystemExit):
            m.parse_timestamp("yesterday-ish")

    def test_relative_windows(self):
        for spec in ("6h", "24hr", "12hrs", "1hour", "2hours", "3d", "1day",
                     "5days", "2w", "1wk", "3weeks"):
            since, until = m.parse_window(ns(last=spec, from_ts=None, to_ts=None))
            self.assertLess(since, until)

    def test_explicit_window(self):
        since, until = m.parse_window(ns(last="24h", from_ts="2026-08-11",
                                         to_ts="2026-08-12T06:30:00Z"))
        self.assertEqual(since, "2026-08-11T00:00:00Z")
        self.assertEqual(until, "2026-08-12T06:30:00Z")

    def test_from_without_to_dies(self):
        with captured(), self.assertRaises(SystemExit):
            m.parse_window(ns(last="24h", from_ts="2026-08-11", to_ts=None))

    def test_reversed_window_dies(self):
        with captured(), self.assertRaises(SystemExit):
            m.parse_window(ns(last="24h", from_ts="2026-08-12", to_ts="2026-08-11"))

    def test_bad_relative_dies(self):
        with captured(), self.assertRaises(SystemExit):
            m.parse_window(ns(last="fortnight", from_ts=None, to_ts=None))

    def test_long_window_warns(self):
        with captured() as (_, err):
            m.parse_window(ns(last="4w", from_ts=None, to_ts=None))
        self.assertIn("retention", err.getvalue())


# ---------------------------------------------------------------- flag filters

class TestBuildFilter(unittest.TestCase):
    def args(self, **kw):
        base = {"asn": None, "country": None, "host": None, "path_contains": None,
                "ip": None, "ja4": None, "bot_score_min": None, "bot_score_max": None,
                "action": None}
        base.update(kw)
        return ns(**base)

    def test_all_http_filters(self):
        f = m.build_filter(self.args(asn="AS64496", country="ru", host="h",
                                     path_contains="/x", ip="192.0.2.7", ja4="j",
                                     bot_score_min=2, bot_score_max=29),
                           "http", "S", "U", asn_as_string=False)
        self.assertEqual(f["clientAsn"], 64496)
        self.assertEqual(f["clientCountryName"], "RU")
        self.assertEqual(f["clientRequestHTTPHost"], "h")
        self.assertEqual(f["clientRequestPath_like"], "%/x%")
        self.assertEqual(f["clientIP"], "192.0.2.7")
        self.assertEqual(f["ja4"], "j")
        self.assertEqual(f["botScore_geq"], 2)
        self.assertEqual(f["botScore_leq"], 29)

    def test_multi_values_and_firewall_action(self):
        f = m.build_filter(self.args(asn="64496,64497", country="ru,vn", action="block"),
                           "firewall", "S", "U", asn_as_string=True)
        self.assertEqual(f["clientAsn_in"], ["64496", "64497"])
        self.assertEqual(f["clientCountryName_in"], ["RU", "VN"])
        self.assertEqual(f["action"], "block")
        self.assertNotIn("botScore_geq", f)

    def test_bad_asn_dies(self):
        with captured(), self.assertRaises(SystemExit):
            m.build_filter(self.args(asn="banana"), "http", "S", "U", False)


# ---------------------------------------------------------------- --where parsing

def parse(expr):
    return m.WhereParser(m.tokenize_where(expr)).parse()


def translate(expr, ds="http", asn_str=False):
    return m.translate_where(parse(expr), ds, asn_str)


class TestTokenizer(unittest.TestCase):
    def test_token_kinds(self):
        toks = m.tokenize_where('(a) {b} , == != <= >= < > "q\\"x" word /p/*')
        kinds = [k for k, _ in toks]
        self.assertEqual(kinds, ["lparen", "word", "rparen", "lbrace", "word",
                                 "rbrace", "comma", "op", "op", "op", "op", "op",
                                 "op", "value", "word", "word"])
        self.assertEqual(toks[13], ("value", 'q"x'))

    def test_keywords_case_insensitive(self):
        self.assertEqual(m.tokenize_where("AND Or NOT In")[0], ("kw", "and"))

    def test_bad_character(self):
        with self.assertRaises(m.ExprError):
            m.tokenize_where("asn @ 5")


class TestWhereParser(unittest.TestCase):
    def test_precedence_and_binds_tighter(self):
        node = parse("asn eq 1 or asn eq 2 and asn eq 3")
        self.assertEqual(node[0], "or")
        self.assertEqual(node[1][1][0], "and")

    def test_parens_override(self):
        node = parse("(asn eq 1 or asn eq 2) and asn eq 3")
        self.assertEqual(node[0], "and")

    def test_in_braces_parens_commas(self):
        self.assertEqual(parse("asn in {1 2}")[3], ["1", "2"])
        self.assertEqual(parse('country in (RU, VN, "CN")')[3], ["RU", "VN", "CN"])

    def test_errors(self):
        cases = ["", "asn eq 1 trailing", "(asn eq 1", "asn banana 1", "asn eq",
                 "asn in 5", "asn in {}", "asn in {(}", ", eq 1", 'ua matches "x"']
        for expr in cases:
            with self.assertRaises(m.ExprError, msg=expr):
                parse(expr)


class TestVerifiedBotField(unittest.TestCase):
    """cf.bot_management.verified_bot / cf.verified_bot boolean field."""

    def test_infix_true(self):
        self.assertEqual(translate("cf.bot_management.verified_bot eq true"),
                         {"verifiedBot": True})

    def test_infix_false(self):
        self.assertEqual(translate("cf.bot_management.verified_bot eq false"),
                         {"verifiedBot": False})

    def test_short_alias(self):
        self.assertEqual(translate("cf.verified_bot eq true"), {"verifiedBot": True})

    def test_standalone_truthy(self):
        node = parse("cf.bot_management.verified_bot")
        self.assertEqual(node, ("cmp", "cf.bot_management.verified_bot", "eq", ["true"]))
        self.assertEqual(translate("cf.bot_management.verified_bot"), {"verifiedBot": True})

    def test_negated_standalone(self):
        self.assertEqual(translate("not cf.bot_management.verified_bot"),
                         {"verifiedBot": False})

    def test_negated_infix(self):
        self.assertEqual(translate("not cf.bot_management.verified_bot eq true"),
                         {"verifiedBot": False})

    def test_in_compound(self):
        result = translate("cf.bot_management.verified_bot and ip.geoip.asnum eq 15169")
        self.assertIn("AND", result)
        self.assertIn({"verifiedBot": True}, result["AND"])

    def test_bad_value_errors(self):
        with self.assertRaises(m.ExprError) as ctx:
            translate("cf.bot_management.verified_bot eq maybe")
        self.assertIn("boolean field", str(ctx.exception))


class TestWhereFunctionCallSyntax(unittest.TestCase):
    """starts_with(field, value) / ends_with(field, value) — Cloudflare wirefilter function form."""

    def test_starts_with_basic(self):
        self.assertEqual(parse('starts_with(path, "/api")'),
                         ("cmp", "path", "starts", ["/api"]))

    def test_ends_with_basic(self):
        self.assertEqual(parse('ends_with(path, ".json")'),
                         ("cmp", "path", "ends", [".json"]))

    def test_starts_with_wirefilter_alias_field(self):
        node = parse('starts_with(http.request.uri.path, "/users/auth/")')
        self.assertEqual(node, ("cmp", "http.request.uri.path", "starts", ["/users/auth/"]))

    def test_ends_with_wirefilter_alias_field(self):
        node = parse('ends_with(http.request.uri.path, "/callback")')
        self.assertEqual(node, ("cmp", "http.request.uri.path", "ends", ["/callback"]))

    def test_function_call_in_compound_expression(self):
        expr = ('(starts_with(http.request.uri.path, "/users/auth/") and '
                '(http.request.uri.path contains "facebook" or '
                'http.request.uri.path contains "shopify"))')
        node = parse(expr)
        self.assertEqual(node[0], "and")
        self.assertEqual(node[1][0], ("cmp", "http.request.uri.path", "starts", ["/users/auth/"]))

    def test_function_call_mixed_with_infix(self):
        node = parse('starts_with(path, "/api") or path ends_with ".json"')
        self.assertEqual(node[0], "or")
        self.assertEqual(node[1][0][2], "starts")
        self.assertEqual(node[1][1][2], "ends")

    def test_function_call_with_not(self):
        node = parse('not starts_with(path, "/api")')
        self.assertEqual(node, ("not", ("cmp", "path", "starts", ["/api"])))

    def test_starts_with_without_paren_errors(self):
        with self.assertRaises(m.ExprError) as ctx:
            parse("starts_with path eq 1")
        self.assertIn("function", str(ctx.exception).lower())

    def test_starts_with_non_word_field_errors(self):
        with self.assertRaises(m.ExprError):
            parse('starts_with("literal", "/api")')

    def test_starts_with_missing_comma_errors(self):
        with self.assertRaises(m.ExprError):
            parse('starts_with(path "/api")')

    def test_starts_with_missing_value_errors(self):
        with self.assertRaises(m.ExprError):
            parse("starts_with(path, )")

    def test_starts_with_unclosed_paren_errors(self):
        with self.assertRaises(m.ExprError):
            parse('starts_with(path, "/api"')

    def test_translate_starts_with_function_call(self):
        self.assertEqual(translate('starts_with(path, "/api")'),
                         {"clientRequestPath_like": "/api%"})

    def test_translate_ends_with_function_call(self):
        self.assertEqual(translate('ends_with(path, ".json")'),
                         {"clientRequestPath_like": "%.json"})

    def test_translate_with_wirefilter_alias(self):
        self.assertEqual(translate('starts_with(http.request.uri.path, "/users/auth/")'),
                         {"clientRequestPath_like": "/users/auth/%"})

    def test_translate_function_call_negated(self):
        self.assertEqual(translate('not starts_with(path, "/api")'),
                         {"clientRequestPath_notlike": "/api%"})

    def test_translate_function_call_in_compound(self):
        expr = ('starts_with(http.request.uri.path, "/users/auth/") and '
                '(http.request.uri.path contains "facebook" or '
                'http.request.uri.path contains "shopify")')
        result = translate(expr)
        self.assertEqual(result["AND"][0], {"clientRequestPath_like": "/users/auth/%"})
        self.assertIn("OR", result["AND"][1])


class TestWhereTranslate(unittest.TestCase):
    def test_every_operator(self):
        self.assertEqual(translate("asn eq 64496"), {"clientAsn": 64496})
        self.assertEqual(translate("asn != 64496"), {"clientAsn_neq": 64496})
        self.assertEqual(translate("botscore < 30"), {"botScore_lt": 30})
        self.assertEqual(translate("botscore <= 30"), {"botScore_leq": 30})
        self.assertEqual(translate("botscore > 2"), {"botScore_gt": 2})
        self.assertEqual(translate("botscore >= 2"), {"botScore_geq": 2})
        self.assertEqual(translate("asn in {64496 64497}"),
                         {"clientAsn_in": [64496, 64497]})
        self.assertEqual(translate("ua contains bot"), {"userAgent_like": "%bot%"})
        self.assertEqual(translate('path starts_with "/api"'),
                         {"clientRequestPath_like": "/api%"})
        self.assertEqual(translate('path ends_with ".json"'),
                         {"clientRequestPath_like": "%.json"})
        self.assertEqual(translate("path wildcard /u/*/x"),
                         {"clientRequestPath_like": "/u/%/x"})

    def test_negations_de_morgan(self):
        self.assertEqual(translate("not asn eq 1"), {"clientAsn_neq": 1})
        self.assertEqual(translate("not asn in {1 2}"), {"clientAsn_notin": [1, 2]})
        self.assertEqual(translate("not ua contains x"), {"userAgent_notlike": "%x%"})
        self.assertEqual(translate('not path starts_with "/a"'),
                         {"clientRequestPath_notlike": "/a%"})
        self.assertEqual(translate('not path ends_with "/a"'),
                         {"clientRequestPath_notlike": "%/a"})
        self.assertEqual(translate("not path wildcard /a/*"),
                         {"clientRequestPath_notlike": "/a/%"})
        self.assertEqual(translate("not botscore lt 30"), {"botScore_geq": 30})
        node = translate("not (country eq US or botscore lt 5)")
        self.assertEqual(node, {"AND": [{"clientCountryName_neq": "US"},
                                        {"botScore_geq": 5}]})
        node = translate("not (country eq US and botscore lt 5)")
        self.assertEqual(node, {"OR": [{"clientCountryName_neq": "US"},
                                       {"botScore_geq": 5}]})

    def test_wirefilter_aliases(self):
        self.assertEqual(translate("ip.geoip.asnum eq 64496"), {"clientAsn": 64496})
        self.assertEqual(translate("cf.bot_management.score le 29"), {"botScore_leq": 29})
        self.assertEqual(translate("cf.waf.score lt 20"), {"wafAttackScore_lt": 20})
        self.assertEqual(translate("cf.waf.score.sqli lt 20"), {"wafSqliAttackScore_lt": 20})

    def test_asn_typing_and_prefix(self):
        self.assertEqual(translate("asn eq AS64496", "firewall", True),
                         {"clientAsn": "64496"})
        with self.assertRaises(m.ExprError):
            translate("asn eq ASXYZ")

    def test_type_errors(self):
        with self.assertRaises(m.ExprError):
            translate("botscore eq abc")
        with self.assertRaises(m.ExprError):
            translate("ua lt 5")
        with self.assertRaises(m.ExprError):
            translate("botscore contains 3")

    def test_unknown_field(self):
        with self.assertRaises(m.ExprError):
            translate("frobnitz eq 1")

    def test_dataset_mismatch_hints(self):
        with self.assertRaises(m.ExprError) as ctx:
            translate("botscore lt 30", "firewall", True)
        self.assertIn("http dataset's 'security' dim", str(ctx.exception))
        with self.assertRaises(m.ExprError) as ctx:
            translate("action eq block", "http", False)
        self.assertNotIn("security", str(ctx.exception))


# ---------------------------------------------------------------- query layer

class TestQueryBuild(unittest.TestCase):
    def test_with_and_without_dimensions(self):
        q = m.build_query("Z", "httpRequestsAdaptiveGroups", ["clientIP"],
                          {"a": 1}, 150, True, "count_DESC")
        self.assertIn("dimensions { clientIP }", q)
        self.assertIn("orderBy: [count_DESC]", q)
        self.assertIn("avg { sampleInterval }", q)
        q = m.build_query("Z", "x", [], {"a": 1}, 1, False, None)
        self.assertNotIn("dimensions", q)
        self.assertNotIn("orderBy", q)
        self.assertNotIn("avg", q)

    def test_extract_rows(self):
        self.assertIsNone(m.extract_rows({"viewer": {"zones": []}}))
        self.assertIsNone(m.extract_rows(None))
        self.assertEqual(m.extract_rows(
            {"viewer": {"zones": [{"result": [1]}]}}), [1])


class TestQueryGrouped(unittest.TestCase):
    def run_grouped(self, gql_side_effects, fields=("clientAsn", "clientASNDescription")):
        with mock.patch.object(m, "gql", side_effect=gql_side_effects):
            return m.query_grouped({}, "Z", "ds", list(fields), {"f": 1}, 10, 60)

    def test_success(self):
        rows, err = self.run_grouped([({"viewer": {"zones": [{"result": [{"count": 1}]}]}}, [])])
        self.assertIsNone(err)
        self.assertEqual(rows, [{"count": 1}])

    def test_asn_description_fallback(self):
        effects = [(None, [{"message": "unknown field clientASNDescription"}]),
                   ({"viewer": {"zones": [{"result": []}]}}, [])]
        rows, err = self.run_grouped(effects)
        self.assertIsNone(err)
        self.assertEqual(rows, [])

    def test_sample_interval_fallback(self):
        effects = [(None, [{"message": "no sampleInterval here"}]),
                   ({"viewer": {"zones": [{"result": []}]}}, [])]
        rows, err = self.run_grouped(effects, fields=("clientIP",))
        self.assertIsNone(err)

    def test_hard_error(self):
        rows, err = self.run_grouped([(None, [{"message": "quota exceeded"}])])
        self.assertIsNone(rows)
        self.assertIn("quota", err)

    def test_no_zones_means_no_access(self):
        rows, err = self.run_grouped([({"viewer": {"zones": []}}, [])])
        self.assertIsNone(rows)
        self.assertIn("Analytics:Read", err)


# ---------------------------------------------------------------- rendering

class TestRendering(unittest.TestCase):
    def rows(self, n=2):
        return [{"count": 5, "avg": {"sampleInterval": 10},
                 "dimensions": {"clientIP": f"192.0.2.{i}"}} for i in range(n)]

    def test_print_table(self):
        with captured() as (out, _):
            m.print_table("T", ["clientIP"], self.rows(), 1000, 150)
        self.assertIn("192.0.2.0", out.getvalue())
        self.assertIn("5.00%", out.getvalue())

    def test_print_table_empty_and_zero_total(self):
        with captured() as (out, _):
            m.print_table("T", ["clientIP"], [], 100, 150)
        self.assertIn("(no data)", out.getvalue())
        with captured() as (out, _):
            m.print_table("T", ["clientIP"], self.rows(), 0, 150)
        self.assertIn("-", out.getvalue())

    def ts_rows(self, n):
        return [{"count": 10 + i, "avg": {"sampleInterval": 10},
                 "dimensions": {"datetimeHour": f"2026-08-13T{i % 24:02d}:00:00Z"}}
                for i in range(n)]

    def test_print_timeseries(self):
        with captured() as (out, _):
            m.print_timeseries("hour", "datetimeHour", 3600, [])
        self.assertIn("(no data)", out.getvalue())
        with captured() as (out, _):
            m.print_timeseries("hour", "datetimeHour", 3600, self.ts_rows(3))
        self.assertIn("#", out.getvalue())
        self.assertIn("peak", out.getvalue())
        with captured() as (out, _):
            m.print_timeseries("hour", "datetimeHour", 3600, self.ts_rows(120))
        self.assertIn("too many buckets", out.getvalue())


# ---------------------------------------------------------------- CSV output

class TestWriteCsvs(unittest.TestCase):
    def test_writes_dims_timeseries_meta_and_skips_errors(self):
        results = {
            "meta": {"zone": "smithlabs.io"},
            "datasets": {
                "http": {
                    "total": {"samples": 10, "estimated_requests": 100},
                    "timeseries": {"bucket": "hour", "field": "datetimeHour",
                                   "bucket_seconds": 3600, "error": None,
                                   "rows": [{"count": 1, "avg": {"sampleInterval": 10},
                                             "dimensions": {"datetimeHour": "t0"}}]},
                    "dims": {
                        "ip": {"title": "T", "fields": ["clientIP"], "error": None,
                               "rows": [{"count": 2, "avg": {"sampleInterval": 10},
                                         "dimensions": {"clientIP": "192.0.2.1"}}]},
                        "ja4": {"title": "J", "fields": ["ja4"], "rows": [],
                                "error": "boom"},
                    },
                },
            },
        }
        with tempfile.TemporaryDirectory() as td:
            written = m.write_csvs(td, results)
            names = sorted(os.path.basename(p) for p in written)
            self.assertEqual(names, ["http_ip.csv", "http_timeseries.csv", "meta.json"])
            with open(os.path.join(td, "http_ip.csv")) as fh:
                body = fh.read()
            self.assertIn("192.0.2.1", body)
            self.assertIn("20", body)  # est_requests = 2 * 10

    def test_errored_timeseries_not_written(self):
        results = {"meta": {},
                   "datasets": {"http": {"total": {},
                                         "timeseries": {"bucket": "hour", "field": "datetimeHour",
                                                        "bucket_seconds": 3600,
                                                        "rows": [], "error": "boom"},
                                         "dims": {}}}}
        with tempfile.TemporaryDirectory() as td:
            written = m.write_csvs(td, results)
            self.assertEqual([os.path.basename(p) for p in written], ["meta.json"])


# ---------------------------------------------------------------- --probe

class TestInspect(unittest.TestCase):
    def test_full_access_zone(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "report.json")
            out, _, fake = run_main(BASE + ["--inspect", "--out", path], fake=FakeAPI())
            with open(path) as fh:
                report = json.load(fh)
        self.assertIn("=== flareql inspect | smithlabs.io | plan: Free Website ===", out)
        self.assertIn("[http] httpRequestsAdaptiveGroups: AVAILABLE", out)
        self.assertIn("[firewall] firewallEventsAdaptiveGroups: AVAILABLE", out)
        self.assertIn("limits:     history: 31d back max | window per query: 31d max"
                      " | fields per query: 30 | rows per page: 10,000", out)
        self.assertRegex(out, r"\n    ip\s+yes\n")
        self.assertRegex(out, r"\n    ua\s+yes\n")
        self.assertNotRegex(out, r"\n    \S+\s+no\n")
        self.assertNotIn("partial", out)
        self.assertEqual(report["plan"], "Free Website")
        self.assertTrue(all(f["status"] == "yes"
                            for f in report["datasets"]["http"]["fields"].values()))
        self.assertEqual(sorted(report["datasets"]["http"]["timeseries"]),
                         sorted(m.TIMESERIES_BUCKETS))
        # availability + field probe + settings per dataset
        self.assertEqual(len(fake.queries), 6)

    def test_gated_zone_groups_yes_and_no(self):
        fake = FakeAPI(
            gated_datasets=("firewallEventsAdaptiveGroups",),
            gated_fields=("clientASNDescription", "botScore", "botScoreSrcName",
                          "ja4", "wafAttackScore", "wafAttackScoreClass",
                          "wafSqliAttackScore", "wafXssAttackScore",
                          "wafRceAttackScore"))
        out, _, _ = run_main(BASE + ["--inspect"], fake=fake)
        self.assertIn("NOT AVAILABLE — plan-gated on this zone", out)
        self.assertRegex(out, r"\n    asn\s+partial \(missing clientASNDescription")
        for name in ("attackclass", "attackscore", "botscore", "botsrc", "ja4",
                     "rce", "sqli", "xss"):
            self.assertRegex(out, rf"\n    {name}\s+no\n")
        # grouped: every yes row sits above every no row
        lines = out.splitlines()
        yes_rows = [i for i, l in enumerate(lines) if re.fullmatch(r"    \S+\s+yes", l)]
        no_rows = [i for i, l in enumerate(lines) if re.fullmatch(r"    \S+\s+no", l)]
        self.assertTrue(yes_rows and no_rows)
        self.assertLess(max(yes_rows), min(no_rows))
        self.assertNotIn("no (field not exposed", out)
        self.assertIn("Notes:", out)

    def test_everything_gated(self):
        all_fields = ({f for fields, _ in m.HTTP_DIMS.values() for f in fields}
                      | {f for fields, _ in m.FIREWALL_DIMS.values() for f in fields}
                      | {f for f, _ in m.TIMESERIES_BUCKETS.values()}
                      | {gf for gf, _t, _d in m.WHERE_FIELDS.values()})
        out, _, _ = run_main(BASE + ["--inspect"],
                             fake=FakeAPI(gated_fields=tuple(all_fields)))
        self.assertNotRegex(out, r"\n    \S+\s+yes\n")
        self.assertIn("timeseries: (none)", out)

    def test_dataset_unavailable_with_other_error(self):
        fake = FakeAPI(fail_substrings=("firewallEventsAdaptiveGroups",))
        out, _, _ = run_main(BASE + ["--inspect"], fake=fake)
        self.assertIn("NOT AVAILABLE — injected failure", out)

    def test_aborts_on_unrecognized_error(self):
        # availability passes (no dims), but every dimension query fails without
        # naming a field -> elimination can't proceed
        fake = FakeAPI(fail_substrings=("dimensions",))
        out, err, _ = run_main(BASE + ["--inspect"], fake=fake)
        self.assertIn("inspect incomplete", out)
        self.assertIn("inspect aborted", err)

    def test_without_zone_access(self):
        out, _, _ = run_main(BASE + ["--inspect"], fake=FakeAPI(empty_zones=True))
        self.assertIn("token likely lacks", out)

    def test_settings_unavailable_omits_limits(self):
        out, _, _ = run_main(BASE + ["--inspect"],
                             fake=FakeAPI(fail_substrings=("settings",)))
        self.assertIn("AVAILABLE", out)
        self.assertNotIn("limits:", out)

    def test_partial_settings_omits_limits_line(self):
        # all four numeric settings fields gated -> only 'enabled' survives,
        # so no limits line is printed
        gated = ("maxDuration", "maxNumberOfFields", "maxPageSize", "notOlderThan")
        out, _, _ = run_main(BASE + ["--inspect"], fake=FakeAPI(gated_fields=gated))
        self.assertIn("AVAILABLE", out)
        self.assertNotIn("limits:", out)

    def test_zone_id_no_plan_header(self):
        out, _, _ = run_main(["--token", "t", "--zone", ZONE_ID, "--inspect"])
        self.assertIn(f"=== flareql inspect | {ZONE_ID} ===", out)

    def test_ignored_flags_warn(self):
        _, err, _ = run_main(BASE + ["--inspect", "--dims", "ip", "--dataset", "http",
                                     "--timeseries", "hour", "--limit", "10",
                                     "--last", "3d", "--where", "asn eq 1",
                                     "--asn", "64496"])
        self.assertIn("--inspect runs standalone; ignoring: --dims, --dataset, "
                      "--timeseries, --limit, --last/--from/--to, --where, filter flags",
                      err)

    def test_explicit_window_flags_also_ignored(self):
        _, err, _ = run_main(BASE + ["--inspect", "--from", "2026-01-01",
                                     "--to", "2026-01-02"])
        self.assertIn("--last/--from/--to", err)
        _, err, _ = run_main(BASE + ["--inspect", "--to", "2026-01-02"])
        self.assertIn("--last/--from/--to", err)

    def test_csv_format_warns_and_writes_json(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "report.out")
            _, err, _ = run_main(BASE + ["--inspect", "--format", "csv", "--out", path])
            with open(path) as fh:
                report = json.load(fh)
        self.assertIn("ignoring --format csv", err)
        self.assertIn("datasets", report)

    def test_quiet_suppresses_console(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "report.json")
            out, _, _ = run_main(BASE + ["--inspect", "--quiet", "--out", path])
            self.assertTrue(os.path.exists(path))
        self.assertEqual(out, "")

    def test_parse_gated_field_variants(self):
        self.assertEqual(m.parse_gated_field(
            "zone 'x' does not have access to the field 'clientasn' from the path"),
            "clientasn")
        self.assertEqual(m.parse_gated_field('Cannot query field "ja4" on type "t"'),
                         "ja4")
        self.assertEqual(m.parse_gated_field('Field "botScore" is not defined by "f"'),
                         "botScore")
        self.assertIsNone(m.parse_gated_field("query quota exceeded"))

    def test_fmt_secs(self):
        self.assertEqual(m.fmt_secs(86400), "1d")
        self.assertEqual(m.fmt_secs(2678400), "31d")
        self.assertEqual(m.fmt_secs(3600 * 5), "5h")
        self.assertEqual(m.fmt_secs(90), "90s")


class TestDatasetSettings(unittest.TestCase):
    ZONES = {"viewer": {"zones": [{"settings": {"httpRequestsAdaptiveGroups":
             {"enabled": True, "notOlderThan": 86400}}}]}}

    def run_settings(self, side_effects):
        with mock.patch.object(m, "gql", side_effect=side_effects):
            return m.get_dataset_settings({}, "Z", "httpRequestsAdaptiveGroups", 60)

    def test_success(self):
        self.assertEqual(self.run_settings([(self.ZONES, [])])["notOlderThan"], 86400)

    def test_field_elimination_then_success(self):
        effects = [(None, [{"message": 'Cannot query field "maxPageSize" on "s"'}]),
                   (self.ZONES, [])]
        self.assertEqual(self.run_settings(effects)["notOlderThan"], 86400)

    def test_unnamed_error_returns_none(self):
        self.assertIsNone(self.run_settings([(None, [{"message": "internal error"}])]))

    def test_empty_zones_returns_none(self):
        self.assertIsNone(self.run_settings([({"viewer": {"zones": []}}, [])]))

    def test_all_fields_eliminated_returns_none(self):
        effects = [(None, [{"message": f'Cannot query field "{f}" on "s"'}])
                   for f in m.SETTINGS_FIELDS]
        self.assertIsNone(self.run_settings(effects))


# ---------------------------------------------------------------- main / CLI

class TestMain(unittest.TestCase):
    def test_full_run_both_datasets(self):
        out, err, fake = run_main(BASE + ["--last", "3d"])
        self.assertIn("HTTP requests (sampled)", out)
        self.assertIn("Firewall events", out)
        self.assertIn("Top ASNs", out)
        self.assertIn("Top rules fired", out)
        # opt-in score distributions must not run under --dims all
        self.assertFalse(any("wafSqliAttackScore" in q for q in fake.queries))

    def test_numeric_dim_sorted_by_value(self):
        out, _, _ = run_main(BASE + ["--dataset", "http", "--dims", "botscore"])
        self.assertLess(out.index(" 2 "), out.index(" 30 "))

    def test_filters_where_and_json_out(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "r.json")
            out, err, fake = run_main(BASE + [
                "--dataset", "http", "--dims", "asn,ip",
                "--asn", "64496", "--country", "ru", "--host", "h",
                "--path-contains", "/x", "--ip", "192.0.2.7", "--ja4", "j",
                "--bot-score-min", "2", "--bot-score-max", "29",
                "--where", "ua contains bot or status eq 403",
                "--out", path])
            data = json.load(open(path))
        self.assertIn("Filters:", out)
        self.assertEqual(data["meta"]["zone"], "smithlabs.io")
        self.assertIn("asn", data["datasets"]["http"]["dims"])
        self.assertTrue(any('"AND"' not in q and "OR" in q for q in fake.queries))

    def test_csv_out_with_failing_dim_and_timeseries(self):
        fake = FakeAPI(fail_substrings=["ja4"])
        with tempfile.TemporaryDirectory() as td:
            outdir = os.path.join(td, "pull")
            _, err, _ = run_main(BASE + ["--dataset", "http", "--dims", "ip,ja4",
                                         "--timeseries", "hour",
                                         "--format", "csv", "--out", outdir],
                                 fake=fake)
            files = sorted(os.listdir(outdir))
        self.assertIn("http_ip.csv", files)
        self.assertIn("http_timeseries.csv", files)
        self.assertIn("meta.json", files)
        self.assertNotIn("http_ja4.csv", files)
        self.assertIn("injected failure", err)

    def test_quiet_suppresses_tables(self):
        out, _, _ = run_main(BASE + ["--dataset", "http", "--dims", "ip",
                                     "--timeseries", "hour", "--quiet"])
        self.assertEqual(out, "")

    def test_where_skips_dataset_missing_field(self):
        _, err, fake = run_main(BASE + ["--dims", "ip", "--where", "botscore lt 30"])
        self.assertIn("skipping this dataset", err)
        self.assertFalse(any("firewallEvents" in q for q in fake.queries))

    def test_where_parse_error_dies(self):
        with self.assertRaises(SystemExit):
            run_main(BASE + ["--where", "asn eq"])

    def test_unknown_dim_warns(self):
        _, err, _ = run_main(BASE + ["--dataset", "http", "--dims", "ip,bogus"])
        self.assertIn("'bogus' not available", err)

    def test_asn_type_flip_on_firewall(self):
        fake = FakeAPI(flip_asn=True)
        out, _, fake = run_main(BASE + ["--dataset", "firewall", "--dims", "ip",
                                        "--asn", "64496"], fake=fake)
        self.assertIn("Firewall events", out)
        quoted = [q for q in fake.queries if 'clientAsn: "64496"' in q]
        unquoted = [q for q in fake.queries if "clientAsn: 64496" in q]
        self.assertTrue(quoted and unquoted)

    def test_total_query_failure_skips_dataset(self):
        fake = FakeAPI(fail_substrings=["firewallEvents"])
        out, err, _ = run_main(BASE + ["--dims", "ip"], fake=fake)
        self.assertIn("window-total query failed", err)
        self.assertIn("HTTP requests (sampled)", out)

    def test_timeseries_error_warns(self):
        fake = FakeAPI(fail_substrings=["datetimeMinute"])
        _, err, _ = run_main(BASE + ["--dataset", "http", "--dims", "ip",
                                     "--timeseries", "minute"], fake=fake)
        self.assertIn("timeseries] query failed", err)

    def test_cross_dataset_flag_warnings(self):
        _, err, _ = run_main(BASE + ["--dataset", "firewall", "--dims", "ip",
                                     "--bot-score-min", "2"])
        self.assertIn("--bot-score-*", err)
        _, err, _ = run_main(BASE + ["--dataset", "http", "--dims", "ip",
                                     "--action", "block"])
        self.assertIn("--action", err)

    def test_retention_error_hint(self):
        fake = FakeAPI(fail_substrings=("httpRequestsAdaptiveGroups",),
                       fail_message="cannot request data older than 86400s")
        _, err, _ = run_main(BASE + ["--dataset", "http", "--dims", "ip"], fake=fake)
        self.assertIn("retention limit", err)
        self.assertIn("--inspect", err)

    def test_gated_field_hint_on_pull(self):
        fake = FakeAPI(gated_fields=("botScore",))
        _, err, _ = run_main(BASE + ["--dataset", "http", "--dims", "botscore"],
                             fake=fake)
        self.assertIn("plan/entitlement gating", err)

    def test_zone_is_required(self):
        with captured(), self.assertRaises(SystemExit):
            with mock.patch.object(m.sys, "argv", ["flareql.py", "--token", "t"]):
                m.main()


if __name__ == "__main__":
    unittest.main()
