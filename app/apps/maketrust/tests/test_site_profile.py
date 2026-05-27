"""Unit tests for the body classifier and WAF detector in site_profile.

We only test the pure-Python helpers; the full module is exercised via the
orchestrator integration test in test_orchestrator.py.
"""
from __future__ import annotations

import pytest

from apps.maketrust.scanner.site_profile import (
    _classify_body,
    _detect_waf,
)


# --- _classify_body ------------------------------------------------------

class TestClassifyBodyType:
    def test_unreachable_when_status_zero(self):
        assert _classify_body("", 0) == ("unreachable", "")

    def test_parked_sedo(self):
        body = '<html><body><script src="https://sedoparking.com/p.js"></script></body></html>'
        assert _classify_body(body, 200) == ("parked", "")

    def test_parked_godaddy(self):
        body = '<html>buy now at https://godaddy.com/forsale/example</html>'
        assert _classify_body(body, 200) == ("parked", "")

    def test_parked_dan_com(self):
        body = '<html><a href="https://dan.com/buy/example">acquire</a></html>'
        assert _classify_body(body, 200) == ("parked", "")

    def test_for_sale_french(self):
        body = '<html><h1>Ce domaine est à vendre</h1></html>'
        assert _classify_body(body, 200) == ("for_sale", "")

    def test_for_sale_english(self):
        body = '<html><h1>BUY THIS DOMAIN today</h1></html>'
        assert _classify_body(body, 200) == ("for_sale", "")

    def test_registrar_default_nginx(self):
        body = '<html><h1>Welcome to nginx!</h1></html>'
        assert _classify_body(body, 200) == ("registrar_default", "")

    def test_registrar_default_apache(self):
        body = '<!DOCTYPE html><h1>Apache2 Ubuntu Default Page</h1>'
        assert _classify_body(body, 200) == ("registrar_default", "")

    def test_registrar_default_only_below_2k(self):
        # If the body is huge, it's probably a real site even if it mentions nginx.
        body = "Welcome to nginx" + ("x" * 3000)
        assert _classify_body(body, 200)[0] != "registrar_default"

    def test_non_html(self):
        body = '{"status": "ok"}'
        assert _classify_body(body, 200) == ("non_html", "")

    def test_real_site_default(self):
        body = '<!DOCTYPE html><html><body><h1>Acme Corp</h1></body></html>'
        assert _classify_body(body, 200) == ("real_site", "custom")


class TestClassifyBodyStack:
    def test_wordpress_via_wp_content(self):
        body = '<!DOCTYPE html><html><link href="/wp-content/themes/x.css"></html>'
        assert _classify_body(body, 200) == ("real_site", "wordpress")

    def test_shopify_cdn(self):
        body = '<!DOCTYPE html><html><script src="https://cdn.shopify.com/s/x.js"></script></html>'
        assert _classify_body(body, 200) == ("real_site", "shopify")

    def test_wix(self):
        body = '<!DOCTYPE html><html><img src="https://static.wixstatic.com/x.jpg"></html>'
        assert _classify_body(body, 200) == ("real_site", "wix")

    def test_squarespace(self):
        body = '<!DOCTYPE html><html><img src="https://static1.squarespace.com/x"></html>'
        assert _classify_body(body, 200) == ("real_site", "squarespace")

    def test_webflow(self):
        body = '<!DOCTYPE html><html data-wf-domain="acme.webflow.io"></html>'
        assert _classify_body(body, 200) == ("real_site", "webflow")

    def test_drupal(self):
        body = '<!DOCTYPE html><html><script>"drupal-settings-json"</script></html>'
        assert _classify_body(body, 200) == ("real_site", "drupal")

    def test_generator_meta_wins_over_body(self):
        body = '<!DOCTYPE html><html><meta name="generator" content="Ghost 5.0"></html>'
        assert _classify_body(body, 200) == ("real_site", "ghost")

    def test_generator_unknown_stack_keeps_custom(self):
        body = '<!DOCTYPE html><html><meta name="generator" content="MyCustomFramework v1"></html>'
        assert _classify_body(body, 200) == ("real_site", "custom")


# --- _detect_waf ---------------------------------------------------------

class TestWafFromHeaders:
    def test_cloudflare_via_cf_ray(self):
        assert _detect_waf({"CF-Ray": "abc-AMS"}, "") == "cloudflare"

    def test_cloudflare_via_server(self):
        assert _detect_waf({"Server": "cloudflare"}, "") == "cloudflare"

    def test_akamai(self):
        assert _detect_waf({"Server": "AkamaiGHost"}, "") == "akamai"

    def test_aws_cloudfront(self):
        assert _detect_waf({"X-Amz-Cf-Id": "blah"}, "") == "aws_cloudfront"

    def test_fastly_via_request_id(self):
        assert _detect_waf({"X-Fastly-Request-Id": "x"}, "") == "fastly"

    def test_fastly_via_served_by(self):
        assert _detect_waf({"X-Served-By": "cache-mad1234-MAD"}, "") == "fastly"

    def test_sucuri(self):
        assert _detect_waf({"X-Sucuri-Id": "abc"}, "") == "sucuri"

    def test_imperva(self):
        assert _detect_waf({"X-Iinfo": "abc"}, "") == "imperva"

    def test_bunnycdn(self):
        assert _detect_waf({"Server": "BunnyCDN-FRA1"}, "") == "bunnycdn"

    def test_no_match(self):
        assert _detect_waf({"Server": "nginx"}, "") == ""


class TestWafFromCookies:
    def test_cloudflare_cookie(self):
        assert _detect_waf({}, "__cf_bm=xyz; Path=/") == "cloudflare"

    def test_imperva_cookie(self):
        assert _detect_waf({}, "incap_ses_42_99=xyz") == "imperva"

    def test_unrelated_cookie(self):
        assert _detect_waf({}, "session=xyz; Path=/") == ""
