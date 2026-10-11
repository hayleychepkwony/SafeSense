import os
import unittest

from safesense import analyze, analyze_url, registered_domain
from safesense.engine import scan
from safesense import ml

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def read(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def ids(findings):
    return {f.id for f in findings}


class DomainTests(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("mail.google.com"), "google.com")
        self.assertEqual(registered_domain("www.safaricom.co.ke"), "safaricom.co.ke")
        self.assertEqual(registered_domain("example.com"), "example.com")


class UrlTests(unittest.TestCase):
    def test_lookalike_domain(self):
        self.assertIn("lookalike-domain", ids(analyze_url("https://paypa1.com/login")))
        self.assertIn("lookalike-domain", ids(analyze_url("https://rnicrosoft.com")))

    def test_brand_in_wrong_domain(self):
        self.assertIn("brand-misuse", ids(analyze_url("https://paypal-verify-account.com")))

    def test_official_domain_not_flagged(self):
        self.assertEqual(analyze_url("https://accounts.google.com/signin"), [])
        self.assertEqual(analyze_url("https://www.safaricom.co.ke/personal"), [])

    def test_unrelated_word_not_flagged(self):
        # 'apple' inside another word must not trigger the brand check
        self.assertEqual(analyze_url("https://pineapple-recipes.com"), [])

    def test_ip_address(self):
        self.assertIn("ip-address-link", ids(analyze_url("http://203.0.113.45/login")))

    def test_shortener(self):
        self.assertIn("shortener", ids(analyze_url("https://bit.ly/abc123")))

    def test_userinfo_trick(self):
        self.assertIn("userinfo-trick", ids(analyze_url("https://paypal.com@evil.example.net/")))

    def test_punycode(self):
        self.assertIn("punycode", ids(analyze_url("https://xn--pypal-4ve.com")))


class TextTests(unittest.TestCase):
    def test_pin_inside_word_not_flagged(self):
        r = analyze("We are spinning up the new team calendar next week.")
        self.assertNotIn("credentials", ids(r.findings))

    def test_credential_request(self):
        r = analyze("Please enter your password to continue.")
        self.assertIn("credentials", ids(r.findings))

    def test_display_name_spoof_and_reply_mismatch(self):
        text = 'From: "Microsoft Support" <helpdesk@gmail.com>\nReply-To: x@other.example.net\n\nHi'
        found = ids(analyze(text).findings)
        self.assertIn("display-name-spoof", found)
        self.assertIn("reply-mismatch", found)

    def test_link_text_mismatch(self):
        text = '<a href="http://evil.example.net/x">https://www.paypal.com/verify</a>'
        self.assertIn("link-text-mismatch", ids(analyze(text).findings))

    def test_risky_attachment(self):
        self.assertIn("risky-attachment", ids(analyze("See Invoice_88231.zip attached").findings))

    def test_bare_domain_input(self):
        r = analyze("paypa1-login.com/verify")
        self.assertIn("lookalike-domain", ids(r.findings))
        self.assertNotIn("no-https", ids(r.findings))

    def test_empty_input(self):
        r = analyze("")
        self.assertEqual((r.score, r.level), (0, "low"))


class SampleTests(unittest.TestCase):
    def test_phishing_samples_score_high(self):
        for name in ("phishing_1_paypal.txt", "phishing_2_prize.txt", "phishing_3_invoice.txt"):
            with self.subTest(name=name):
                self.assertEqual(analyze(read(name)).level, "high")

    def test_legit_sample_scores_low(self):
        r = analyze(read("legit_1_meeting.txt"))
        self.assertEqual(r.level, "low")
        self.assertEqual(r.findings, [])

    def test_score_is_capped(self):
        self.assertLessEqual(analyze(read("phishing_1_paypal.txt")).score, 100)


class EngineTests(unittest.TestCase):
    def test_model_separates_classes(self):
        self.assertGreater(ml.phishing_probability("Your account will be suspended. Verify your password now."), 0.8)
        self.assertLess(ml.phishing_probability("Hi, thanks for the call. Notes are in the shared folder."), 0.3)

    def test_scan_levels(self):
        self.assertEqual(scan(read("phishing_1_paypal.txt"))["level"], "high")
        self.assertEqual(scan(read("phishing_2_prize.txt"))["level"], "high")
        self.assertEqual(scan(read("legit_1_meeting.txt"))["level"], "low")

    def test_scan_shape(self):
        r = scan("http://bit.ly/x")
        for key in ("score", "level", "rule_score", "ml_probability", "ml_signals", "urls", "findings"):
            self.assertIn(key, r)
        self.assertTrue(0 <= r["score"] <= 100)


class ApiTests(unittest.TestCase):
    def setUp(self):
        import app as flask_app
        self.client = flask_app.app.test_client()

    def test_home_page(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_analyze_ok(self):
        res = self.client.post("/api/analyze", json={"text": read("phishing_1_paypal.txt")})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["level"], "high")

    def test_analyze_rejects_empty(self):
        self.assertEqual(self.client.post("/api/analyze", json={"text": "  "}).status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", data="nope").status_code, 400)


if __name__ == "__main__":
    unittest.main()
