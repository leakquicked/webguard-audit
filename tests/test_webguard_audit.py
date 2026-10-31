import unittest

from webguard_audit import normalize_target


class WebGuardTests(unittest.TestCase):
    def test_domain_defaults_to_https(self):
        url, parsed = normalize_target("example.com")
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "example.com")

    def test_domain_with_port_defaults_to_https(self):
        _, parsed = normalize_target("example.com:8443")
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.port, 8443)

    def test_accepts_explicit_http_url(self):
        _, parsed = normalize_target("http://example.com")
        self.assertEqual(parsed.scheme, "http")

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            normalize_target("ftp://example.com")

    def test_rejects_credentials(self):
        with self.assertRaises(ValueError):
            normalize_target("https://user:pass@example.com")

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            normalize_target("https://example.com:99999")

    def test_rejects_non_numeric_port(self):
        with self.assertRaises(ValueError):
            normalize_target("https://example.com:abc")

    def test_rejects_empty_target(self):
        with self.assertRaises(ValueError):
            normalize_target("")


if __name__ == "__main__":
    unittest.main()
