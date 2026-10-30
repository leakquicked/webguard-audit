import unittest
from webguard_audit import normalize_target

class WebGuardTests(unittest.TestCase):
    def test_domain_defaults_to_https(self):
        url, parsed = normalize_target("example.com")
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "example.com")
    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            normalize_target("ftp://example.com")
    def test_rejects_credentials(self):
        with self.assertRaises(ValueError):
            normalize_target("https://user:pass@example.com")

if __name__ == "__main__": unittest.main()
