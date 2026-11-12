import unittest
from main import triage

class Tests(unittest.TestCase):
    def test_normal(self): self.assertEqual(triage('https://portal.example/')['verdict'],'no_flags')
    def test_userinfo(self): self.assertIn('userinfo_in_url',triage('https://portal.example@evil.example/')['reasons'])
    def test_suffix_is_not_trusted(self): self.assertIn('outside_trusted_hosts',triage('https://portal.example.evil.example/', ['portal.example'])['reasons'])
    def test_ipv6(self): self.assertIn('ip_literal_host',triage('http://[2001:db8::1]/')['reasons'])
    def test_unicode(self): self.assertIn('internationalized_host',triage('https://пример.example/')['reasons'])
    def test_bad_port(self): self.assertEqual(triage('https://example.test:99999/')['reasons'],['invalid_http_url'])
    def test_relative(self): self.assertEqual(triage('/login')['host'],None)
