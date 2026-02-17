#!/usr/bin/env python3
"""
Tests for Reconflex utils module
"""

import sys
import os
import unittest

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import is_valid_domain, validate_domains


class TestDomainValidation(unittest.TestCase):
    """Test domain validation functions."""

    def test_valid_domains(self):
        """Test that valid domains pass validation."""
        valid = [
            'example.com',
            'sub.example.com',
            'deep.sub.example.com',
            'abbvie.com',
            'test-domain.co.uk',
            'a123.io',
            'my-site.org',
        ]
        for domain in valid:
            self.assertTrue(is_valid_domain(domain), f"Should be valid: {domain}")

    def test_invalid_domains(self):
        """Test that invalid domains fail validation."""
        invalid = [
            '',
            None,
            'a',
            '.com',
            'example.',
            '-example.com',
            'example-.com',
            'exam ple.com',
            'example..com',
            'http://example.com',
            'example.com/path',
            '*.example.com',
            123,
        ]
        for domain in invalid:
            self.assertFalse(is_valid_domain(domain), f"Should be invalid: {domain}")

    def test_validate_domains_list(self):
        """Test batch domain validation."""
        input_domains = [
            'valid.com',
            '',
            'also-valid.org',
            'not valid',
            'another.io',
        ]
        result = validate_domains(input_domains)
        self.assertEqual(len(result), 3)
        self.assertIn('valid.com', result)
        self.assertIn('also-valid.org', result)
        self.assertIn('another.io', result)

    def test_validate_domains_empty(self):
        """Test batch validation with empty list."""
        self.assertEqual(validate_domains([]), [])
        self.assertEqual(validate_domains(['']), [])


class TestCLIParsing(unittest.TestCase):
    """Test CLI source parsing."""

    def test_parse_sources(self):
        """Test source parsing with aliases."""
        from cli import parse_sources

        # Test aliases
        result = parse_sources('vt,st,sf')
        self.assertIn('virustotal', result)
        self.assertIn('securitytrails', result)
        self.assertIn('subfinder', result)

    def test_parse_sources_full_names(self):
        """Test source parsing with full names."""
        from cli import parse_sources

        result = parse_sources('virustotal,crtsh,shodan')
        self.assertEqual(len(result), 3)
        self.assertIn('virustotal', result)
        self.assertIn('crtsh', result)
        self.assertIn('shodan', result)

    def test_parse_sources_none(self):
        """Test that None input returns None (use all)."""
        from cli import parse_sources

        self.assertIsNone(parse_sources(None))
        self.assertIsNone(parse_sources(''))

    def test_parse_sources_invalid(self):
        """Test that invalid sources are skipped."""
        from cli import parse_sources

        result = parse_sources('virustotal,nonexistent,crtsh')
        self.assertEqual(len(result), 2)


class TestOutputManager(unittest.TestCase):
    """Test output manager functions."""

    def test_save_results(self):
        """Test saving results to file."""
        from output_manager import save_results
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_path = f.name

        try:
            items = {'c.example.com', 'a.example.com', 'b.example.com'}
            count = save_results(temp_path, items)
            self.assertEqual(count, 3)

            with open(temp_path, 'r') as f:
                lines = [line.strip() for line in f if line.strip()]

            # Should be sorted
            self.assertEqual(lines[0], 'a.example.com')
            self.assertEqual(lines[1], 'b.example.com')
            self.assertEqual(lines[2], 'c.example.com')
        finally:
            os.unlink(temp_path)

    def test_save_results_dedup(self):
        """Test that save_results deduplicates."""
        from output_manager import save_results
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_path = f.name

        try:
            items = ['a.com', 'b.com', 'a.com', 'b.com', 'c.com']
            count = save_results(temp_path, items)
            self.assertEqual(count, 3)
        finally:
            os.unlink(temp_path)


class TestHTTPXDetection(unittest.TestCase):
    """Test Go httpx binary detection."""

    def test_find_go_httpx(self):
        """Test that find_go_httpx returns a path or None."""
        from utils import find_go_httpx

        result = find_go_httpx()
        # Should return a string path or None
        self.assertTrue(result is None or isinstance(result, str))
        if result:
            self.assertTrue(os.path.isfile(result))


if __name__ == '__main__':
    unittest.main()
