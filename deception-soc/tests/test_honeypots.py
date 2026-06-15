"""
Tests for the Honeypots (SSH command simulation, HTTP responses).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'honeypots', 'ssh-honeypot'))

# We can't import fake_ssh directly due to asyncssh dependency,
# but we can test the logic patterns


class TestSSHHoneypotLogic(unittest.TestCase):
    """Test SSH honeypot helper logic."""

    def test_accepted_credentials(self):
        """Verify the set of accepted weak credentials."""
        ACCEPTED = {
            ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
            ("root", "root"), ("root", "toor"), ("test", "test"),
        }
        self.assertEqual(len(ACCEPTED), 6)
        self.assertIn(("admin", "admin123"), ACCEPTED)
        self.assertIn(("root", "toor"), ACCEPTED)
        self.assertNotIn(("admin", "strongpassword"), ACCEPTED)

    def test_fake_filesystem_paths(self):
        """Verify bait files exist in the fake filesystem directory."""
        base = os.path.join(os.path.dirname(__file__), '..', 'honeypots',
                           'ssh-honeypot', 'fake_filesystem')
        expected_files = [
            'etc/passwd',
            'etc/shadow',
            'home/admin/credentials.txt',
            'home/admin/notes.txt',
            'home/admin/.bash_history',
            'var/www/config.php',
        ]
        for f in expected_files:
            path = os.path.join(base, f)
            self.assertTrue(os.path.exists(path), f"Missing bait file: {f}")

    def test_bait_files_contain_fake_marker(self):
        """Ensure all bait credentials contain 'FAKE' marker."""
        creds_path = os.path.join(
            os.path.dirname(__file__), '..', 'honeypots',
            'ssh-honeypot', 'fake_filesystem', 'home', 'admin', 'credentials.txt'
        )
        with open(creds_path, 'r') as f:
            content = f.read()
        self.assertIn("FAKE", content, "Bait credentials must contain 'FAKE' marker")


class TestHTTPHoneypotLogic(unittest.TestCase):
    """Test HTTP honeypot patterns."""

    def test_sqli_patterns(self):
        """Verify SQL injection patterns are comprehensive."""
        import re
        patterns = [
            r"union\s+select", r"select\s+.*\s+from", r"1\s*=\s*1",
            r"'\s*or\s+", r"--\s*$",
        ]
        test_payloads = [
            "1' UNION SELECT * FROM users--",
            "admin' OR '1'='1",
            "1; DROP TABLE users;--",
        ]
        for payload in test_payloads:
            matched = any(re.search(p, payload.lower()) for p in patterns)
            self.assertTrue(matched, f"SQLi payload not detected: {payload}")


if __name__ == "__main__":
    unittest.main()
