"""
=============================================================================
Attacker Clustering Module
=============================================================================
Groups attackers into behavioral clusters using K-Means clustering.
Uses StandardScaler for normalization and PCA for 2D visualization.
=============================================================================
"""

import logging
import os
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

from .feature_extractor import AttackerFeatureExtractor

logger = logging.getLogger("ai.clustering")

# Model persistence directory
MODEL_DIR = os.getenv("MODEL_DIR", "/app/models")

# Cluster label definitions
CLUSTER_LABELS = {
    0: "Script Kiddie",
    1: "Credential Stuffer",
    2: "Advanced Recon",
    3: "Data Thief",
    4: "Malware Dropper",
}

CLUSTER_DESCRIPTIONS = {
    0: "Low-skill attacker using automated tools with minimal interaction",
    1: "Focused on credential brute-forcing with large wordlists",
    2: "Methodical reconnaissance, careful enumeration of system resources",
    3: "Targeted data exfiltration, accessing sensitive files and databases",
    4: "Attempts to download and deploy malware or backdoors",
}


class AttackerClusterer:
    """
    Groups attacker sessions into behavioral clusters using K-Means.

    Clusters:
        0: Script Kiddie
        1: Credential Stuffer
        2: Advanced Recon
        3: Data Thief
        4: Malware Dropper
    """

    N_CLUSTERS = 5
    RANDOM_STATE = 42

    def __init__(self):
        self.feature_extractor = AttackerFeatureExtractor()
        self.scaler: Optional[StandardScaler] = None
        self.kmeans: Optional[KMeans] = None
        self.pca: Optional[PCA] = None
        self.is_trained = False
        self._cluster_stats: Dict = {}

        # Ensure model directory exists
        os.makedirs(MODEL_DIR, exist_ok=True)

        # Try to load existing models
        self._load_models()

    def _model_path(self, name: str) -> str:
        return os.path.join(MODEL_DIR, name)

    def _load_models(self):
        """Load previously saved models from disk."""
        scaler_path = self._model_path("scaler.pkl")
        kmeans_path = self._model_path("kmeans.pkl")
        pca_path = self._model_path("pca.pkl")
        stats_path = self._model_path("cluster_stats.pkl")

        if all(os.path.exists(p) for p in [scaler_path, kmeans_path, pca_path]):
            try:
                self.scaler = joblib.load(scaler_path)
                self.kmeans = joblib.load(kmeans_path)
                self.pca = joblib.load(pca_path)
                if os.path.exists(stats_path):
                    self._cluster_stats = joblib.load(stats_path)
                self.is_trained = True
                logger.info("Loaded pre-trained clustering models from disk")
            except Exception as e:
                logger.warning(f"Could not load models: {e}")
                self.is_trained = False
        else:
            logger.info("No pre-trained models found — training required")

    def _save_models(self):
        """Save models to disk."""
        try:
            joblib.dump(self.scaler, self._model_path("scaler.pkl"))
            joblib.dump(self.kmeans, self._model_path("kmeans.pkl"))
            joblib.dump(self.pca, self._model_path("pca.pkl"))
            joblib.dump(self._cluster_stats, self._model_path("cluster_stats.pkl"))
            logger.info(f"Models saved to {MODEL_DIR}")
        except Exception as e:
            logger.error(f"Error saving models: {e}")

    def train(self, sessions: List[dict]) -> dict:
        """
        Train the clustering model on a list of session data dicts.

        Args:
            sessions: List of session data dictionaries

        Returns:
            Training summary with cluster statistics
        """
        if len(sessions) < self.N_CLUSTERS:
            logger.warning(
                f"Need at least {self.N_CLUSTERS} sessions to train, "
                f"got {len(sessions)}"
            )
            return {
                "status": "error",
                "message": f"Need at least {self.N_CLUSTERS} sessions",
                "sessions_provided": len(sessions),
            }

        logger.info(f"Training clustering model on {len(sessions)} sessions")

        # Extract features from all sessions
        feature_matrix = np.array([
            self.feature_extractor.extract(s) for s in sessions
        ])
        logger.info(f"Feature matrix shape: {feature_matrix.shape}")

        # Scale features
        self.scaler = StandardScaler()
        scaled_features = self.scaler.fit_transform(feature_matrix)

        # Fit K-Means
        self.kmeans = KMeans(
            n_clusters=self.N_CLUSTERS,
            random_state=self.RANDOM_STATE,
            n_init=10,
            max_iter=300,
        )
        cluster_labels = self.kmeans.fit_predict(scaled_features)

        # Fit PCA for 2D visualization
        self.pca = PCA(n_components=2, random_state=self.RANDOM_STATE)
        positions_2d = self.pca.fit_transform(scaled_features)

        # Calculate cluster statistics
        self._cluster_stats = {}
        for cluster_id in range(self.N_CLUSTERS):
            mask = cluster_labels == cluster_id
            cluster_features = feature_matrix[mask]
            cluster_positions = positions_2d[mask]

            if len(cluster_features) > 0:
                self._cluster_stats[cluster_id] = {
                    "count": int(mask.sum()),
                    "label": CLUSTER_LABELS[cluster_id],
                    "description": CLUSTER_DESCRIPTIONS[cluster_id],
                    "avg_duration": float(cluster_features[:, 0].mean()),
                    "avg_commands": float(cluster_features[:, 1].mean()),
                    "avg_credentials": float(cluster_features[:, 9].mean()),
                    "avg_files": float(cluster_features[:, 12].mean()),
                    "center_2d": cluster_positions.mean(axis=0).tolist()
                    if len(cluster_positions) > 0
                    else [0.0, 0.0],
                }
            else:
                self._cluster_stats[cluster_id] = {
                    "count": 0,
                    "label": CLUSTER_LABELS[cluster_id],
                    "description": CLUSTER_DESCRIPTIONS[cluster_id],
                    "avg_duration": 0.0,
                    "avg_commands": 0.0,
                    "avg_credentials": 0.0,
                    "avg_files": 0.0,
                    "center_2d": [0.0, 0.0],
                }

        self.is_trained = True
        self._save_models()

        summary = {
            "status": "success",
            "sessions_trained": len(sessions),
            "n_clusters": self.N_CLUSTERS,
            "cluster_stats": self._cluster_stats,
            "pca_explained_variance": self.pca.explained_variance_ratio_.tolist(),
        }

        logger.info(
            f"Training complete: {len(sessions)} sessions → "
            f"{self.N_CLUSTERS} clusters"
        )
        return summary

    def predict(self, session_data: dict) -> dict:
        """
        Predict the cluster for a given session.

        Args:
            session_data: Session data dictionary

        Returns:
            Prediction result with cluster ID, label, confidence,
            2D position, and feature summary
        """
        if not self.is_trained:
            logger.warning("Model not trained — cannot predict")
            return {
                "status": "not_trained",
                "message": "Model has not been trained yet",
            }

        # Extract and scale features
        features = self.feature_extractor.extract(session_data)
        scaled = self.scaler.transform(features.reshape(1, -1))

        # Predict cluster
        cluster_id = int(self.kmeans.predict(scaled)[0])

        # Calculate confidence (inverse distance to cluster center)
        distances = self.kmeans.transform(scaled)[0]
        min_distance = distances[cluster_id]
        max_distance = distances.max()

        if max_distance > 0:
            confidence = 1.0 - (min_distance / max_distance)
        else:
            confidence = 1.0
        confidence = max(0.0, min(1.0, confidence))

        # Get 2D position
        position_2d = self.pca.transform(scaled)[0].tolist()

        # Feature summary
        feature_names = AttackerFeatureExtractor.FEATURE_NAMES
        feature_summary = dict(zip(feature_names, features.tolist()))

        return {
            "status": "success",
            "cluster_id": cluster_id,
            "cluster_label": CLUSTER_LABELS.get(cluster_id, "Unknown"),
            "cluster_description": CLUSTER_DESCRIPTIONS.get(cluster_id, ""),
            "confidence": round(confidence, 4),
            "position_2d": position_2d,
            "feature_summary": feature_summary,
            "distances_to_centers": distances.tolist(),
        }

    def get_cluster_stats(self) -> Dict:
        """Return current cluster statistics."""
        return {
            "is_trained": self.is_trained,
            "n_clusters": self.N_CLUSTERS,
            "cluster_labels": CLUSTER_LABELS,
            "cluster_stats": self._cluster_stats,
        }
