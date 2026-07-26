"""
Unsupervised Behavioral Anomaly Detection Model.
Uses Isolation Forest to detect novel/unseen deviations in entity behavioral history.

Why Isolation Forest is Appropriate for Behavioral Anomaly Detection:
--------------------------------------------------------------------
1. Unsupervised Baseline: In cybersecurity, the vast majority of telemetry is normal.
   Attack samples are rare, highly imbalanced, and mutate constantly. Isolation Forest trains
   strictly on normal patterns without needing historical threat labels, capturing zero-day attacks.
2. Efficient Outlier Isolation: Rather than defining complex, high-dimensional boundaries
   around normal data clusters (which can lead to overfitting and false positives), Isolation Forest
   isolates anomalies by randomly partitioning features. Anomalies require significantly fewer
   splits to isolate, meaning they appear closer to the root of the trees.
3. Linear Scalability: Access logs contain millions of daily entries. Isolation Forest's
   computational complexity scales linearly O(n), making it highly performant for streaming telemetry.
"""
import numpy as np
from sklearn.ensemble import IsolationForest

class ProfileAnomalyDetector:
    """Isolation Forest model to identify general behavioral baseline deviations."""
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.02, # Set to align with expected 1-3% anomaly rate
            random_state=42
        )

    def fit(self, X):
        """Fit Isolation Forest strictly on baseline normal behavior features."""
        self.model.fit(X)

    def predict(self, X):
        """
        Predict outlier status.
        Returns:
            1 for Normal, -1 for Anomaly.
        """
        return self.model.predict(X)

    def score_samples(self, X):
        """
        Calculate anomaly score.
        Returns:
            Scores normalized between 0.0 (perfectly normal) and 1.0 (highly anomalous).
        """
        raw_scores = self.model.score_samples(X)
        # Shift and scale raw scores (typically in range [-0.8, -0.3]) to [0, 1] range
        min_val, max_val = -0.8, -0.3
        scores_normalized = (raw_scores - min_val) / (max_val - min_val)
        return np.clip(1.0 - scores_normalized, 0.0, 1.0)

    def evaluate_instance(self, X) -> dict:
        """
        Evaluates a single feature row or multiple rows.
        Generates: Prediction, Anomaly Score, and Confidence.
        """
        pred = self.predict(X)
        scores = self.score_samples(X)
        
        # Raw distance to decision boundary
        raw_decisions = self.model.decision_function(X)
        
        # Confidence is calculated as the absolute distance from the decision boundary
        # scaled to [0, 1] interval. Values closer to boundary have lower confidence.
        confidences = np.clip(np.abs(raw_decisions) / 0.5, 0.0, 1.0)
        
        return {
            "prediction": ["Normal" if p == 1 else "Anomaly" for p in pred],
            "anomaly_score": [float(s) for s in scores],
            "confidence": [float(c) for c in confidences]
        }
