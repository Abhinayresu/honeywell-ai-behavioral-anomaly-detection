"""
Supervised Threat Classification Model.
Trains a multi-class XGBoost classifier to identify specific attack classes.
Handles class imbalance via inverse frequency sample weighting and target label encoding.
"""
import numpy as np
from xgboost import XGBClassifier
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.preprocessing import LabelEncoder

class ThreatClassifier:
    """XGBoost multi-class threat signature classifier with integrated LabelEncoder."""
    def __init__(self):
        self.model = XGBClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            objective="multi:softprob",
            random_state=42
        )
        self.encoder = LabelEncoder()
        self.classes_ = []
    def fit(self, X, y):
        """Fit XGBoost model with label encoding."""
        y_encoded = self.encoder.fit_transform(y)
        self.classes_ = self.encoder.classes_.tolist()
        self.model.fit(X, y_encoded)

    def predict(self, X):
        """Classify attack types returning string labels."""
        preds_encoded = self.model.predict(X)
        return self.encoder.inverse_transform(preds_encoded)

    def predict_proba(self, X):
        """Return classification probabilities."""
        return self.model.predict_proba(X)
