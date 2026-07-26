"""
Behaviour Classification Engine.
Aggregates unsupervised scores, multi-class predictions, feature attributions,
and security contexts to output complete structured threat diagnostics.
"""
import numpy as np
import pandas as pd
from typing import Dict, Any
from config.settings import Settings
from models.risk_scorer import ExplainableRiskEngine

SEVERITY_MAPPING = {
    "Normal": "Low",
    "Brute Force": "High",
    "Credential Stuffing": "High",
    "Impossible Travel": "High",
    "Lateral Movement": "Critical",
    "Device Spoofing": "Medium",
    "Low-and-Slow Exfiltration": "Critical",
    "Insider Drift": "Medium"
}

class BehaviourClassifierEngine:
    """Wrapper that classifies access anomalies and returns comprehensive evidence payloads."""
    def __init__(self, classifier_model, explainer_model):
        self.classifier = classifier_model
        self.explainer = explainer_model
        self.risk_engine = ExplainableRiskEngine()
        self.settings = Settings()

    def classify_behavior(self, raw_event: dict, features_row: pd.DataFrame, iforest_score: float) -> Dict[str, Any]:
        """
        Classifies incoming behavior telemetry and packages attributions, severity, and evidence.
        """
        # Predict class label & probabilities
        probs = self.classifier.predict_proba(features_row)[0]
        predicted_idx = np.argmax(probs)
        predicted_class = self.classifier.classes_[predicted_idx]
        confidence = float(probs[predicted_idx])
        
        # Calibration layer to reduce false positives:
        # If the model predicts an attack class, but confidence is low (< 75%),
        # default classification back to "Normal" to maintain low false positive rates.
        if predicted_class != "Normal" and confidence < 0.75:
            predicted_class = "Normal"
            confidence = float(probs[self.classifier.classes_.index("Normal")])

        # Evaluate complete explainable risk package
        feat_dict = features_row.to_dict(orient="records")[0]
        risk_payload = self.risk_engine.evaluate_risk(
            features_row=feat_dict,
            attack_type=predicted_class,
            confidence=confidence,
            iforest_score=iforest_score
        )

        return {
            "attack_type": predicted_class,
            "severity": risk_payload["risk_level"],
            "confidence": confidence,
            "reason": risk_payload["soc_explanation"],
            "evidence": risk_payload["evidence"],
            "business_impact": risk_payload["business_impact"],
            "recommended_action": risk_payload["recommended_action"]
        }
