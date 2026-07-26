"""
Model Explainability Engine.
Uses SHAP (SHapley Additive exPlanations) to provide feature-level attributions,
mapping mathematical scores to plain-English cybersecurity insights.
"""
import shap
import pandas as pd
import numpy as np

class AnomalyExplainer:
    """Computes SHAP values and translates them to human-readable explanations."""
    def __init__(self, classifier_model, training_features_df):
        self.model = classifier_model
        # Use a small sample of training data as the background dataset
        background_sample = training_features_df.sample(min(100, len(training_features_df)), random_state=42)
        # TreeExplainer expects the underlying XGBClassifier model, not our custom wrapper class
        underlying_model = getattr(classifier_model, "model", classifier_model)
        self.explainer = shap.TreeExplainer(underlying_model, background_sample)

    def explain_instance(self, feature_row: pd.DataFrame) -> dict:
        """
        Generate feature attributions and natural language explanations for a single log.
        """
        # Compute SHAP values
        shap_values = self.explainer.shap_values(feature_row)
        
        # In multi-class XGBoost, shap_values is a list of arrays (one per class), or a 3D array
        # We find the predicted class
        pred_probabilities = self.model.predict_proba(feature_row)[0]
        predicted_class_idx = np.argmax(pred_probabilities)
        
        # Extract SHAP array for the predicted class
        if isinstance(shap_values, list):
            class_shap = shap_values[predicted_class_idx][0]
        elif len(shap_values.shape) == 3:  # (num_samples, num_features, num_classes)
            class_shap = shap_values[0, :, predicted_class_idx]
        else:
            class_shap = shap_values[0]  # Fallback for binary / single output shape
            
        feature_names = feature_row.columns.tolist()
        attributions = dict(zip(feature_names, [float(v) for v in class_shap]))
        
        # Generate Natural Language summary based on top positive contributors
        positive_contributors = sorted(
            [(k, v) for k, v in attributions.items() if v > 0],
            key=lambda x: x[1],
            reverse=True
        )
        
        explanations = []
        for feat, val in positive_contributors[:3]:
            raw_val = feature_row[feat].values[0]
            if feat == "speed_kmh" and raw_val > 50:
                explanations.append(f"Physical velocity between logins was anomalous at {raw_val:.1f} km/h (Impossible Travel)")
            elif feat == "failed_logins_1h" and raw_val >= 3:
                explanations.append(f"Host registered {int(raw_val)} login failures in the past hour (Brute-Force pattern)")
            elif feat == "is_ua_novel" and raw_val == 1:
                explanations.append("Session originated from an unrecognized browser/OS profile")
            elif feat == "is_mac_novel" and raw_val == 1:
                explanations.append("Device network hardware signature (MAC hash) is completely novel for this user")
            elif feat == "is_off_hours" and raw_val == 1:
                explanations.append("Access request occurred outside standard working hours baseline")
            elif feat == "is_resource_novel" and raw_val == 1:
                explanations.append("User requested access to a resource outside their standard department scope")
            elif feat == "resource_entropy_1h" and raw_val < 0.5:
                explanations.append("Rapidly hopped between multiple distinct systems (Lateral Movement pattern)")

        if not explanations:
            explanations.append("Activity mostly matches normal profile. Elevated score due to cumulative baseline deviation.")
            
        return {
            "predicted_class_idx": int(predicted_class_idx),
            "attributions": attributions,
            "narrative_explanations": explanations
        }
