"""
Explainable Enterprise Risk Scorer Engine.
Computes multi-dimensional risk scores (0-100) and compiles structured
diagnostics, business impacts, recommended SOC actions, and natural explanations.
"""
import numpy as np
from typing import Dict, Any
from config.settings import Settings

BUSINESS_IMPACT_MAP = {
    "Normal": "No operational impact detected. Event conforms to established baseline parameters.",
    "Brute Force": "Potential account takeover attempt risking unauthorized database access, user impersonation, and service lockouts.",
    "Credential Stuffing": "Automated credential stuffing targeting bulk user accounts risking systemic service disruption and mass account compromise.",
    "Impossible Travel": "Session hijacking or credential sharing indicating access from two separate geographic locations within a physically impossible timeframe.",
    "Lateral Movement": "Internal threat actor or compromised host performing internal reconnaissance to access sensitive corporate repositories.",
    "Device Spoofing": "Impersonation of trusted device parameters to bypass endpoint authentication filters and access networks.",
    "Low-and-Slow Exfiltration": "Stealthy data exfiltration of internal databases risking severe intellectual property leakage and compliance violations.",
    "Insider Drift": "Privileged user baseline drift indicating potential rogue employee activity or slow-burn credential compromise."
}

RECOMMENDED_ACTION_MAP = {
    "Normal": "No action required. Continue standard logging.",
    "Brute Force": "Temporarily lock the account, terminate all active sessions immediately, and force a password reset + MFA re-enrollment.",
    "Credential Stuffing": "Enable CAPTCHA/rate-limiting on authentication endpoints, block source IP in the WAF, and notify target users.",
    "Impossible Travel": "Revoke active SSO token, terminate active sessions immediately, and contact the user to verify travel status.",
    "Lateral Movement": "Isolate the source host/device in the endpoint manager (EDR), restrict internal service ports, and audit directory permissions.",
    "Device Spoofing": "Reject current MAC session, flag device certificate status, and initiate endpoint compliance health check.",
    "Low-and-Slow Exfiltration": "Block outbound transfer routes to destination IP, isolate targeted storage repository, and initiate full forensic audit.",
    "Insider Drift": "Alert security operations management, restrict administrative access privileges, and review recent activity with department supervisor."
}

class ExplainableRiskEngine:
    """Enterprise risk scoring framework incorporating security heuristics and confidence metrics."""
    def __init__(self):
        self.settings = Settings()

    def evaluate_risk(self, features_row: Dict[str, Any], attack_type: str, confidence: float, iforest_score: float) -> Dict[str, Any]:
        """
        Evaluate and return comprehensive risk diagnostics.
        """
        # 1. Calculate risk score (0-100) based on confidence, iforest, and sensitivity
        res_sensitivity = features_row.get("resource_sensitivity", 2.0)
        
        # Base ML probability contribution
        ml_contrib = (1.0 - confidence) * 100.0 if attack_type == "Normal" else confidence * 100.0
        
        # Base severity heuristic
        severity_val = 0.0
        if attack_type in ["Brute Force", "Credential Stuffing", "Impossible Travel", "Device Spoofing"]:
            severity_val = 70.0
        elif attack_type in ["Lateral Movement", "Low-and-Slow Exfiltration"]:
            severity_val = 90.0
        elif attack_type == "Insider Drift":
            severity_val = 50.0
            
        # Resource sensitivity contribution (scale 1-5 to 0-100)
        sensitivity_contrib = ((res_sensitivity - 1.0) / 4.0) * 100.0
        
        # Aggregate base score
        base_score = (self.settings.ALPHA * ml_contrib) + (self.settings.BETA * severity_val) + (self.settings.GAMMA * sensitivity_contrib)
        
        # Modulate by Isolation Forest outlier score
        final_score = (base_score * 0.8) + (iforest_score * 100.0 * 0.2)
        risk_score = float(np.clip(final_score, 0.0, 100.0) if 'np' in globals() else min(max(final_score, 0.0), 100.0))
        
        # 2. Assign Risk Level
        if risk_score >= 80.0:
            risk_level = "Critical"
        elif risk_score >= 60.0:
            risk_level = "High"
        elif risk_score >= 35.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # 3. Construct Evidence
        evidence = {
            "time_diff_sec": features_row.get("time_difference_sec", 3600.0),
            "login_velocity_kmh": features_row.get("login_velocity_kmh", 0.0),
            "rolling_failed_logins_1h": features_row.get("rolling_failed_logins_1h", 0),
            "resource_entropy_1h": features_row.get("resource_entropy_1h", 1.0),
            "device_novelty": features_row.get("device_novelty", 0),
            "country_change": features_row.get("country_change", 0),
            "download_behaviour": features_row.get("download_behaviour", 0),
            "command_sequence_novelty": features_row.get("command_sequence_novelty", 0),
            "resource_sensitivity": res_sensitivity,
            "isolation_forest_score": iforest_score,
            "classification_confidence": confidence
        }

        # 4. Generate SOC Explanation
        explanations = []
        if evidence["rolling_failed_logins_1h"] >= 3:
            explanations.append(f"{evidence['rolling_failed_logins_1h']} login failures occurred in the past hour")
        if evidence["login_velocity_kmh"] > 50.0:
            explanations.append(f"Login locations changed at an impossible speed of {evidence['login_velocity_kmh']:.1f} km/h")
        if evidence["device_novelty"] == 1:
            explanations.append("The device fingerprint/browser differs from historical baseline")
        if evidence["country_change"] == 1:
            explanations.append("The country of access has changed from the previous event")
        if evidence["download_behaviour"] == 1:
            explanations.append("Access targeted a secure data vault or initiated download commands")
        if evidence["command_sequence_novelty"] == 1:
            explanations.append("An anomalous/unseen sequence of command scripts was executed")
        if evidence["resource_sensitivity"] >= 4.0:
            explanations.append(f"Access targeted highly sensitive asset (sensitivity rating: {evidence['resource_sensitivity']:.1f})")
            
        soc_explanation = f"Alert generated because: {'; '.join(explanations)}." if explanations else "Alert generated due to cumulative anomaly deviations from behavior baseline."

        return {
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "evidence": evidence,
            "business_impact": BUSINESS_IMPACT_MAP.get(attack_type, "Unknown risk impact."),
            "recommended_action": RECOMMENDED_ACTION_MAP.get(attack_type, "Investigate log anomalies immediately."),
            "soc_explanation": soc_explanation
        }
