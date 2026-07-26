import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models_store"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)

# Database Configuration
SQLITE_DB_PATH = str(DATA_DIR / "profiles.db")
TINYDB_PATH = str(DATA_DIR / "logs.json")

# Model Paths
XGB_MODEL_PATH = str(MODELS_DIR / "xgb_classifier.json")
IFOREST_MODEL_PATH = str(MODELS_DIR / "isolation_forest.joblib")
SCALER_PATH = str(MODELS_DIR / "scaler.joblib")

# Threat Config
ATTACK_CLASSES = [
    "Normal",
    "Credential Misuse",
    "Brute-force",
    "Lateral Movement",
    "Impossible Travel",
    "Device Spoofing"
]

# Risk Scoring Weights
ALPHA = 0.5   # ML Model Probability Weight
BETA = 0.3    # Anomaly/Attack Severity Heuristic Weight
GAMMA = 0.2   # Asset Criticality Weight

# Asset Criticality mapping
ASSET_CRITICALITY = {
    "public_dashboard": 1.0,
    "user_inbox": 2.0,
    "internal_wiki": 2.0,
    "code_repository": 3.5,
    "hr_database": 4.0,
    "billing_gateway": 4.5,
    "admin_console": 5.0
}

# Drift Configuration
DRIFT_PSI_THRESHOLD = 0.25
DRIFT_WINDOW_SIZE = 1000  # Number of events to check drift over
