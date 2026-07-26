"""
Settings configuration class.
Defines paths, hyperparameters, and environment variables for the system.
"""
from pathlib import Path

class Settings:
    """System-wide configuration settings."""
    def __init__(self):
        self.BASE_DIR = Path(__file__).resolve().parent.parent
        self.DATA_DIR = self.BASE_DIR / "data"
        self.MODELS_STORE = self.BASE_DIR / "models"
        
        # Ensure base directories exist
        self.DATA_DIR.mkdir(exist_ok=True)
        self.MODELS_STORE.mkdir(exist_ok=True)
        
        # DB Configuration
        self.SQLITE_DB_PATH = str(self.DATA_DIR / "profiles.db")
        self.TINYDB_PATH = str(self.DATA_DIR / "logs.json")
        
        # Threat Classes
        self.ATTACK_CLASSES = [
            "Normal",
            "Credential Misuse",
            "Brute-force",
            "Lateral Movement",
            "Impossible Travel",
            "Device Spoofing"
        ]
        
        # Risk Weight settings
        self.ALPHA = 0.5
        self.BETA = 0.3
        self.GAMMA = 0.2
        
        # Drift configuration
        self.DRIFT_PSI_THRESHOLD = 0.25
        self.DRIFT_WINDOW_SIZE = 1000
