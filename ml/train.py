"""
Offline Model Training Script.
Generates Honeywell-schema access logs, splits into train/test sets,
constructs behavioral profiles on train logs, and trains models.
"""
import joblib
import pandas as pd
from config.settings import Settings
from ml.generator import SyntheticLogGenerator
from ml.dataset import AnomalyDatasetBuilder
from models.anomaly_detector import ProfileAnomalyDetector
from models.classifier import ThreatClassifier

class ModelTrainer:
    """Orchestrates generation of dataset and training of threat models."""
    def __init__(self):
        self.settings = Settings()
        self.generator = SyntheticLogGenerator(num_entities=500)
        self.dataset_builder = AnomalyDatasetBuilder()
        self.anomaly_detector = ProfileAnomalyDetector()
        self.classifier = ThreatClassifier()

    def run_training(self):
        """Builds dataset, trains and serializes model assets."""
        print("1. Generating 25,000+ access logs across 500+ entities...")
        # Ingest 27,000 events to ensure abundant training and testing data
        raw_logs = self.generator.generate_dataset(total_events=27000, anomaly_rate=0.02)
        df_logs = pd.DataFrame(raw_logs)
        df_logs["timestamp_dt"] = pd.to_datetime(df_logs["timestamp"])
        df_logs = df_logs.sort_values(by=["entity_id", "timestamp_dt"]).reset_index(drop=True)
        
        # Save raw logs for dashboard historical analytics
        logs_path = self.settings.DATA_DIR / "access_logs.csv"
        df_logs.to_csv(logs_path, index=False)
        print(f"   Saved raw logs to {logs_path}")
        
        # Train/Test Split (80/20 per entity chronologically)
        train_dfs = []
        test_dfs = []
        for entity_id, group in df_logs.groupby("entity_id"):
            split_idx = int(len(group) * 0.8)
            train_dfs.append(group.iloc[:split_idx])
            test_dfs.append(group.iloc[split_idx:])
            
        df_train = pd.concat(train_dfs).sort_values(by=["entity_id", "timestamp_dt"]).reset_index(drop=True)
        df_test = pd.concat(test_dfs).sort_values(by=["entity_id", "timestamp_dt"]).reset_index(drop=True)
        
        # Save test logs separately for evaluate script
        df_test.to_csv(self.settings.DATA_DIR / "test_logs.csv", index=False)
        
        print("2. Fitting Behaviour Profiler and extracting training features...")
        # Fit profiler only on training set
        X_train = self.dataset_builder.build_features(df_train, fit_profiler=True)
        y_train = df_train["label"]
        
        X_train.to_csv(self.settings.DATA_DIR / "training_features.csv", index=False)
        
        print("3. Fitting unsupervised Isolation Forest baseline...")
        normal_idx = (y_train == "Normal")
        X_train_normal = X_train[normal_idx]
        self.anomaly_detector.fit(X_train_normal)
        
        # Save Isolation Forest
        iforest_path = self.settings.MODELS_STORE / "isolation_forest.joblib"
        joblib.dump(self.anomaly_detector, iforest_path)
        print(f"   Saved Isolation Forest to {iforest_path}")
        
        print("4. Training cost-sensitive multi-class XGBoost classifier...")
        self.classifier.fit(X_train, y_train)
        
        # Save Classifier
        classifier_path = self.settings.MODELS_STORE / "xgb_classifier.joblib"
        joblib.dump(self.classifier, classifier_path)
        print(f"   Saved Threat Classifier to {classifier_path}")
        
        # Save dataset builder containing profiles
        builder_path = self.settings.DATA_DIR / "dataset_builder.joblib"
        joblib.dump(self.dataset_builder, builder_path)
        print(f"   Saved Profiling Database and Builder to {builder_path}")
        print("Model training successfully completed!")

if __name__ == "__main__":
    trainer = ModelTrainer()
    trainer.run_training()
