"""
Model Evaluation and Metrics Reporting.
Evaluates model accuracy, false positives, classification reports, and outputs scores.
"""
import joblib
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from config.settings import Settings

class ModelEvaluator:
    """Computes operational metrics to validate detection rates and false positive rates."""
    def __init__(self):
        self.settings = Settings()
        
    def evaluate(self):
        """Loads serialized models, loads test set, and reports performance."""
        iforest_path = self.settings.MODELS_STORE / "isolation_forest.joblib"
        classifier_path = self.settings.MODELS_STORE / "xgb_classifier.joblib"
        builder_path = self.settings.DATA_DIR / "dataset_builder.joblib"
        
        try:
            anomaly_detector = joblib.load(iforest_path)
            classifier = joblib.load(classifier_path)
            dataset_builder = joblib.load(builder_path)
        except FileNotFoundError as e:
            print(f"Error loading models: {e}. Please run ml/train.py first.")
            return

        print("1. Loading test dataset and aligning timestamps...")
        try:
            df_test = pd.read_csv(self.settings.DATA_DIR / "test_logs.csv")
        except FileNotFoundError:
            print("Test logs not found. Please run ml/train.py first.")
            return
            
        df_test["timestamp_dt"] = pd.to_datetime(df_test["timestamp"])
        df_test = df_test.sort_values(by=["entity_id", "timestamp_dt"]).reset_index(drop=True)
        
        print("2. Extracting test features using Behaviour Profiler...")
        # Evaluate without refitting the profiler baseline (fit_profiler=False)
        X_test = dataset_builder.build_features(df_test, fit_profiler=False)
        y_test = df_test["label"]
        
        print("3. Executing predictions...")
        y_pred = classifier.predict(X_test)
        
        acc = accuracy_score(y_test, y_pred)
        print("\n=======================================================")
        print("                EVALUATION METRICS REPORT              ")
        print("=======================================================")
        print(f"Classification Accuracy: {acc * 100.0:.2f}%")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        # Calculate False Positive Rate and False Negative Rate for cybersecurity context
        cm = confusion_matrix(y_test, y_pred, labels=classifier.classes_)
        try:
            normal_idx = classifier.classes_.index("Normal")
            actual_normal = sum(cm[normal_idx, :])
            fp = actual_normal - cm[normal_idx, normal_idx]
            actual_attacks = cm.sum() - actual_normal
            fn = sum(cm[:, normal_idx]) - cm[normal_idx, normal_idx]
            
            fpr = fp / actual_normal if actual_normal > 0 else 0.0
            fnr = fn / actual_attacks if actual_attacks > 0 else 0.0
            print(f"False Positive Rate (FPR) (Normal flagged as Attack): {fpr * 100.0:.3f}%")
            print(f"False Negative Rate (FNR) (Missed threats): {fnr * 100.0:.3f}%")
        except ValueError:
            print("Normal class not found in classifier classes.")
            
        print("=======================================================")

if __name__ == "__main__":
    evaluator = ModelEvaluator()
    evaluator.evaluate()
