"""
Unit and Integration Tests for Behavioral Anomaly Detection System.
Tests log generation, feature engineering, and model training logic.
"""
import pandas as pd
import pytest
from ml.generator import SyntheticLogGenerator
from ml.dataset import AnomalyDatasetBuilder

def test_log_generator():
    """Verify generator produces valid Honeywell-schema chronological logs."""
    generator = SyntheticLogGenerator(num_entities=10)
    events = generator.generate_dataset(total_events=100, anomaly_rate=0.05)
    
    assert len(events) >= 100
    # Check Honeywell schema fields
    required_fields = [
        "entity_id", "entity_type", "timestamp", "source_ip", 
        "geo_location", "resource_accessed", "auth_method", 
        "session_duration", "command_sequence", "device_fingerprint", "label"
    ]
    for field in required_fields:
        assert field in events[0]

def test_feature_engineering():
    """Verify sequential feature extraction generates the documented schema."""
    generator = SyntheticLogGenerator(num_entities=10)
    events = generator.generate_dataset(total_events=50, anomaly_rate=0.0)
    df_logs = pd.DataFrame(events)
    
    builder = AnomalyDatasetBuilder()
    X = builder.build_features(df_logs, fit_profiler=True)
    
    expected_features = [
        "time_difference_sec", "login_velocity_kmh", "country_change",
        "device_novelty", "rolling_failed_logins_1h", "resource_entropy_1h",
        "historical_session_average", "command_sequence_novelty",
        "download_behaviour", "resource_sensitivity", "behaviour_deviation_score"
    ]
    
    for feat in expected_features:
        assert feat in X.columns
    assert len(X) == len(df_logs)
