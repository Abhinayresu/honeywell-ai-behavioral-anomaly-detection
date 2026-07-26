"""
Dataset Builder & Sequential Feature Engineering.
Implements chronological, history-aware feature engineering using historical
entity profiles instead of static snapshots.

Engineered Features Documentation:
----------------------------------
1. time_difference_sec: Time delta (seconds) since the entity's immediately preceding login event.
2. login_velocity_kmh: Speed (km/h) between consecutive logins computed using great-circle distance.
3. country_change: Binary (1/0) indicating if current country differs from the previous event's country.
4. device_novelty: Binary (1/0) indicating if User-Agent or MAC differs from typical baseline.
5. rolling_failed_logins_1h: Rolling sum of failed login attempts for this entity in the last 1 hour.
6. resource_entropy_1h: Ratio of unique resources to total accesses in the last 1 hour (Lateral Movement indicator).
7. historical_session_average: Entity's historic mean session duration prior to the current event.
8. command_sequence_novelty: Binary (1/0) indicating if command string is unseen in the baseline profile.
9. download_behaviour: Binary (1/0) indicating file download activity or database vault queries.
10. resource_sensitivity: Criticality rating (1.0 to 5.0) of the target system resource.
11. behaviour_deviation_score: A composite metric aggregating time, location, device, and scope deviations.
"""
import json
from datetime import timedelta
import numpy as np
import pandas as pd
from models.profiling_engine import BehaviourProfiler

ASSET_CRITICALITY = {
    "public_dashboard": 1.0,
    "user_inbox": 2.0,
    "internal_wiki": 2.0,
    "code_repository": 3.5,
    "hr_database": 4.0,
    "billing_gateway": 4.5,
    "admin_console": 5.0
}

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance in kilometers between two coordinates."""
    r = 6371.0
    lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat / 2.0)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2.0)**2
    c = 2.0 * np.arcsin(np.sqrt(a))
    return r * c

class AnomalyDatasetBuilder:
    """Computes history-aware sequential features chronologically for ML ingestion."""
    def __init__(self):
        self.profiler = BehaviourProfiler()

    def build_features(self, df_logs: pd.DataFrame, fit_profiler: bool = True) -> pd.DataFrame:
        """
        Builds ML-ready tabular feature vectors incorporating entity baselines and event history.
        """
        df = df_logs.copy()
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values(by=["entity_id", "timestamp_dt"]).reset_index(drop=True)
        
        if fit_profiler:
            self.profiler.learn_profiles_from_logs(df)
            
        features_list = []
        
        # Track dynamic session history per entity during processing loop
        history_tracker = {}
        
        for row in df.itertuples():
            entity_id = row.entity_id
            profile = self.profiler.get_profile(entity_id)
            
            # Unpack geo coords
            try:
                geo = json.loads(row.geo_location)
                lat, lon = geo.get("lat", 0.0), geo.get("lon", 0.0)
                country = geo.get("country", "Unknown")
            except (json.JSONDecodeError, TypeError):
                lat, lon = 0.0, 0.0
                country = "Unknown"
                
            # Initialize entity tracker if unseen
            if entity_id not in history_tracker:
                history_tracker[entity_id] = {
                    "prev_timestamp": None,
                    "prev_lat": None,
                    "prev_lon": None,
                    "prev_country": None,
                    "session_durations": [],
                    "past_events": []
                }
                
            tracker = history_tracker[entity_id]
            
            # --- 1. Previous Login & Time Difference ---
            time_diff = 3600.0  # default fallback
            if tracker["prev_timestamp"] is not None:
                time_diff = (row.timestamp_dt - tracker["prev_timestamp"]).total_seconds()
                
            # --- 2. Login Velocity (Speed) & Country Change ---
            velocity = 0.0
            country_change = 0
            if tracker["prev_lat"] is not None:
                dist = haversine_distance(lat, lon, tracker["prev_lat"], tracker["prev_lon"])
                if time_diff > 0:
                    velocity = dist / (time_diff / 3600.0)
                if country != tracker["prev_country"]:
                    country_change = 1
                    
            # --- 3. Device Novelty ---
            device_novelty = 0
            if profile:
                typical_ua = list(profile["preferred_devices"].keys())
                if typical_ua and row.device_fingerprint not in typical_ua:
                    device_novelty = 1
                    
            # --- 4. Rolling Failed Logins (1 hour window) ---
            # Append current event to sliding window tracker
            tracker["past_events"].append({
                "time": row.timestamp_dt,
                "status": row.auth_method,
                "resource": row.resource_accessed,
                "command": row.command_sequence,
                "duration": row.session_duration
            })
            # Clean window
            cutoff = row.timestamp_dt - timedelta(hours=1)
            tracker["past_events"] = [e for e in tracker["past_events"] if e["time"] >= cutoff]
            
            # Count failed logins in the window (duration = 0.0, command contains login)
            failed_logins = sum(1 for e in tracker["past_events"] if "login" in e["command"].lower() and e["duration"] == 0.0)
                
            # --- 5. Resource Entropy (diversity of resources in 1 hour) ---
            recent_resources = [e["resource"] for e in tracker["past_events"]]
            unique_res = len(set(recent_resources))
            total_res = len(recent_resources)
            resource_entropy = unique_res / total_res if total_res > 0 else 1.0
            
            # --- 6. Historical Session Average ---
            hist_sessions = tracker["session_durations"]
            session_avg = np.mean(hist_sessions) if hist_sessions else 300.0
            # Store current session duration in history
            tracker["session_durations"].append(row.session_duration)
            
            # --- 7. Command Sequence Novelty ---
            cmd_novelty = 0
            if profile:
                if row.command_sequence not in profile["frequent_commands"]:
                    cmd_novelty = 1
                    
            # --- 8. Download Behaviour ---
            download_behaviour = 0
            if "download" in row.command_sequence.lower() or row.resource_accessed == "backup_vault":
                download_behaviour = 1
                
            # --- 9. Resource Sensitivity ---
            res_sensitivity = ASSET_CRITICALITY.get(row.resource_accessed, 2.0)
            
            # --- 10. Behaviour Deviation Score ---
            # Composite sum of deviations
            dev_score = int(time_diff < 300.0) * 0.2 + velocity / 1000.0 * 0.3 + country_change * 0.2 + device_novelty * 0.3
            
            features_list.append({
                "time_difference_sec": float(time_diff),
                "login_velocity_kmh": float(velocity),
                "country_change": int(country_change),
                "device_novelty": int(device_novelty),
                "rolling_failed_logins_1h": int(failed_logins),
                "resource_entropy_1h": float(resource_entropy),
                "historical_session_average": float(session_avg),
                "command_sequence_novelty": int(cmd_novelty),
                "download_behaviour": int(download_behaviour),
                "resource_sensitivity": float(res_sensitivity),
                "behaviour_deviation_score": float(np.clip(dev_score, 0.0, 1.0))
            })
            
            # Update tracker state for next iteration
            tracker["prev_timestamp"] = row.timestamp_dt
            tracker["prev_lat"] = lat
            tracker["prev_lon"] = lon
            tracker["prev_country"] = country
            
        return pd.DataFrame(features_list)
