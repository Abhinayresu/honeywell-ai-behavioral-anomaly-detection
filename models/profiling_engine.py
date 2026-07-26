"""
Behaviour Profiling Engine with Cold Start & Concept Drift Handling.
Learns baseline profiles, implements department/entity peer-group fallbacks,
and dynamically adapts baselines to evolving normal behaviors via EMA updates.
"""
import json
import numpy as np
import pandas as pd
from typing import Dict, Any

class BehaviourProfiler:
    """Computes, stores, and adapts behavioral baseline profiles for entities."""
    def __init__(self):
        self.profiles = {}
        self.peer_profiles = {}  # Fallbacks for Cold Start (department & type baselines)

    def learn_profiles_from_logs(self, df_logs: pd.DataFrame):
        """
        Processes historical logs to compile baseline profiles and peer-group parameters.
        """
        df = df_logs.copy()
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"])
        df["hour"] = df["timestamp_dt"].dt.hour
        
        # Filter for normal logs only to build clean baselines
        df_normal = df[df["label"] == "Normal"]
        
        # 1. Compute Entity-Level Profiles
        grouped = df_normal.groupby("entity_id")
        for entity_id, group in grouped:
            self._build_single_profile(entity_id, group)
            
        # 2. Compute Peer-Group Baseline Profiles (Department + Entity Type)
        # Used for Cold Start mitigation
        df_normal["department"] = df_normal["entity_id"].apply(lambda x: x.split("_")[0] if "_" in x else "General")
        peer_grouped = df_normal.groupby(["entity_type", "department"])
        for (ent_type, dept), group in peer_grouped:
            peer_key = f"{ent_type}_{dept}"
            hours = group["hour"].tolist()
            mean_hour = float(np.mean(hours)) if hours else 12.0
            std_hour = float(np.std(hours)) if hours else 2.0
            durations = group["session_duration"].dropna().tolist()
            mean_dur = float(np.mean(durations)) if durations else 300.0
            std_dur = float(np.std(durations)) if durations else 60.0
            
            self.peer_profiles[peer_key] = {
                "typical_hour_mean": mean_hour,
                "typical_hour_std": std_hour,
                "working_hours_range": (int(max(0, mean_hour - 2 * std_hour)), int(min(23, mean_hour + 2 * std_hour))),
                "session_duration_stats": (mean_dur, std_dur),
                "allowed_resources": group["resource_accessed"].unique().tolist(),
                "trusted_countries": group["geo_location"].apply(lambda x: json.loads(x).get("country") if isinstance(x, str) else "US").value_counts(normalize=True).to_dict()
            }

    def _build_single_profile(self, entity_id: str, group: pd.DataFrame):
        """Construct a single baseline profile dict."""
        hours = group["hour"].tolist()
        mean_hour = float(np.mean(hours)) if hours else 12.0
        std_hour = float(np.std(hours)) if hours else 2.0
        
        devices = group["device_fingerprint"].value_counts(normalize=True).to_dict()
        ips = group["source_ip"].value_counts(normalize=True).to_dict()
        
        countries = []
        for geo_str in group["geo_location"]:
            try:
                geo = json.loads(geo_str) if isinstance(geo_str, str) else geo_str
                countries.append(geo.get("country"))
            except (json.JSONDecodeError, TypeError):
                pass
        countries_pct = pd.Series(countries).value_counts(normalize=True).to_dict() if countries else {}
        
        resources = group["resource_accessed"].value_counts(normalize=True).to_dict()
        durations = group["session_duration"].dropna().tolist()
        mean_dur = float(np.mean(durations)) if durations else 300.0
        std_dur = float(np.std(durations)) if durations else 60.0
        
        commands = group["command_sequence"].dropna().unique().tolist()

        self.profiles[entity_id] = {
            "entity_id": entity_id,
            "entity_type": group["entity_type"].iloc[0],
            "department": entity_id.split("_")[0] if "_" in entity_id else "General",
            "history_count": len(group),
            "typical_hour_mean": mean_hour,
            "typical_hour_std": std_hour,
            "working_hours_range": (int(max(0, mean_hour - 2 * std_hour)), int(min(23, mean_hour + 2 * std_hour))),
            "preferred_devices": devices,
            "trusted_ips": ips,
            "trusted_countries": countries_pct,
            "resource_usage": resources,
            "session_duration_stats": (mean_dur, std_dur),
            "frequent_commands": commands
        }

    def get_profile(self, entity_id: str, entity_type: str = "User") -> Dict[str, Any]:
        """
        Retrieve baseline profile. Falls back to peer-group profile (Cold Start) if history count is low.
        """
        profile = self.profiles.get(entity_id)
        
        # Cold Start fallback check
        if not profile or profile.get("history_count", 0) < 5:
            dept = entity_id.split("_")[0] if "_" in entity_id else "General"
            peer_key = f"{entity_type}_{dept}"
            peer_profile = self.peer_profiles.get(peer_key, self.peer_profiles.get(f"{entity_type}_General"))
            
            if peer_profile:
                # Return virtual peer-group baseline profile
                return {
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                    "is_cold_start": True,
                    "typical_hour_mean": peer_profile["typical_hour_mean"],
                    "typical_hour_std": peer_profile["typical_hour_std"],
                    "working_hours_range": peer_profile["working_hours_range"],
                    "preferred_devices": {},
                    "trusted_ips": {},
                    "trusted_countries": peer_profile["trusted_countries"],
                    "resource_usage": {r: 1.0 / len(peer_profile["allowed_resources"]) for r in peer_profile["allowed_resources"]},
                    "session_duration_stats": peer_profile["session_duration_stats"],
                    "frequent_commands": []
                }
        return profile

    def update_profile_with_event(self, event: dict, risk_score: float):
        """
        Adapts baseline profiles to evolving normal behavior (Concept Drift mitigation).
        If the event is verified as normal (low risk), we merge it into the running profile stats.
        """
        entity_id = event["entity_id"]
        if risk_score > 35.0:
            # Do not update baseline with anomalous behaviors to prevent poison attacks
            return

        profile = self.profiles.get(entity_id)
        if not profile:
            # Initialize dynamic profile for new cold-start entity
            self.profiles[entity_id] = {
                "entity_id": entity_id,
                "entity_type": event["entity_type"],
                "department": entity_id.split("_")[0] if "_" in entity_id else "General",
                "history_count": 1,
                "typical_hour_mean": float(pd.to_datetime(event["timestamp"]).hour),
                "typical_hour_std": 2.0,
                "working_hours_range": (8, 18),
                "preferred_devices": {event["device_fingerprint"]: 1.0},
                "trusted_ips": {event["source_ip"]: 1.0},
                "trusted_countries": {},
                "resource_usage": {event["resource_accessed"]: 1.0},
                "session_duration_stats": (float(event["session_duration"]), 30.0),
                "frequent_commands": [event["command_sequence"]]
            }
            return

        # Increment history count
        profile["history_count"] += 1
        alpha = 0.05  # baseline adaptation learning rate (EMA)
        
        # 1. Update Typical Hour (cyclical mean adaptation)
        hour = float(pd.to_datetime(event["timestamp"]).hour)
        profile["typical_hour_mean"] = (1 - alpha) * profile["typical_hour_mean"] + alpha * hour
        
        # 2. Update Session Duration stats
        dur = float(event["session_duration"])
        mean_dur, std_dur = profile["session_duration_stats"]
        new_mean = (1 - alpha) * mean_dur + alpha * dur
        profile["session_duration_stats"] = (new_mean, std_dur)
        
        # 3. Add to IP list with decayed historical counts
        ip = event["source_ip"]
        profile["trusted_ips"][ip] = profile["trusted_ips"].get(ip, 0.0) + 0.1
        # Re-normalize
        total_ip_w = sum(profile["trusted_ips"].values())
        profile["trusted_ips"] = {k: v / total_ip_w for k, v in profile["trusted_ips"].items()}
        
        # 4. Add browser device
        dev = event["device_fingerprint"]
        profile["preferred_devices"][dev] = profile["preferred_devices"].get(dev, 0.0) + 0.1
        total_dev_w = sum(profile["preferred_devices"].values())
        profile["preferred_devices"] = {k: v / total_dev_w for k, v in profile["preferred_devices"].items()}

    def calculate_deviation(self, event: dict) -> dict:
        """
        Quantifies deviation from the entity profile (incorporates cold-start fallbacks).
        """
        entity_id = event["entity_id"]
        profile = self.get_profile(entity_id, event["entity_type"])
        
        if not profile:
            return {
                "time_deviation": 0.5,
                "device_deviation": 0.5,
                "ip_deviation": 0.5,
                "country_deviation": 0.5,
                "resource_deviation": 0.5,
                "duration_deviation": 0.5,
                "is_cold_start": 1
            }
            
        dt = pd.to_datetime(event["timestamp"])
        hour = dt.hour
        
        # 1. Time deviation
        mean_h = profile["typical_hour_mean"]
        std_h = profile["typical_hour_std"] if profile["typical_hour_std"] > 0 else 1.0
        time_dev = min(2.0, abs(hour - mean_h) / std_h) / 2.0
        
        # 2. Device novelty
        device = event["device_fingerprint"]
        dev_prob = profile["preferred_devices"].get(device, 0.0)
        device_dev = 1.0 - dev_prob
        
        # 3. IP novelty
        ip = event["source_ip"]
        ip_prob = profile["trusted_ips"].get(ip, 0.0)
        ip_dev = 1.0 - ip_prob
        
        # 4. Country novelty
        try:
            geo = json.loads(event["geo_location"]) if isinstance(event["geo_location"], str) else event["geo_location"]
            country = geo.get("country")
        except (json.JSONDecodeError, TypeError):
            country = "Unknown"
        country_prob = profile["trusted_countries"].get(country, 0.0)
        country_dev = 1.0 - country_prob
        
        # 5. Resource novelty
        res = event["resource_accessed"]
        res_prob = profile["resource_usage"].get(res, 0.0)
        res_dev = 1.0 - res_prob
        
        # 6. Session duration deviation
        dur = event["session_duration"]
        mean_dur, std_dur = profile["session_duration_stats"]
        std_dur = std_dur if std_dur > 0 else 30.0
        dur_dev = min(3.0, abs(dur - mean_dur) / std_dur) / 3.0
        
        return {
            "time_deviation": float(time_dev),
            "device_deviation": float(device_dev),
            "ip_deviation": float(ip_dev),
            "country_deviation": float(country_dev),
            "resource_deviation": float(res_dev),
            "duration_deviation": float(dur_dev),
            "is_cold_start": 1 if profile.get("is_cold_start", False) else 0
        }
