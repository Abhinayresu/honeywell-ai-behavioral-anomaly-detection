import random
from datetime import datetime, timedelta
from app.generator.profile_generator import UserProfileManager
from app.generator.threat_scenarios import (
    get_random_ip,
    simulate_brute_force,
    simulate_impossible_travel,
    simulate_device_spoofing,
    simulate_credential_misuse,
    simulate_lateral_movement
)

class LogSimulator:
    def __init__(self, num_users=50):
        self.profile_manager = UserProfileManager(num_users=num_users)
        self.users = list(self.profile_manager.profiles.keys())

    def generate_normal_event(self, username, current_time):
        profile = self.profile_manager.get_profile(username)
        
        # Determine if it's success or failure (normal users have low failure rate, e.g. 2%)
        status = "success" if random.random() > 0.02 else "failure"
        
        # Access hours: standard working hours +/- some random jitter
        work_start, work_end = profile["working_hours"]
        hour = random.randint(work_start, work_end - 1)
        event_time = current_time.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
        
        return {
            "timestamp": event_time.isoformat(),
            "username": username,
            "ip_address": get_random_ip(profile["home_ip_prefix"]),
            "user_agent": profile["device"]["ua"],
            "os": profile["device"]["os"],
            "browser": profile["device"]["browser"],
            "mac_address": profile["mac_address"],
            "resource_accessed": random.choice(profile["allowed_resources"]),
            "status": status,
            "label": "Normal"
        }

    def generate_dataset(self, num_days=14, anomaly_ratio=0.03):
        """
        Generates a historical dataset of normal and anomalous access logs.
        anomaly_ratio: fraction of log entries that are anomalous.
        """
        logs = []
        start_time = datetime.now() - timedelta(days=num_days)
        
        # Generate base normal logs first
        current_time = start_time
        for day in range(num_days):
            day_time = start_time + timedelta(days=day)
            for username in self.users:
                profile = self.profile_manager.get_profile(username)
                # Number of events per day based on avg rate
                num_events = int(random.gauss(profile["avg_request_rate"] * 8, 2))
                num_events = max(1, num_events)
                
                for _ in range(num_events):
                    logs.append(self.generate_normal_event(username, day_time))
                    
        # Sort chronologically
        logs.sort(key=lambda x: x["timestamp"])
        
        # Inject anomalies
        num_anomalies_to_inject = int(len(logs) * anomaly_ratio)
        anomalies = []
        anomaly_types = ["Brute-force", "Impossible Travel", "Device Spoofing", "Credential Misuse", "Lateral Movement"]
        
        for _ in range(num_anomalies_to_inject):
            username = random.choice(self.users)
            profile = self.profile_manager.get_profile(username)
            # Pick a random point in logs to inject
            idx = random.randint(0, len(logs) - 1)
            base_time = datetime.fromisoformat(logs[idx]["timestamp"])
            
            atk_type = random.choice(anomaly_types)
            if atk_type == "Brute-force":
                sim_events = simulate_brute_force(profile, base_time)
            elif atk_type == "Impossible Travel":
                sim_events = simulate_impossible_travel(profile, base_time)
            elif atk_type == "Device Spoofing":
                sim_events = simulate_device_spoofing(profile, base_time)
            elif atk_type == "Credential Misuse":
                sim_events = simulate_credential_misuse(profile, base_time)
            else: # Lateral Movement
                sim_events = simulate_lateral_movement(profile, base_time)
                
            anomalies.extend(sim_events)
            
        logs.extend(anomalies)
        logs.sort(key=lambda x: x["timestamp"])
        return logs
