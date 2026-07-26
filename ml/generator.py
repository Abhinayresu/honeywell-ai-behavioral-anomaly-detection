"""
Synthetic Enterprise Access Log Generator.
Generates 500+ entities (Users, Service Accounts, Edge Devices) with distinct behavioral profiles
and produces 20,000+ chronological access events, injecting realistic attack scenarios.
"""
import csv
import json
import random
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

# Configuration & Mappings
ENTITY_TYPES = ["User", "Service Account", "Edge Device"]

AUTH_METHODS = {
    "User": ["MFA_Push", "MFA_TOTP", "Password", "SSO"],
    "Service Account": ["API_Key", "OAuth2_Token", "Client_Certificate"],
    "Edge Device": ["Mutual_TLS", "IPsec_Tunnel", "PSK_SSH"]
}

RESOURCES = {
    "User": ["user_inbox", "internal_wiki", "hr_database", "code_repository", "public_dashboard"],
    "Service Account": ["billing_gateway", "backup_vault", "telemetry_endpoint", "api_gateway"],
    "Edge Device": ["firmware_server", "sensor_stream_01", "gateway_config", "status_check"]
}

COUNTRIES = [
    {"country": "US", "lat": 37.7749, "lon": -122.4194},
    {"country": "GB", "lat": 51.5074, "lon": -0.1278},
    {"country": "IN", "lat": 12.9716, "lon": 77.5946},
    {"country": "JP", "lat": 35.6762, "lon": 139.6503},
    {"country": "DE", "lat": 52.5200, "lon": 13.4050},
    {"country": "AU", "lat": -33.8688, "lon": 151.2093}
]

COMMAND_TEMPLATES = {
    "User": ["GET /index", "POST /login", "GET /profile", "GET /wiki/view", "POST /repo/commit"],
    "Service Account": ["PUT /data/sync", "GET /api/v1/metrics", "POST /billing/invoice", "DELETE /cache/purge"],
    "Edge Device": ["POST /telemetry", "GET /config/update", "POST /heartbeat", "PUT /status"]
}

def generate_ip_for_country(country_code):
    """Generate fake IP prefix mock values linked to standard regions."""
    if country_code == "US":
        return f"192.168.10.{random.randint(2, 254)}"
    elif country_code == "GB":
        return f"192.168.20.{random.randint(2, 254)}"
    elif country_code == "IN":
        return f"192.168.30.{random.randint(2, 254)}"
    elif country_code == "JP":
        return f"192.168.40.{random.randint(2, 254)}"
    elif country_code == "DE":
        return f"192.168.50.{random.randint(2, 254)}"
    else:
        return f"192.168.60.{random.randint(2, 254)}"

class EntityProfile:
    """Represents a behavioral baseline profile for a single entity."""
    def __init__(self, entity_id, entity_type):
        self.entity_id = entity_id
        self.entity_type = entity_type
        
        # Working hours baseline
        if entity_type == "Service Account":
            # Continuous 24/7 activity
            self.working_hours = (0, 24)
            self.activity_rate = random.uniform(10.0, 30.0) # events/hour
        elif entity_type == "Edge Device":
            self.working_hours = (0, 24)
            self.activity_rate = random.uniform(5.0, 15.0)
        else: # User
            # Normal business day
            start = random.choice([8, 9, 10])
            self.working_hours = (start, start + 8)
            self.activity_rate = random.uniform(1.0, 5.0)
            
        # Locations
        self.primary_location = random.choice(COUNTRIES)
        self.trusted_ips = [generate_ip_for_country(self.primary_location["country"]) for _ in range(2)]
        
        # Resources & Devices
        self.allowed_resources = RESOURCES[entity_type]
        self.auth_methods = AUTH_METHODS[entity_type]
        self.device_fingerprint = fake.user_agent() if entity_type == "User" else f"Agent_{entity_id}"
        
        # Session duration parameters (mean, std)
        if entity_type == "Service Account":
            self.session_dur_params = (5.0, 2.0)
        elif entity_type == "Edge Device":
            self.session_dur_params = (2.0, 0.5)
        else:
            self.session_dur_params = (1200.0, 300.0)

    def to_dict(self):
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "working_hours": list(self.working_hours),
            "primary_country": self.primary_location["country"],
            "primary_lat": self.primary_location["lat"],
            "primary_lon": self.primary_location["lon"],
            "trusted_ips": self.trusted_ips,
            "allowed_resources": self.allowed_resources,
            "auth_methods": self.auth_methods,
            "device_fingerprint": self.device_fingerprint,
            "session_dur_params": list(self.session_dur_params)
        }


class SyntheticLogGenerator:
    """Generates over 20,000 chronological events and injects attack scenarios."""
    def __init__(self, num_entities=500):
        self.entities = []
        self.profiles = {}
        self.num_entities = num_entities
        self._initialize_entities()

    def _initialize_entities(self):
        # Generate at least 500 entity profiles
        for i in range(self.num_entities):
            if i < 350:
                ent_type = "User"
                ent_id = f"user_{1000 + i}"
            elif i < 430:
                ent_type = "Service Account"
                ent_id = f"sa_{2000 + (i - 350)}"
            else:
                ent_type = "Edge Device"
                ent_id = f"dev_{3000 + (i - 430)}"
                
            prof = EntityProfile(ent_id, ent_type)
            self.entities.append(prof)
            self.profiles[ent_id] = prof

    def generate_normal_event(self, prof, current_time):
        """Generates a normal log entry satisfying the entity profile baseline."""
        ip = random.choice(prof.trusted_ips)
        res = random.choice(prof.allowed_resources)
        auth = random.choice(prof.auth_methods)
        
        # Hours variance
        start_h, end_h = prof.working_hours
        h = random.randint(start_h, end_h - 1) if end_h > start_h else random.randint(0, 23)
        event_time = current_time.replace(hour=h, minute=random.randint(0, 59), second=random.randint(0, 59))
        
        duration = max(1.0, random.normalvariate(prof.session_dur_params[0], prof.session_dur_params[1]))
        cmds = random.sample(COMMAND_TEMPLATES[prof.entity_type], k=random.randint(1, 3))
        
        return {
            "entity_id": prof.entity_id,
            "entity_type": prof.entity_type,
            "timestamp": event_time.isoformat(),
            "source_ip": ip,
            "geo_location": json.dumps({"country": prof.primary_location["country"], "lat": prof.primary_location["lat"], "lon": prof.primary_location["lon"]}),
            "resource_accessed": res,
            "auth_method": auth,
            "session_duration": round(duration, 1),
            "command_sequence": "; ".join(cmds),
            "device_fingerprint": prof.device_fingerprint,
            "label": "Normal"
        }

    def generate_dataset(self, total_events=22000, anomaly_rate=0.02):
        """Builds dataset and injects the specified range of anomalies (1-3%)."""
        events = []
        base_time = datetime.now() - timedelta(days=10)
        
        # Base event generation
        events_per_entity = total_events // len(self.entities)
        for prof in self.entities:
            for i in range(events_per_entity):
                day_offset = random.randint(0, 9)
                current_time = base_time + timedelta(days=day_offset)
                events.append(self.generate_normal_event(prof, current_time))
                
        # Sort chronologically
        events.sort(key=lambda x: x["timestamp"])
        
        # Inject anomalies
        num_anomalies = int(total_events * anomaly_rate)
        anomalies_injected = 0
        anomaly_types = [
            "Brute Force", "Credential Stuffing", "Impossible Travel",
            "Lateral Movement", "Device Spoofing", "Low-and-Slow Exfiltration",
            "Insider Drift"
        ]
        
        while anomalies_injected < num_anomalies:
            target_prof = random.choice(self.entities)
            # Find a location in timeline to inject
            idx = random.randint(0, len(events) - 1)
            time_anchor = datetime.fromisoformat(events[idx]["timestamp"])
            
            atk = random.choice(anomaly_types)
            
            if atk == "Brute Force":
                # High frequency failed login
                for i in range(8):
                    events.append({
                        "entity_id": target_prof.entity_id,
                        "entity_type": target_prof.entity_type,
                        "timestamp": (time_anchor + timedelta(seconds=i * 5)).isoformat(),
                        "source_ip": "198.51.100.42",
                        "geo_location": json.dumps({"country": "CN", "lat": 39.9042, "lon": 116.4074}),
                        "resource_accessed": random.choice(target_prof.allowed_resources),
                        "auth_method": "Password",
                        "session_duration": 0.0,
                        "command_sequence": "POST /login",
                        "device_fingerprint": "Hydra_Attacker_v1.0",
                        "label": "Brute Force"
                    })
                anomalies_injected += 1
                
            elif atk == "Credential Stuffing":
                # Random accounts getting fast sequential failures
                for i in range(5):
                    tmp_prof = random.choice(self.entities)
                    events.append({
                        "entity_id": tmp_prof.entity_id,
                        "entity_type": tmp_prof.entity_type,
                        "timestamp": (time_anchor + timedelta(seconds=i * 2)).isoformat(),
                        "source_ip": "203.0.113.12",
                        "geo_location": json.dumps({"country": "RU", "lat": 55.7558, "lon": 37.6173}),
                        "resource_accessed": "SSO",
                        "auth_method": "Password",
                        "session_duration": 0.0,
                        "command_sequence": "POST /login",
                        "device_fingerprint": "Botnet_Browser_8",
                        "label": "Credential Stuffing"
                    })
                anomalies_injected += 1
                
            elif atk == "Impossible Travel" and target_prof.entity_type == "User":
                # First normal login
                normal_ev = self.generate_normal_event(target_prof, time_anchor)
                events.append(normal_ev)
                
                # Second anomalous login in a different country 15 mins later
                dist_country = random.choice([c for c in COUNTRIES if c["country"] != target_prof.primary_location["country"]])
                events.append({
                    "entity_id": target_prof.entity_id,
                    "entity_type": target_prof.entity_type,
                    "timestamp": (time_anchor + timedelta(minutes=15)).isoformat(),
                    "source_ip": generate_ip_for_country(dist_country["country"]),
                    "geo_location": json.dumps(dist_country),
                    "resource_accessed": random.choice(target_prof.allowed_resources),
                    "auth_method": "SSO",
                    "session_duration": 300.0,
                    "command_sequence": "GET /dashboard",
                    "device_fingerprint": target_prof.device_fingerprint,
                    "label": "Impossible Travel"
                })
                anomalies_injected += 1
                
            elif atk == "Lateral Movement":
                # Accessing non-scoped resources rapidly
                all_res = ["billing_gateway", "backup_vault", "hr_database", "firmware_server", "admin_console"]
                unauthorized_res = [r for r in all_res if r not in target_prof.allowed_resources]
                if unauthorized_res:
                    for i, res in enumerate(unauthorized_res[:4]):
                        events.append({
                            "entity_id": target_prof.entity_id,
                            "entity_type": target_prof.entity_type,
                            "timestamp": (time_anchor + timedelta(minutes=i * 3)).isoformat(),
                            "source_ip": random.choice(target_prof.trusted_ips),
                            "geo_location": json.dumps({"country": target_prof.primary_location["country"], "lat": target_prof.primary_location["lat"], "lon": target_prof.primary_location["lon"]}),
                            "resource_accessed": res,
                            "auth_method": random.choice(target_prof.auth_methods),
                            "session_duration": 120.0,
                            "command_sequence": "GET /admin/stats; POST /execute",
                            "device_fingerprint": target_prof.device_fingerprint,
                            "label": "Lateral Movement"
                        })
                    anomalies_injected += 1
                    
            elif atk == "Device Spoofing":
                events.append({
                    "entity_id": target_prof.entity_id,
                    "entity_type": target_prof.entity_type,
                    "timestamp": time_anchor.isoformat(),
                    "source_ip": random.choice(target_prof.trusted_ips),
                    "geo_location": json.dumps({"country": target_prof.primary_location["country"], "lat": target_prof.primary_location["lat"], "lon": target_prof.primary_location["lon"]}),
                    "resource_accessed": random.choice(target_prof.allowed_resources),
                    "auth_method": random.choice(target_prof.auth_methods),
                    "session_duration": 45.0,
                    "command_sequence": "POST /telemetry",
                    "device_fingerprint": "Malicious_Spoofed_Agent_v2.0",
                    "label": "Device Spoofing"
                })
                anomalies_injected += 1
                
            elif atk == "Low-and-Slow Exfiltration":
                # Continuous, low volume data transfers off-hours
                for i in range(10):
                    events.append({
                        "entity_id": target_prof.entity_id,
                        "entity_type": target_prof.entity_type,
                        "timestamp": (time_anchor + timedelta(hours=i * 24)).isoformat(),
                        "source_ip": random.choice(target_prof.trusted_ips),
                        "geo_location": json.dumps({"country": target_prof.primary_location["country"], "lat": target_prof.primary_location["lat"], "lon": target_prof.primary_location["lon"]}),
                        "resource_accessed": "backup_vault",
                        "auth_method": "Password",
                        "session_duration": 5.0,
                        "command_sequence": "GET /archive/download",
                        "device_fingerprint": target_prof.device_fingerprint,
                        "label": "Low-and-Slow Exfiltration"
                    })
                anomalies_injected += 1
                
            elif atk == "Insider Drift":
                # Slowly changes activity pattern to off-hours and sensitive access
                drift_time = time_anchor
                for i in range(5):
                    drift_time += timedelta(days=1)
                    events.append({
                        "entity_id": target_prof.entity_id,
                        "entity_type": target_prof.entity_type,
                        "timestamp": drift_time.replace(hour=2).isoformat(), # Off hours
                        "source_ip": random.choice(target_prof.trusted_ips),
                        "geo_location": json.dumps({"country": target_prof.primary_location["country"], "lat": target_prof.primary_location["lat"], "lon": target_prof.primary_location["lon"]}),
                        "resource_accessed": "hr_database",
                        "auth_method": "Password",
                        "session_duration": 600.0,
                        "command_sequence": "GET /salaries/view",
                        "device_fingerprint": target_prof.device_fingerprint,
                        "label": "Insider Drift"
                    })
                anomalies_injected += 1

        events.sort(key=lambda x: x["timestamp"])
        return events
