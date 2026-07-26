import random
from datetime import datetime, timedelta
from app.generator.profile_generator import LOCATIONS, USER_AGENTS, RESOURCES_BY_DEPT

# Helper to generate random IP
def get_random_ip(prefix=None):
    if prefix:
        return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def simulate_brute_force(profile, base_time):
    # Generates a sequence of 5-12 failed attempts followed by 1 success, from a foreign IP
    events = []
    attacker_ip = get_random_ip() # Distinct from user home prefix
    attacker_ua = random.choice(USER_AGENTS)
    
    # Generate failures
    num_failures = random.randint(5, 12)
    current_time = base_time
    
    for _ in range(num_failures):
        current_time += timedelta(seconds=random.randint(2, 20))
        events.append({
            "timestamp": current_time.isoformat(),
            "username": profile["username"],
            "ip_address": attacker_ip,
            "user_agent": attacker_ua["ua"],
            "os": attacker_ua["os"],
            "browser": attacker_ua["browser"],
            "mac_address": f"00:50:56:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}",
            "resource_accessed": "admin_console",
            "status": "failure",
            "label": "Brute-force"
        })
        
    # Success event
    current_time += timedelta(seconds=random.randint(2, 5))
    events.append({
        "timestamp": current_time.isoformat(),
        "username": profile["username"],
        "ip_address": attacker_ip,
        "user_agent": attacker_ua["ua"],
        "os": attacker_ua["os"],
        "browser": attacker_ua["browser"],
        "mac_address": events[-1]["mac_address"],
        "resource_accessed": "admin_console",
        "status": "success",
        "label": "Brute-force"
    })
    
    return events

def simulate_impossible_travel(profile, base_time):
    # Generates 1 normal login at home, then another login from a distant location 10-30 mins later
    events = []
    
    # Event 1: Normal login at home
    home_loc = profile["home_location"]
    home_ip = get_random_ip(profile["home_ip_prefix"])
    
    events.append({
        "timestamp": base_time.isoformat(),
        "username": profile["username"],
        "ip_address": home_ip,
        "user_agent": profile["device"]["ua"],
        "os": profile["device"]["os"],
        "browser": profile["device"]["browser"],
        "mac_address": profile["mac_address"],
        "resource_accessed": random.choice(profile["allowed_resources"]),
        "status": "success",
        "label": "Normal" # First one is normal
    })
    
    # Choose a distant location
    distant_loc = random.choice([loc for loc in LOCATIONS if loc["city"] != home_loc["city"]])
    distant_ip = get_random_ip(distant_loc["ip_prefix"])
    
    # 10 to 30 mins later
    travel_time = timedelta(minutes=random.randint(10, 30))
    event2_time = base_time + travel_time
    
    events.append({
        "timestamp": event2_time.isoformat(),
        "username": profile["username"],
        "ip_address": distant_ip,
        "user_agent": profile["device"]["ua"],
        "os": profile["device"]["os"],
        "browser": profile["device"]["browser"],
        "mac_address": profile["mac_address"],
        "resource_accessed": random.choice(profile["allowed_resources"]),
        "status": "success",
        "label": "Impossible Travel" # Second one is anomalous
    })
    
    return events

def simulate_device_spoofing(profile, base_time):
    # Success login from the user's home location, but with an anomalous MAC and completely different User-Agent
    # Claiming to be the user
    spoofed_ua = random.choice([ua for ua in USER_AGENTS if ua["browser"] != profile["device"]["browser"]])
    spoofed_mac = f"00:0c:29:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}"
    
    return [{
        "timestamp": base_time.isoformat(),
        "username": profile["username"],
        "ip_address": get_random_ip(profile["home_ip_prefix"]),
        "user_agent": spoofed_ua["ua"],
        "os": spoofed_ua["os"],
        "browser": spoofed_ua["browser"],
        "mac_address": spoofed_mac,
        "resource_accessed": random.choice(profile["allowed_resources"]),
        "status": "success",
        "label": "Device Spoofing"
    }]

def simulate_credential_misuse(profile, base_time):
    # Access from an entirely foreign location, off-hours (e.g. 2 AM), accessing highly restricted resource
    foreign_loc = random.choice(LOCATIONS)
    foreign_ip = get_random_ip(foreign_loc["ip_prefix"])
    
    # Set time to off-hours (e.g., working_hours start - 5 hours)
    off_hour = (profile["working_hours"][0] - 5) % 24
    anomalous_time = base_time.replace(hour=off_hour, minute=random.randint(0, 59))
    
    # Restrict to sensitive resources outside of the department or high priority admin/billing
    sensitive_resource = "admin_console" if "admin_console" not in profile["allowed_resources"] else "hr_database"
    
    return [{
        "timestamp": anomalous_time.isoformat(),
        "username": profile["username"],
        "ip_address": foreign_ip,
        "user_agent": profile["device"]["ua"],
        "os": profile["device"]["os"],
        "browser": profile["device"]["browser"],
        "mac_address": profile["mac_address"],
        "resource_accessed": sensitive_resource,
        "status": "success",
        "label": "Credential Misuse"
    }]

def simulate_lateral_movement(profile, base_time):
    # Logs into 5-8 distinct internal resources very quickly (within 2-5 minutes), many not allowed for dept
    events = []
    current_time = base_time
    
    # Get all possible resources across all departments
    all_resources = list(set([res for sublist in RESOURCES_BY_DEPT.values() for res in sublist]))
    
    # Select 5 unique resources (including some non-allowed)
    target_resources = random.sample(all_resources, 5)
    
    for res in target_resources:
        current_time += timedelta(seconds=random.randint(10, 45))
        events.append({
            "timestamp": current_time.isoformat(),
            "username": profile["username"],
            "ip_address": get_random_ip(profile["home_ip_prefix"]),
            "user_agent": profile["device"]["ua"],
            "os": profile["device"]["os"],
            "browser": profile["device"]["browser"],
            "mac_address": profile["mac_address"],
            "resource_accessed": res,
            "status": "success",
            "label": "Lateral Movement"
        })
        
    return events
