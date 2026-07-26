import random
import uuid

# Pre-defined user profiles database template for generation
DEPARTMENTS = ["Engineering", "HR", "Sales", "Finance", "Legal", "Operations", "Admin"]

RESOURCES_BY_DEPT = {
    "Engineering": ["code_repository", "internal_wiki", "public_dashboard"],
    "HR": ["hr_database", "internal_wiki", "public_dashboard"],
    "Sales": ["billing_gateway", "public_dashboard", "internal_wiki"],
    "Finance": ["billing_gateway", "hr_database", "internal_wiki"],
    "Legal": ["internal_wiki"],
    "Operations": ["admin_console", "public_dashboard", "internal_wiki"],
    "Admin": ["admin_console", "code_repository", "hr_database", "billing_gateway", "internal_wiki", "public_dashboard"]
}

LOCATIONS = [
    {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060, "ip_prefix": "192.168.10"},
    {"city": "London", "country": "GB", "lat": 51.5074, "lon": -0.1278, "ip_prefix": "192.168.20"},
    {"city": "Bangalore", "country": "IN", "lat": 12.9716, "lon": 77.5946, "ip_prefix": "192.168.30"},
    {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503, "ip_prefix": "192.168.40"},
    {"city": "Berlin", "country": "DE", "lat": 52.5200, "lon": 13.4050, "ip_prefix": "192.168.50"}
]

USER_AGENTS = [
    {"browser": "Chrome", "os": "Windows", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"},
    {"browser": "Safari", "os": "macOS", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"},
    {"browser": "Firefox", "os": "Linux", "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"},
    {"browser": "Edge", "os": "Windows", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"}
]

class UserProfileManager:
    def __init__(self, num_users=50):
        self.profiles = {}
        self.num_users = num_users
        self._generate_profiles()

    def _generate_profiles(self):
        # Generate stable user profiles
        names = ["alice", "bob", "charlie", "david", "emma", "frank", "grace", "helen", "ian", "jack", 
                 "kate", "leo", "mia", "noah", "olivia", "peter", "quinn", "rachel", "sam", "tina",
                 "ulf", "val", "wendy", "xander", "yara", "zach"]
        
        # If we need more than names, we can append numbers
        usernames = []
        for i in range(self.num_users):
            base_name = names[i % len(names)]
            suffix = f"_{i // len(names)}" if i >= len(names) else ""
            usernames.append(f"{base_name}{suffix}")

        for username in usernames:
            dept = random.choice(DEPARTMENTS)
            location = random.choice(LOCATIONS)
            device = random.choice(USER_AGENTS)
            
            # Working hour window (e.g. start hour and duration)
            start_hour = random.choice([8, 9, 10])
            work_duration = 8
            
            self.profiles[username] = {
                "username": username,
                "department": dept,
                "allowed_resources": RESOURCES_BY_DEPT[dept],
                "home_location": location,
                "home_ip_prefix": location["ip_prefix"],
                "device": device,
                "mac_address": f"{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}",
                "working_hours": (start_hour, start_hour + work_duration),
                "avg_request_rate": random.uniform(2.0, 8.0) # Requests per hour
            }

    def get_profile(self, username):
        return self.profiles.get(username)

    def get_all_profiles(self):
        return list(self.profiles.values())
