"""
General utility and helper functions for feature engineering and pre-processing.
"""

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great circle distance in kilometers between two points
    on the earth (specified in decimal degrees).
    """
    pass

def calculate_speed(distance_km: float, time_difference_seconds: float) -> float:
    """
    Calculate travel speed in km/h.
    """
    pass

def parse_user_agent(ua_string: str) -> dict:
    """
    Parse OS and Browser information from raw User-Agent string.
    """
    pass
