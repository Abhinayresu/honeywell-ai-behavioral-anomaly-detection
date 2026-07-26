"""
Concept Drift Detection.
Calculates Population Stability Index (PSI) to detect drift in access pattern features.
"""
import numpy as np

def calculate_psi(expected: np.ndarray, actual: np.ndarray, num_buckets: int = 10) -> float:
    """
    Calculate the Population Stability Index (PSI) between expected (training)
    and actual (production) distribution arrays.
    
    PSI < 0.1: No significant change
    PSI 0.1 - 0.25: Moderate change
    PSI > 0.25: Significant change (drift detected)
    """
    # Remove NaNs
    expected = expected[~np.isnan(expected)]
    actual = actual[~np.isnan(actual)]
    
    if len(expected) == 0 or len(actual) == 0:
        return 0.0

    # Determine bin quantiles based on expected dataset
    percentiles = np.linspace(0, 100, num_buckets + 1)
    buckets = np.percentile(expected, percentiles)
    # Deduplicate buckets in case data has low variance
    buckets = np.unique(buckets)
    if len(buckets) < 2:
        # Not enough variance to compute buckets
        return 0.0
        
    # Calculate counts in each bucket
    expected_counts, _ = np.histogram(expected, bins=buckets)
    actual_counts, _ = np.histogram(actual, bins=buckets)
    
    # Convert to fractions with Laplace smoothing to avoid division by zero
    expected_pct = (expected_counts + 1e-4) / (len(expected) + 1e-4 * len(expected_counts))
    actual_pct = (actual_counts + 1e-4) / (len(actual) + 1e-4 * len(actual_counts))
    
    # Calculate PSI
    psi_value = np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct))
    return float(psi_value)
