"""Utility functions for flow statistics."""

from typing import List, Dict, Any


def get_statistics(values: List[float]) -> Dict[str, float]:
    """Calculate statistics (mean, std, min, max, total) from a list of values.
    
    Args:
        values: List of numeric values
        
    Returns:
        Dictionary with 'mean', 'std', 'min', 'max', 'total' keys
    """
    if not values:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "total": 0.0}
    
    total = sum(values)
    mean = total / len(values)
    
    if len(values) == 1:
        std = 0.0
    else:
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = variance ** 0.5
    
    return {
        "mean": mean,
        "std": std,
        "min": min(values),
        "max": max(values),
        "total": total,
    }

