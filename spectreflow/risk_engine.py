def calculate_risk(dynamic_result: dict, static_features: dict) -> int:
    score = 0

    if dynamic_result.get("cpu_spike"):
        score += 3
    if dynamic_result.get("network_activity"):
        score += 4
    if dynamic_result.get("file_activity"):
        score += 2
    score += len(dynamic_result.get("flagged_functions", [])) * 2

    if static_features.get("complexity", 0) > 20:
        score += 2
    if static_features.get("loop_count", 0) > 3:
        score += 2
    if static_features.get("branch_factor", 0) > 1.5:
        score += 1
    if static_features.get("suspicious_density", 0) > 0.1:
        score += 4

    return score


def classify(score: int) -> str:
    if score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    return "LOW"
