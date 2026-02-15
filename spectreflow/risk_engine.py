MAX_RISK_SCORE = 32


def calculate_risk(dynamic_result, static_features):
    score = 0

    if dynamic_result.get("cpu_spike"):
        score += 4

    suspicious_conns = dynamic_result.get("suspicious_connections", [])
    total_conns = dynamic_result.get("network_activity", [])
    if suspicious_conns:
        score += 5
        if len(suspicious_conns) >= 3:
            score += 2
    elif total_conns:
        score += 1

    if dynamic_result.get("sensitive_dir_write"):
        score += 5
    elif dynamic_result.get("suspicious_file_write"):
        score += 3
    elif dynamic_result.get("file_activity"):
        score += 1

    flagged = dynamic_result.get("flagged_functions", [])
    score += len(flagged) * 2

    if static_features.get("complexity", 0) > 20:
        score += 2
    if static_features.get("loop_count", 0) > 3:
        score += 2
    if static_features.get("branch_factor", 0) > 1.5:
        score += 1
    if static_features.get("suspicious_density", 0) > 0.1:
        score += 4

    return min(score, MAX_RISK_SCORE)


def classify(score):
    if score >= 12:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"
