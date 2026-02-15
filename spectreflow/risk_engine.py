MAX_RISK_SCORE = 50


def calculate_risk(dynamic_result, static_features, pe_result=None, hash_result=None):
    score = 0

    if hash_result and hash_result.get("known_malware"):
        score += 10

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

    if pe_result:
        if not pe_result.get("signed"):
            score += 1

        for finding in pe_result.get("findings", []):
            sev = finding.get("severity", "")
            if sev == "critical":
                score += 4
            elif sev == "high":
                score += 3
            elif sev == "medium":
                score += 1

        api_count = len(pe_result.get("suspicious_imports", []))
        score += min(api_count * 2, 6)

    return min(score, MAX_RISK_SCORE)


def classify(score):
    if score >= 18:
        return "HIGH"
    if score >= 8:
        return "MEDIUM"
    return "LOW"
