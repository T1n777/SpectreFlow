import logging

logger = logging.getLogger("spectreflow.risk")

WEIGHT_DYNAMIC   = 10
WEIGHT_STATIC    = 5
WEIGHT_PE        = 10
WEIGHT_HASH      = 10
WEIGHT_STRINGS   = 5
WEIGHT_YARA      = 5
WEIGHT_VT        = 10

MAX_SCORE = (WEIGHT_DYNAMIC + WEIGHT_STATIC + WEIGHT_PE
             + WEIGHT_HASH + WEIGHT_STRINGS + WEIGHT_YARA + WEIGHT_VT)


def calculate_risk(dynamic_result, static_features, pe_result=None,
                   hash_result=None, yara_matches=None, vt_result=None):
    breakdown = {
        "dynamic_score": 0,
        "static_score": 0,
        "pe_score": 0,
        "hash_score": 0,
        "strings_score": 0,
        "yara_score": 0,
        "vt_score": 0,
    }

    ds = 0
    if dynamic_result.get("suspicious"):
        ds += 3
    if dynamic_result.get("cpu_spike"):
        ds += 2
    if dynamic_result.get("suspicious_connections"):
        ds += 3
    if dynamic_result.get("suspicious_file_write"):
        ds += 1
    if dynamic_result.get("sensitive_dir_write"):
        ds += 1
    breakdown["dynamic_score"] = min(ds, WEIGHT_DYNAMIC)

    ss = 0
    complexity = static_features.get("complexity", 0)
    if complexity > 50:
        ss += 3
    elif complexity > 20:
        ss += 1
    density = static_features.get("suspicious_density", 0)
    if density > 0.5:
        ss += 2
    elif density > 0.2:
        ss += 1
    breakdown["static_score"] = min(ss, WEIGHT_STATIC)

    ps = 0
    if pe_result:
        findings = pe_result.get("findings", [])
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")
        ps = critical * 4 + high * 2 + medium * 1
    breakdown["pe_score"] = min(ps, WEIGHT_PE)

    hs = 0
    if hash_result and hash_result.get("found"):
        hs = WEIGHT_HASH
    breakdown["hash_score"] = hs

    sts = 0
    if pe_result:
        pe_strings = pe_result.get("suspicious_strings", [])
        if len(pe_strings) >= 5:
            sts = 5
        elif len(pe_strings) >= 2:
            sts = 3
        elif pe_strings:
            sts = 1
    breakdown["strings_score"] = min(sts, WEIGHT_STRINGS)

    ys = 0
    if yara_matches:
        ys = min(len(yara_matches) * 2, WEIGHT_YARA)
    breakdown["yara_score"] = ys

    vs = 0
    if vt_result and vt_result.get("found"):
        ratio = vt_result.get("detection_ratio", 0)
        if ratio > 0.50:
            vs = 10
        elif ratio > 0.25:
            vs = 7
        elif ratio > 0.10:
            vs = 4
        elif vt_result.get("malicious_count", 0) > 0:
            vs = 2
    breakdown["vt_score"] = vs

    total = sum(breakdown.values())
    breakdown["total"] = total
    breakdown["max_possible"] = MAX_SCORE

    logger.info("Risk breakdown: %s  total=%d/%d", breakdown, total, MAX_SCORE)
    return breakdown


def classify(score_breakdown):
    total = score_breakdown["total"]
    if total >= 25:
        return "HIGH"
    elif total >= 12:
        return "MEDIUM"
    return "LOW"
