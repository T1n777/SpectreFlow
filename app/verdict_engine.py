import logging

logger = logging.getLogger("spectreflow.verdict")

VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_LIKELY_SAFE = "LIKELY SAFE"
VERDICT_CLEAN = "CLEAN"


def render_verdict(result, score_breakdown, pe_result=None, hash_result=None,
                   vt_result=None):
    reasons = []
    verdict = None
    confidence = 0.0
    total = score_breakdown.get("total", 0)

    if hash_result and hash_result.get("found"):
        reasons.append(
            f"File hash matched known malware in threat database "
            f"(SHA-256: {hash_result.get('sha256', '?')[:16]}…)"
        )
        verdict = VERDICT_MALICIOUS
        confidence = 0.99

    yara_matches = result.get("yara_matches", [])
    if yara_matches:
        rules = ", ".join(yara_matches[:5])
        reasons.append(f"YARA rules matched: {rules}")
        if verdict != VERDICT_MALICIOUS:
            verdict = VERDICT_SUSPICIOUS
            confidence = max(confidence, 0.80)

    if pe_result:
        findings = pe_result.get("findings", [])
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]

        if critical:
            for f in critical[:3]:
                reasons.append(f"Critical PE finding: {f['indicator']} — {f.get('detail', '')}")
            if verdict != VERDICT_MALICIOUS:
                verdict = VERDICT_MALICIOUS
                confidence = max(confidence, 0.90)

        if high:
            for f in high[:3]:
                reasons.append(f"High-severity PE finding: {f['indicator']} — {f.get('detail', '')}")
            if verdict is None:
                if total > 15:
                    verdict = VERDICT_SUSPICIOUS
                    confidence = max(confidence, 0.70)
                else:
                    verdict = VERDICT_LIKELY_SAFE
                    confidence = max(confidence, 0.50)
                    reasons.append("Note: Static anomalies detected (e.g. packing), but behavioral score is low.")

        pe_strings = pe_result.get("suspicious_strings", [])
        if pe_strings:
            categories = set()
            for s in pe_strings:
                categories.add(s.get("category", "unknown"))
            reasons.append(
                f"{len(pe_strings)} suspicious strings found "
                f"(categories: {', '.join(sorted(categories))})"
            )
            if verdict is None:
                if total > 15:
                    verdict = VERDICT_SUSPICIOUS
                    confidence = max(confidence, 0.55)
                else:
                    verdict = VERDICT_LIKELY_SAFE
                    confidence = max(confidence, 0.45)

    vt_found = vt_result and vt_result.get("found")
    vt_ratio = vt_result.get("detection_ratio", 0) if vt_result else 0
    vt_malicious = vt_result.get("malicious_count", 0) if vt_result else 0
    vt_total = vt_result.get("total_engines", 0) if vt_result else 0
    vt_label = vt_result.get("threat_label") if vt_result else None

    if vt_found and vt_malicious > 0:
        reasons.append(
            f"VirusTotal: {vt_malicious}/{vt_total} engines flagged as malicious "
            f"({vt_result.get('detection_pct', '?')})"
        )
        if vt_label:
            reasons.append(f"VirusTotal threat label: {vt_label}")

        if vt_ratio > 0.50:
            verdict = VERDICT_MALICIOUS
            confidence = max(confidence, 0.96)
        elif vt_ratio > 0.25:
            verdict = VERDICT_MALICIOUS
            confidence = max(confidence, 0.88)
        elif vt_ratio > 0.10:
            if verdict != VERDICT_MALICIOUS:
                verdict = VERDICT_SUSPICIOUS
                confidence = max(confidence, 0.75)
        else:
            if verdict not in (VERDICT_MALICIOUS,):
                verdict = VERDICT_SUSPICIOUS
                confidence = max(confidence, 0.55)

    dynamic = result
    dyn_signals = []
    if dynamic.get("cpu_spike"):
        dyn_signals.append("abnormal CPU usage detected")
    if dynamic.get("suspicious_connections"):
        conns = dynamic["suspicious_connections"]
        dyn_signals.append(f"{len(conns)} suspicious network connection(s)")
    if dynamic.get("suspicious_file_write"):
        dyn_signals.append("suspicious file(s) written to disk")
    if dynamic.get("sensitive_dir_write"):
        dyn_signals.append("wrote to sensitive system directory")
    flagged = dynamic.get("flagged_functions", [])
    if flagged:
        dyn_signals.append(f"flagged behaviors: {', '.join(flagged)}")

    if dyn_signals:
        for sig in dyn_signals:
            reasons.append(f"Dynamic analysis: {sig}")
        if verdict is None:
            if len(dyn_signals) >= 3:
                verdict = VERDICT_SUSPICIOUS
                confidence = max(confidence, 0.70)
            elif len(dyn_signals) >= 1:
                verdict = VERDICT_SUSPICIOUS
                confidence = max(confidence, 0.50)

    total = score_breakdown.get("total", 0)
    max_score = score_breakdown.get("max_possible", 55)

    if verdict is None:
        if total >= 25:
            verdict = VERDICT_SUSPICIOUS
            confidence = max(confidence, 0.60)
        elif total >= 12:
            verdict = VERDICT_LIKELY_SAFE
            confidence = max(confidence, 0.65)
            reasons.append("Minor indicators present but no strong malicious signals.")
        else:
            verdict = VERDICT_CLEAN
            confidence = 0.85
            if vt_found and vt_malicious == 0:
                confidence = 0.95
                reasons.append("VirusTotal: 0 engines flagged — confirmed clean.")
            else:
                reasons.append("No malicious indicators detected.")

    if verdict == VERDICT_LIKELY_SAFE and vt_found and vt_malicious == 0:
        confidence = max(confidence, 0.90)
        reasons.append("VirusTotal: 0 engines flagged — supports safety assessment.")

    if not reasons:
        reasons.append("Analysis complete — no indicators found.")

    summary = _build_summary(verdict, confidence, reasons, result, hash_result,
                              vt_result=vt_result)

    confidence_pct = f"{confidence * 100:.0f}%"

    return {
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "confidence_pct": confidence_pct,
        "risk_score": total,
        "max_risk_score": max_score,
        "reasons": reasons,
        "summary": summary,
    }


def _build_summary(verdict, confidence, reasons, result, hash_result,
                    vt_result=None):
    pct = f"{confidence * 100:.0f}%"
    target = result.get("target_location") or "the analysed file"

    if verdict == VERDICT_MALICIOUS:
        if hash_result and hash_result.get("found"):
            return (
                f"This file is MALICIOUS ({pct} confidence). "
                f"Its hash matches a known threat in malware databases. "
                f"Do NOT execute this file — delete it immediately."
            )
        vt_str = ""
        if vt_result and vt_result.get("found") and vt_result.get("malicious_count", 0) > 0:
            vt_str = (
                f" VirusTotal confirms: {vt_result['malicious_count']}/{vt_result['total_engines']} "
                f"engines flag it as malicious."
            )
        return (
            f"This file is MALICIOUS ({pct} confidence). "
            f"Multiple analysis layers detected dangerous behavior.{vt_str} "
            f"Do NOT run this file."
        )

    if verdict == VERDICT_SUSPICIOUS:
        vt_str = ""
        if vt_result and vt_result.get("found") and vt_result.get("malicious_count", 0) > 0:
            vt_str = (
                f" VirusTotal shows {vt_result['malicious_count']}/{vt_result['total_engines']} "
                f"detections."
            )
        return (
            f"This file is SUSPICIOUS ({pct} confidence). "
            f"Some indicators suggest potentially harmful behavior.{vt_str} "
            f"Exercise caution — avoid running unless you trust the source."
        )

    if verdict == VERDICT_LIKELY_SAFE:
        vt_str = ""
        if vt_result and vt_result.get("found") and vt_result.get("malicious_count", 0) == 0:
            vt_str = " VirusTotal confirms 0 detections."
        return (
            f"This file appears LIKELY SAFE ({pct} confidence). "
            f"Minor indicators were found but nothing strongly malicious.{vt_str} "
            f"Probably safe, but verify the source."
        )

    vt_str = ""
    if vt_result and vt_result.get("found") and vt_result.get("malicious_count", 0) == 0:
        vt_str = " VirusTotal confirms 0 detections."
    return (
        f"This file appears CLEAN ({pct} confidence). "
        f"No malicious indicators were found.{vt_str}"
    )
