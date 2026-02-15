import hashlib
import logging
import time

import requests

logger = logging.getLogger("spectreflow.virustotal")

VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
TIMEOUT = 15


def compute_sha256(binary_path):
    with open(binary_path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()


def lookup_virustotal(sha256, api_key):
    if not api_key:
        logger.info("No VirusTotal API key configured — skipping VT lookup")
        return {"vt_available": False, "error": "No API key"}

    url = VT_API_URL.format(hash=sha256)
    headers = {"x-apikey": api_key, "User-Agent": "SpectreFlow"}

    logger.info("Querying VirusTotal for %s...", sha256[:16])

    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)

        if resp.status_code == 404:
            logger.info("File not found in VirusTotal database")
            return {
                "vt_available": True,
                "found": False,
                "sha256": sha256,
            }

        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit reached — retrying in 15s")
            time.sleep(15)
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)

        if resp.status_code != 200:
            logger.warning("VirusTotal returned HTTP %d", resp.status_code)
            return {
                "vt_available": False,
                "error": f"HTTP {resp.status_code}",
                "sha256": sha256,
            }

        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total_engines = malicious + suspicious + undetected + harmless

        detection_ratio = (malicious + suspicious) / max(total_engines, 1)

        flagged_engines = []
        for engine_name, engine_result in results.items():
            cat = engine_result.get("category", "")
            if cat in ("malicious", "suspicious"):
                flagged_engines.append({
                    "engine": engine_name,
                    "category": cat,
                    "result": engine_result.get("result", ""),
                })

        popular_threat = attrs.get("popular_threat_classification", {})
        threat_label = None
        if popular_threat:
            label_info = popular_threat.get("suggested_threat_label")
            if label_info:
                threat_label = label_info

        tags = attrs.get("tags", [])
        file_type = attrs.get("type_description", "")

        vt_result = {
            "vt_available": True,
            "found": True,
            "sha256": sha256,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "undetected_count": undetected,
            "harmless_count": harmless,
            "total_engines": total_engines,
            "detection_ratio": round(detection_ratio, 4),
            "detection_pct": f"{int(detection_ratio * 100)}%",
            "threat_label": threat_label,
            "tags": tags,
            "file_type": file_type,
            "flagged_engines": flagged_engines[:20],
        }

        if malicious > 0:
            logger.info(
                "VirusTotal: %d/%d engines flagged as malicious (%.0f%%)",
                malicious, total_engines, detection_ratio * 100,
            )
            if threat_label:
                logger.info("VirusTotal threat label: %s", threat_label)
        else:
            logger.info(
                "VirusTotal: 0/%d engines flagged — file appears clean",
                total_engines,
            )

        return vt_result

    except requests.ConnectionError:
        logger.warning("VirusTotal unreachable — skipping VT lookup")
        return {"vt_available": False, "error": "API unreachable", "sha256": sha256}
    except requests.Timeout:
        logger.warning("VirusTotal request timed out")
        return {"vt_available": False, "error": "Request timed out", "sha256": sha256}
    except Exception as e:
        logger.warning("VirusTotal lookup failed: %s", e)
        return {"vt_available": False, "error": str(e), "sha256": sha256}


def check_virustotal(binary_path, api_key):
    sha256 = compute_sha256(binary_path)
    return lookup_virustotal(sha256, api_key)
