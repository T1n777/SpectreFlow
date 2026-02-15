import hashlib
import logging

import requests

logger = logging.getLogger("spectreflow.hash_lookup")

MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
TIMEOUT = 10


def compute_hashes(binary_path):
    with open(binary_path, "rb") as f:
        data = f.read()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def lookup_malwarebazaar(sha256):
    logger.info("Checking hash against MalwareBazaar: %s...", sha256[:16])
    try:
        resp = requests.post(
            MALWAREBAZAAR_API,
            data={"query": "get_info", "hash": sha256},
            headers={"API-KEY": "", "User-Agent": "SpectreFlow"},
            timeout=TIMEOUT,
        )
        result = resp.json()

        if result.get("query_status") == "hash_not_found":
            logger.info("Hash not found in MalwareBazaar")
            return {"known_malware": False}

        if result.get("query_status") == "ok" and result.get("data"):
            entry = result["data"][0]
            info = {
                "known_malware": True,
                "malware_family": entry.get("signature") or "Unknown",
                "tags": entry.get("tags") or [],
                "first_seen": entry.get("first_seen") or "Unknown",
                "file_type": entry.get("file_type") or "Unknown",
            }
            logger.info("KNOWN MALWARE: family=%s, tags=%s",
                         info["malware_family"], info["tags"])
            return info

        logger.info("Unexpected MalwareBazaar response: %s", result.get("query_status"))
        return {"known_malware": False}

    except requests.ConnectionError:
        logger.warning("MalwareBazaar unreachable — skipping hash lookup")
        return {"known_malware": False, "error": "API unreachable"}
    except requests.Timeout:
        logger.warning("MalwareBazaar request timed out")
        return {"known_malware": False, "error": "Request timed out"}
    except Exception as e:
        logger.warning("Hash lookup failed: %s", e)
        return {"known_malware": False, "error": str(e)}


def check_hash(binary_path):
    hashes = compute_hashes(binary_path)
    result = lookup_malwarebazaar(hashes["sha256"])
    result["md5"] = hashes["md5"]
    result["sha256"] = hashes["sha256"]
    return result
