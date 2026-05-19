import requests
from config import VT_API_KEY

VT_URL = "APIKEY"

def vt_lookup(sha256_hash: str) -> dict:
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(VT_URL + sha256_hash, headers=headers)
        if response.status_code != 200:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}"
            }

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "success": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "link": f"https://www.virustotal.com/gui/file/{sha256_hash}"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
