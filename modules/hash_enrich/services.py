import requests
import os
from dotenv import load_dotenv

# Charger les variables d'environnement depuis .env
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")  # Ta clé VirusTotal

def virustotal_hash(hash_value: str):
    """
    Interroge VirusTotal pour obtenir les informations sur un hash.
    """
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not found in .env"}

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "reputation": attrs.get("reputation", 0),
            "last_analysis_stats": attrs.get("last_analysis_stats", {})
        }
    except Exception as e:
        return {"error": str(e)}
