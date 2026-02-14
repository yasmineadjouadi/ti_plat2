import requests
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

OTX_API_KEY = os.getenv("OTX_API_KEY")

def calculate_risk(malicious, suspicious, reputation):

    score = (malicious * 5) + (suspicious * 3) + abs(reputation)

    if score == 0:
        level = "Clean"
    elif score <= 20:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    else:
        level = "High"

    return level, score
def calculate_global_risk(vt_malicious, vt_suspicious, otx_score, otx_rep):

    vt_component = (vt_malicious * 4) + (vt_suspicious * 2)
    otx_component = (otx_score * 5) + abs(otx_rep)

    global_score = vt_component + otx_component

    if global_score == 0:
        level = "Clean"
    elif global_score <= 50:
        level = "Low"
    elif global_score <= 150:
        level = "Medium"
    else:
        level = "High"

    # Confidence logic
    if vt_malicious > 0 and otx_score > 0:
        confidence = "Strong"
    elif vt_malicious > 0 or otx_score > 0:
        confidence = "Moderate"
    else:
        confidence = "Weak"

    return global_score, level, confidence

def otx_hash_enrichment(file_hash):
    
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return {"otx_error": "Not found or API error"}

    data = response.json()

    return {
        "otx_name": data.get("name", "N/A"),
        "otx_malware_families": data.get("malware_families", []),
        "otx_reputation": data.get("reputation", 0),
        "otx_general_score": data.get("general_score", 0)
    }

def get_hash_report(file_hash):

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return {"error": "Hash not found or API error"}

    data = response.json()["data"]["attributes"]

    stats = data.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    risk_level, risk_score = calculate_risk(
        malicious,
        suspicious,
        data.get("reputation", 0)
    )

    otx_data = otx_hash_enrichment(file_hash)

    global_score, global_level, confidence = calculate_global_risk(
        malicious,
        suspicious,
        otx_data.get("otx_general_score", 0),
        otx_data.get("otx_reputation", 0)
    )

    last_analysis_timestamp = data.get("last_analysis_date")
    last_analysis_date = (
        datetime.utcfromtimestamp(last_analysis_timestamp).strftime("%Y-%m-%d")
        if last_analysis_timestamp
        else "N/A"
    )

    return {
        "hash": file_hash,
        "file_type": data.get("type_description", "Unknown"),
        "reputation_score": data.get("reputation", 0),
        "detection": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected
        },
        "last_analysis_date": last_analysis_date,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "otx": otx_data,
        "global_risk_score": global_score,
        "global_risk_level": global_level,
        "confidence": confidence
    }

