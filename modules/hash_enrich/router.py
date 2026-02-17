from fastapi import APIRouter, Query
from modules.hash_enrich.services import get_hash_report
from fastapi.responses import JSONResponse
import json


router = APIRouter(
    prefix="/hash",
    tags=["Hash Enrichment"]
)

@router.get("/")
def hash_lookup(param: str = Query(..., description="Hash value to enrich")):
    report = get_hash_report(param)

    
    formatted = {
        "Hash": report["hash"],
        "File Type": report["file_type"],
        "Reputation Score": report["reputation_score"],
        "Detection": {
            "Malicious": report["detection"]["malicious"],
            "Suspicious": report["detection"]["suspicious"],
            "Undetected": report["detection"]["undetected"]
        },
        "Last Analysis Date": report["last_analysis_date"],
        "Risk": {
            "Score": report["risk_score"],
            "Level": report["risk_level"]
        },
        "OTX": report["otx"],
        "Global Risk": {
            "Score": report["global_risk_score"],
            "Level": report["global_risk_level"],
            "Confidence": report["confidence"]
        }
    }

    return JSONResponse(
    content=json.loads(json.dumps(formatted, indent=4)),
    media_type="application/json"
)