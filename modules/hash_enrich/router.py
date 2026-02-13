from fastapi import APIRouter, Query
from .services import virustotal_hash

router = APIRouter(prefix="/hash", tags=["Hash Enrichment"])

@router.get("/")
def enrich_hash(param: str = Query(..., description="Hash value to enrich")):
    
    vt_data = virustotal_hash(param)
    return {
        "hash": param,
        "vendors": {
            "virustotal": vt_data
        }
    }
