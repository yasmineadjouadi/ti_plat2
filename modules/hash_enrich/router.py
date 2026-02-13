from fastapi import APIRouter, Query
from .services import virustotal_hash

router = APIRouter(prefix="/hash", tags=["Hash Enrichment"])

@router.get("/")
def enrich_hash(param: str = Query(..., description="Hash value to enrich")):
    """
    Endpoint pour enrichir un hash via VirusTotal.
    Exemple: /hash?param=44d88612fea8a8f36de82e1278abb02f
    """
    vt_data = virustotal_hash(param)
    return {
        "hash": param,
        "vendors": {
            "virustotal": vt_data
        }
    }
