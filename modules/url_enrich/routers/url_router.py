from fastapi import APIRouter, Query
from modules.url_enrich.services.url_service import get_url_report

router = APIRouter(
    prefix="/url",
    tags=["URL Enrichment"]
)

@router.get("/")
def url_lookup(param: str = Query(..., description="URL to scan")):
    return get_url_report(param)