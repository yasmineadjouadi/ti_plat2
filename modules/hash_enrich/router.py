from fastapi import APIRouter
from modules.hash_enrich.services import get_hash_report

router = APIRouter(
    prefix="/hash",
    tags=["Hash Enrichment"]
)

@router.get("/")
def hash_lookup(param: str):
    return get_hash_report(param)
