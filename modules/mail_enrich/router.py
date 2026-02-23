from fastapi import APIRouter
from modules.mail_enrich.services import get_email_report

router = APIRouter()

@router.get("/mail")
def enrich_email(email: str):
    return get_email_report(email)