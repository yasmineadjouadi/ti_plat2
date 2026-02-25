from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

# ------------------------------
# Routers depuis modules
# ------------------------------
from modules.hash_enrich.services import get_hash_report
from modules.hash_enrich.router import router as hash_router
from modules.dashboard.router import router as dashboard_router
from modules.domain_enrich.routers.domain_router import router as domain_router
from modules.ip_enrich.routers.ip_router import router as ip_router


# ------------------------------
# DB
# ------------------------------
from database.db import engine, init_db
from database import models

# ------------------------------
# Création de l'application FastAPI
# ------------------------------
app = FastAPI(
    title="Threat Intelligence Platform",
    description="Plateforme TI pour enrichissement de hash, domaines, IP et emails",
    version="1.0"
)

# ------------------------------
# Création des tables au démarrage
# ------------------------------
init_db()  # crée toutes les tables définies dans models.py

# ------------------------------
# Inclusion des routers
# ------------------------------
app.include_router(hash_router, prefix="/hash", tags=["Hash Enrichment"])
app.include_router(domain_router, prefix="/domain", tags=["Domain Enrichment"])
app.include_router(ip_router, prefix="/ip", tags=["IP Reputation"])
# app.include_router(mail_router, prefix="/mail", tags=["Email Enrichment"])  # si mail router
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])

# ------------------------------
# Route racine / Health
# ------------------------------
@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "message": "Threat Intelligence Platform is running"}

# ------------------------------
# Exemple route pour scanner un hash
# ------------------------------
@app.get("/scan/", tags=["Hash Enrichment"])
def scan_hash(param: str = Query(..., description="Hash value to enrich")):
    result = get_hash_report(param)

    if "error" in result:
        return JSONResponse(
            content={"error": result["error"]},
            status_code=400
        )

    return JSONResponse(
        content=result,
        status_code=200
    )