from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from modules.hash_enrich.services import get_hash_report
from modules.hash_enrich.router import router as hash_router
from modules.dashboard.router import router as dashboard_router
from database import models
from database.db import engine

# ------------------------------
# App FastAPI
# ------------------------------
app = FastAPI(
    title="Threat Intelligence Platform",
    description="Plateforme pour enrichissement de hash via VirusTotal",
    version="1.0"
)

# ------------------------------
# Route racine
# ------------------------------
@app.get("/", tags=["Main"])
def root():
    return {"message": "Platform is running"}

# ------------------------------
# Inclure les routers
# ------------------------------
app.include_router(hash_router)
app.include_router(dashboard_router)

# ------------------------------
# Création des tables
# ------------------------------
models.Base.metadata.create_all(bind=engine)

# ------------------------------
# Route principale pour scanner un hash (JSON uniquement)
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