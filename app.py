from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from modules.hash_enrich.router import router as hash_router
from modules.dashboard.router import router as dashboard_router
from modules.hash_enrich.services import get_hash_report
from database.db import engine
from database import models

# ------------------------------
# App FastAPI
# ------------------------------
app = FastAPI(
    title="Threat Intelligence Platform",
    description="Plateforme pour enrichissement de hash via VirusTotal",
    version="1.0"
)

templates = Jinja2Templates(directory="templates")

# ------------------------------
# Inclure les routers
# ------------------------------
app.include_router(hash_router)
app.include_router(dashboard_router)

# ------------------------------
# Page d'accueil (index.html)
# ------------------------------
@app.get("/", response_class=HTMLResponse, tags=["Home"])
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# ------------------------------
# Scan depuis la page Home
# ------------------------------
@app.post("/scan", response_class=HTMLResponse)
def scan_hash(request: Request, hash_value: str = Form(...)):
    result = get_hash_report(hash_value)
    
    if "error" in result:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": "Hash not found or API error"}
        )
    
    return templates.TemplateResponse(
        "result.html",
        {"request": request, "data": result}
    )

# ------------------------------
# Création des tables
# ------------------------------
models.Base.metadata.create_all(bind=engine)
