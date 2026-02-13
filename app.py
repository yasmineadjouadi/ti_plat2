from fastapi import FastAPI
from modules.hash_enrich.router import router as hash_router

app = FastAPI(
    title="Threat Intelligence Platform",
    description="Plateforme pour enrichissement de hash via VirusTotal",
    version="1.0"
)

@app.get("/", tags=["Home"])
def home():
    return {"status": "running"}

# Inclure le router du module hash
app.include_router(hash_router)
