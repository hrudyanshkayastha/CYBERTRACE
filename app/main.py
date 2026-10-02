"""
CYBERTRACE - Main Application Entrypoint
FastAPI application serving both REST API endpoints and the Dark SOC Web Dashboard.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from app.config import BASE_DIR, DATA_DIR, REPORTS_DIR, SAMPLES_DIR
from app.database.db import init_db
from app.api.routes import router as api_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle management."""
    # Ensure all essential directories exist
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    # Initialize SQLite database schema
    init_db()
    yield

app = FastAPI(
    title="CYBERTRACE",
    description="Security Incident Detection & Investigation System",
    version="1.0.0",
    lifespan=lifespan
)

# Static and Template mounts
UI_DIR = Path(__file__).resolve().parent / "ui"
STATIC_DIR = UI_DIR / "static"
TEMPLATES_DIR = UI_DIR / "templates"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Include API Router
app.include_router(api_router)

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Returns empty response to satisfy browser favicon request without 404."""
    return Response(status_code=204)

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serves the primary Single-Page SOC Dashboard."""
    return templates.TemplateResponse(request=request, name="index.html")
