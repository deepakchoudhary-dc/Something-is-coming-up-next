"""
AI Security Gateway - Main Application
A centralized defense layer for securing AI-driven interactions.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
from .gateway.router import router as gateway_router
from .monitoring.logger import setup_logging
from .config.settings import settings

# Setup logging
setup_logging()

# Initialize database
from .monitoring.database import init_db
init_db()

app = FastAPI(
    title="AI Security Gateway",
    description="Enterprise-grade AI Security Gateway for monitoring and securing AI interactions",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(gateway_router, prefix="/api/v1", tags=["gateway"])

# Mount static files and serve dashboard
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def root():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

