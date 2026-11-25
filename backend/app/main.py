"""Main FastAPI application entry point for CIPHERTRACE AI."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router as api_router
from app.api.routes import ws_router
from app.core.config import ensure_directories
from app.db.database import init_db
from app.lab.aitm_lab import router as lab_router
from app.services.inference_engine import engine
from app.services.live_sniffer import live_sniffer


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialize directories, database schema, and trained ML/DL artifacts."""
    ensure_directories()
    init_db(max_retries=5, retry_delay=2.0)
    engine.load_artifacts()
    try:
        yield
    finally:
        live_sniffer.stop()


app = FastAPI(
    title="CIPHERTRACE AI",
    description="Passive ML/DL Encrypted Traffic Threat Detection & Controlled AiTM Lab",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(ws_router)
app.include_router(lab_router)


@app.get("/")
async def root() -> dict[str, str]:
    """Root service metadata."""
    return {
        "service": "CIPHERTRACE AI",
        "docs": "/docs",
        "health": "/api/health",
        "lab_legit": "/lab/legit-portal",
        "lab_aitm": "/lab/aitm-proxy",
    }
