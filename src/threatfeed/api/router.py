"""Single router mounted by the application."""

from fastapi import APIRouter

from threatfeed.api import analyze, health, indicators, stats

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(indicators.router)
api_router.include_router(stats.router)
api_router.include_router(analyze.router)
