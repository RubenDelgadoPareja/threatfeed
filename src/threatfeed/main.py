"""FastAPI application entry point (~ config/application.rb + routes.rb, for now)."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from threatfeed.api.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown hooks. Starlette 1.x removed `on_event`; this is the only mechanism."""
    # Startup: nothing yet (phase 3 will warm caches and check connections here).
    yield
    # Shutdown: nothing yet.


app = FastAPI(
    title="ThreatFeed",
    description="Threat intelligence pipeline: aggregates public IoC feeds, serves them over REST.",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(api_router)
