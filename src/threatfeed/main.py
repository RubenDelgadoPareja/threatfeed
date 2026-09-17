"""FastAPI application entry point (~ config/application.rb + routes.rb, for now)."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI


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


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe: the process is up and answering HTTP."""
    return {"status": "ok"}


# INTERVIEW: FastAPI runs plain `def` endpoints in a threadpool, so synchronous DB calls do not
# block the event loop; `async def` endpoints must never do blocking I/O.
