"""Liveness probe."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    """The process is up and answering HTTP."""
    return {"status": "ok"}
