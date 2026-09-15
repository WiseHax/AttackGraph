"""FastAPI application entry point.

Phase 1: Only a /health endpoint. Domain API routes are Phase 7.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler.

    Database initialization is handled by Alembic migrations.
    This lifespan hook is reserved for future startup/shutdown tasks.
    """
    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(
        title="AttackGraph",
        description=(
            "Defensive cybersecurity platform for modeling authorized "
            "environments as security relationships and analyzing "
            "potential attack paths toward critical assets."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    @application.get("/health")
    async def health_check():
        """Basic health check endpoint."""
        return JSONResponse(
            status_code=200,
            content={"status": "healthy", "version": "0.1.0"},
        )

    return application


app = create_app()
