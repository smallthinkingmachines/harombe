"""FastAPI application factory."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from harombe import __version__
from harombe.config.schema import HarombeConfig
from harombe.server.routes import create_router


def create_app(config: HarombeConfig) -> FastAPI:
    """Create and configure FastAPI application.

    Args:
        config: Harombe configuration

    Returns:
        Configured FastAPI app
    """
    app = FastAPI(
        title="Harombe",
        description="Declarative self-hosted AI assistant platform",
        version=__version__,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routes
    router = create_router(config)
    app.include_router(router)

    return app
