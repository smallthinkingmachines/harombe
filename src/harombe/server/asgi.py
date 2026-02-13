"""ASGI entry point for running harombe server via uvicorn CLI.

Used by `harombe start --detach` to launch the server as a subprocess:
    python -m uvicorn harombe.server.asgi:app --host ... --port ...
"""

from harombe.config.loader import load_config
from harombe.server.app import create_app

config = load_config()
app = create_app(config)
