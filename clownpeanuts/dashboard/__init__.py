"""Dashboard API foundation."""

from .api import create_app
from .theater import TheaterService

__all__ = ["create_app", "TheaterService"]
