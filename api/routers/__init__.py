"""Módulo de enrutadores para la API REST Q-Proof."""

from api.routers.identity import router as identity_router
from api.routers.signatures import router as signatures_router
from api.routers.encryption import router as encryption_router

__all__ = [
    "identity_router",
    "signatures_router",
    "encryption_router",
]
