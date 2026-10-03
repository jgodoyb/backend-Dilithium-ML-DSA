"""Módulo de esquemas de datos Pydantic para la API Q-Proof.

Exporta esquemas unificados para firmas digitales ML-DSA (FIPS 204)
y cifrado híbrido poscuántico ML-KEM (FIPS 203 + AES-256-GCM).
"""

from api.schemas.signatures import (
    SignHashRequest,
    VerifyHashRequest,
    SignatureValidationItem,
    BatchVerifyRequest,
    SignPayload,
    VerifyPayload,
    get_sign_payload,
    get_verify_payload,
    parse_hash_to_bytes,
    sign_openapi_extra,
    verify_openapi_extra,
)
from api.schemas.encryption import (
    SecurityLevel,
    KeygenRequest,
    KeygenResponse,
    HybridEncryptRequest,
    HybridEncryptResponse,
    HybridDecryptRequest,
    HybridDecryptResponse,
)

__all__ = [
    # Signatures (ML-DSA)
    "SignHashRequest",
    "VerifyHashRequest",
    "SignatureValidationItem",
    "BatchVerifyRequest",
    "SignPayload",
    "VerifyPayload",
    "get_sign_payload",
    "get_verify_payload",
    "parse_hash_to_bytes",
    "sign_openapi_extra",
    "verify_openapi_extra",
    # Encryption (ML-KEM)
    "SecurityLevel",
    "KeygenRequest",
    "KeygenResponse",
    "HybridEncryptRequest",
    "HybridEncryptResponse",
    "HybridDecryptRequest",
    "HybridDecryptResponse",
]
