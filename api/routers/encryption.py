"""Router para cifrado híbrido poscuántico ML-KEM (FIPS 203) y AES-256-GCM.

Implementa los endpoints para generación de claves, cifrado de payloads (encapsulación + AES-GCM)
y descifrado con validación de autenticidad e integridad.
"""

import base64
from typing import Dict
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Body, HTTPException, Request, status

from api.dependencies import limiter
from api.schemas.encryption import (
    KeygenRequest,
    KeygenResponse,
    HybridEncryptRequest,
    HybridEncryptResponse,
    HybridDecryptRequest,
    HybridDecryptResponse,
)
from mlkem.crypto.hybrid import HybridPQC
from mlkem.parameters.params import (
    MLKEMParameters,
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
)

# Mapeo de parámetros para niveles de seguridad FIPS 203
PARAMS_MAP: Dict[int, MLKEMParameters] = {
    512: ML_KEM_512,
    768: ML_KEM_768,
    1024: ML_KEM_1024,
}

router = APIRouter(tags=["Encryption"])


@router.post(
    "/keygen",
    response_model=KeygenResponse,
    summary="Generar par de claves ML-KEM",
)
@router.post(
    "/api/keygen",
    response_model=KeygenResponse,
    include_in_schema=False,
)
@limiter.limit("10/minute")
async def keygen_endpoint(
    request: Request,
    payload: KeygenRequest = Body(default_factory=KeygenRequest),
) -> KeygenResponse:
    """Genera un par de claves (ek, dk) según FIPS 203 para el nivel de seguridad seleccionado."""
    params = PARAMS_MAP.get(payload.security_level, ML_KEM_768)
    hybrid = HybridPQC(params)
    ek, dk = hybrid.keygen()

    return KeygenResponse(
        ek_b64=base64.b64encode(ek).decode("ascii"),
        dk_b64=base64.b64encode(dk).decode("ascii"),
        security_level=payload.security_level,
    )


@router.post(
    "/encrypt",
    response_model=HybridEncryptResponse,
    summary="Cifrado Híbrido Poscuántico (ML-KEM + AES-256-GCM)",
)
@router.post(
    "/api/encrypt",
    response_model=HybridEncryptResponse,
    include_in_schema=False,
)
@limiter.limit("10/minute")
async def hybrid_encrypt_endpoint(
    request: Request,
    payload: HybridEncryptRequest,
) -> HybridEncryptResponse:
    """Cifra un mensaje mediante encapsulación ML-KEM y cifrado simétrico autenticado AES-256-GCM."""
    params = PARAMS_MAP.get(payload.security_level, ML_KEM_768)
    hybrid = HybridPQC(params)
    ek = payload.get_ek_bytes()

    plaintext_bytes = payload.plaintext.encode("utf-8")

    try:
        result = hybrid.encrypt_payload(ek, plaintext_bytes)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return HybridEncryptResponse(
        capsule_b64=base64.b64encode(result["capsule"]).decode("ascii"),
        nonce_b64=base64.b64encode(result["nonce"]).decode("ascii"),
        ciphertext_b64=base64.b64encode(result["ciphertext"]).decode("ascii"),
    )


@router.post(
    "/decrypt",
    response_model=HybridDecryptResponse,
    summary="Descifrado y Verificación Híbrida",
)
@router.post(
    "/api/decrypt",
    response_model=HybridDecryptResponse,
    include_in_schema=False,
)
@limiter.limit("10/minute")
async def hybrid_decrypt_endpoint(
    request: Request,
    payload: HybridDecryptRequest,
) -> HybridDecryptResponse:
    """Desencapsula la clave compartida con ML-KEM y descifra/autentica el payload con AES-256-GCM."""
    params = PARAMS_MAP.get(payload.security_level, ML_KEM_768)
    hybrid = HybridPQC(params)
    dk = payload.get_dk_bytes()
    capsule = payload.get_capsule_bytes()
    nonce = payload.get_nonce_bytes()
    ciphertext = payload.get_ciphertext_bytes()

    try:
        plaintext_bytes = hybrid.decrypt_payload(
            dk=dk,
            capsule=capsule,
            nonce=nonce,
            ciphertext=ciphertext,
        )
    except InvalidTag:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decryption failed: integrity check failed",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    try:
        plaintext_str = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext_str = base64.b64encode(plaintext_bytes).decode("ascii")

    return HybridDecryptResponse(plaintext=plaintext_str)
