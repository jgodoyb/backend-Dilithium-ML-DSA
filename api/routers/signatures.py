"""Router para firmas digitales post-cuánticas ML-DSA (FIPS 204).

Implementa endpoints para firma individual, verificación individual (JSON / multipart)
y verificación por lotes para firmas PAdES multicapa con optimización anti-N+1 Zero-Trust.
"""

import base64
from fastapi import APIRouter, Depends, HTTPException, Request

from api import dependencies as deps
from api.dependencies import limiter, get_current_user
from api.schemas.signatures import (
    BatchVerifyRequest,
    SignPayload,
    VerifyPayload,
    get_sign_payload,
    get_verify_payload,
    parse_hash_to_bytes,
    sign_openapi_extra,
    verify_openapi_extra,
)
from mldsa.mldsa import hash_sign, hash_verify, hash_sign_digest, hash_verify_digest

router = APIRouter(prefix="/api", tags=["Signatures"])


@router.post("/sign", openapi_extra=sign_openapi_extra, summary="Firmar documento digitalmente (ML-DSA)")
@limiter.limit("10/minute")
async def sign_document(
    request: Request,
    payload: SignPayload = Depends(get_sign_payload),
    auth_data: dict = Depends(get_current_user),
):
    """Firma un documento o su hash SHA-256 utilizando la clave privada ML-DSA del usuario autenticado."""
    try:
        user_id = auth_data["payload"].get("sub")
        token = auth_data["token"]

        if not user_id:
            raise HTTPException(status_code=401, detail="Token missing subject claim")

        # Inyecta seguridad: cliente autenticado de Supabase para RLS
        user_supabase = deps.get_supabase_client(token=token)
        if not user_supabase:
            raise HTTPException(status_code=500, detail="Database client not configured")

        res = (
            user_supabase.table("crypto_identities")
            .select("private_key")
            .eq("user_id", user_id)
            .single()
            .execute()
        )
        if not res.data or "private_key" not in res.data:
            raise HTTPException(status_code=404, detail="Private key not found")

        private_key = res.data["private_key"]
        sk_bytes = base64.b64decode(private_key)

        if payload.document_hash:
            ph_m = parse_hash_to_bytes(payload.document_hash)
            signature_bytes = hash_sign_digest(sk=sk_bytes, ph_m=ph_m, ph_algo="SHA-256", ctx=b"Q-Proof")
        elif payload.file_bytes:
            signature_bytes = hash_sign(sk=sk_bytes, M=payload.file_bytes, ph_algo="SHA-256", ctx=b"Q-Proof")
        else:
            raise HTTPException(status_code=400, detail="Either 'document_hash' or 'file' must be provided.")

        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")
        return {"signature_b64": signature_b64}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[SIGN ERROR]: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify", openapi_extra=verify_openapi_extra, summary="Verificar firma digital (ML-DSA)")
@limiter.limit("10/minute")
async def verify_document(
    request: Request,
    payload: VerifyPayload = Depends(get_verify_payload),
):
    """Verifica la autenticidad e integridad de una firma digital ML-DSA dada la clave pública."""
    try:
        try:
            pk_bytes = base64.b64decode(payload.public_key_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid Base64 public_key")

        if payload.document_hash:
            ph_m = parse_hash_to_bytes(payload.document_hash)
            is_valid = hash_verify_digest(
                pk=pk_bytes,
                ph_m=ph_m,
                sigma=payload.signature_bytes,
                ph_algo="SHA-256",
                ctx=b"Q-Proof",
            )
        elif payload.file_bytes:
            is_valid = hash_verify(
                pk=pk_bytes,
                M=payload.file_bytes,
                sigma=payload.signature_bytes,
                ph_algo="SHA-256",
                ctx=b"Q-Proof",
            )
        else:
            raise HTTPException(status_code=400, detail="Either 'document_hash' or 'file' must be provided.")

        return {"is_valid": is_valid}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[VERIFY ERROR]: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify-batch", summary="Verificación en lote de firmas multicapa")
@limiter.limit("10/minute")
async def verify_batch(request: Request, body: BatchVerifyRequest):
    """Verifica en lote firmas digitales sobre múltiples capas de un documento (PAdES),

    consultando de forma optimizada en Supabase para evitar el problema de consultas N+1.
    """
    supabase = deps.get_shared_supabase()
    if not supabase:
        raise HTTPException(status_code=500, detail="Database client not configured")

    # Optimización Anti N+1: Extraer signer_ids únicos y consultar en lote
    unique_signer_ids = list({item.signer_id for item in body.validations if item.signer_id})
    identities_map = {}

    if unique_signer_ids:
        try:
            res = (
                supabase.table("crypto_identities")
                .select("user_id, public_key")
                .in_("user_id", unique_signer_ids)
                .execute()
            )
            if res.data and isinstance(res.data, list):
                identities_map = {
                    row["user_id"]: row["public_key"]
                    for row in res.data
                    if "user_id" in row and "public_key" in row and row["public_key"]
                }
        except Exception as e:
            print(f"[VERIFY BATCH DB ERROR]: {str(e)}")

    results = []
    for item in body.validations:
        try:
            # Búsqueda O(1) en memoria (Zero-Trust)
            public_key_b64 = identities_map.get(item.signer_id)
            if not public_key_b64:
                results.append({"layer": item.layer, "is_valid": False, "error": "Identity not found"})
                continue

            pk_bytes = base64.b64decode(public_key_b64)
            signature_bytes = bytes.fromhex(item.signature_hex)
            ph_m = parse_hash_to_bytes(item.document_hash)

            # Verificación criptográfica Post-Cuántica ML-DSA con contexto Q-Proof
            is_valid = hash_verify_digest(
                pk=pk_bytes,
                ph_m=ph_m,
                sigma=signature_bytes,
                ph_algo="SHA-256",
                ctx=b"Q-Proof",
            )
            results.append({"layer": item.layer, "is_valid": bool(is_valid)})
        except Exception as e:
            print(f"[VERIFY BATCH ERROR] Layer {item.layer}: {str(e)}")
            results.append({"layer": item.layer, "is_valid": False})

    return {"results": results}
