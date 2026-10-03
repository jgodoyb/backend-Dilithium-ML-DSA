"""Router para gestión de identidad criptográfica post-cuántica y generación unificada de claves."""

import base64
from fastapi import APIRouter, Depends, HTTPException, Request

from api import dependencies as deps
from api.dependencies import limiter, get_current_user
from mldsa.mldsa import keygen as dsa_keygen
from mlkem.crypto.hybrid import HybridPQC
from mlkem.parameters.params import ML_KEM_768

router = APIRouter(prefix="/api", tags=["Identity & Keys"])


@router.post("/generate", summary="Generar Identidad Post-Cuántica (ML-DSA + ML-KEM)")
@limiter.limit("10/minute")
async def generate_keys(
    request: Request,
    auth_data: dict = Depends(get_current_user),
):
    """Genera simultáneamente el par de claves ML-DSA (FIPS 204) y el par ML-KEM-768 (FIPS 203),

    almacenándolos en Supabase bajo el contexto de seguridad autenticado (RLS).
    """
    try:
        payload = auth_data["payload"]
        token = auth_data["token"]

        user_id = payload.get("sub")
        email = payload.get("email")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token missing subject claim")

        # 1. Par de claves ML-DSA (FIPS 204)
        dsa_pk, dsa_sk = dsa_keygen()
        dsa_pk_b64 = base64.b64encode(dsa_pk).decode("utf-8")
        dsa_sk_b64 = base64.b64encode(dsa_sk).decode("utf-8")

        # 2. Par de claves ML-KEM-768 (FIPS 203)
        hybrid_kem = HybridPQC(ML_KEM_768)
        kem_ek, kem_dk = hybrid_kem.keygen()
        kem_ek_b64 = base64.b64encode(kem_ek).decode("utf-8")
        kem_dk_b64 = base64.b64encode(kem_dk).decode("utf-8")

        data = {
            "user_id": user_id,
            "email": email,
            "public_key": dsa_pk_b64,
            "private_key": dsa_sk_b64,
            "kem_public_key": kem_ek_b64,
            "kem_private_key": kem_dk_b64,
            "kem_security_level": 768,
        }

        # Inyección del contexto de seguridad para RLS en Supabase
        user_supabase = deps.get_supabase_client(token=token)
        if not user_supabase:
            raise HTTPException(status_code=500, detail="Database client not configured")

        user_supabase.table("crypto_identities").upsert(data).execute()

        return {"status": "success", "message": "Keys generated (ML-DSA + ML-KEM)"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
