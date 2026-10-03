import os
import sys

# Asegurar que el directorio raíz del proyecto esté en sys.path para resolución limpia de paquetes ('mldsa', 'api')
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import base64
import jwt
from datetime import timedelta
from typing import Annotated, List, Optional
from dotenv import load_dotenv

load_dotenv()  # Cargar .env ANTES de cualquier os.environ.get()

from fastapi import FastAPI, Depends, UploadFile, HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from supabase import create_client, Client, ClientOptions

from mldsa.mldsa import keygen, hash_sign, hash_verify, hash_sign_digest, hash_verify_digest

app = FastAPI(
    title="Q-Proof Dilithium ML-DSA API",
    description="API de firma y verificación post-cuántica ML-DSA (FIPS 204)",
    version="1.0.0"
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configuración de Entorno y CORS Dinámico
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()
FRONTEND_URL = os.environ.get("FRONTEND_URL", "")

# Procesar orígenes permitidos desde el .env limpiando espacios y barras finales
env_origins = [origin.strip().rstrip("/") for origin in FRONTEND_URL.split(",") if origin.strip()]

if ENVIRONMENT == "production":
    # Dominio oficial de producción y fallbacks necesarios
    default_prod_origins = [
        "https://www.qproofsystems.es",
        "https://qproofsystems.es",
        "https://front-dilithium-ml-dsa.vercel.app"
    ]
    allowed_origins = list(set(default_prod_origins + env_origins))
    allowed_regex = None  # En producción NO se aceptan conexiones desde localhost
else:
    # Entorno de desarrollo / pruebas
    default_dev_origins = [
        "http://localhost:8080",
        "http://localhost:5173",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:5173"
    ]
    allowed_origins = list(set(default_dev_origins + env_origins))
    allowed_regex = r"http://(localhost|127\.0\.0\.1):\d+"

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=allowed_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "online", "message": "Dilithium ML-DSA API is running"}

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
SUPABASE_JWKS_URL = os.environ.get("SUPABASE_JWKS_URL", "")

if SUPABASE_URL and SUPABASE_KEY:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
else:
    supabase = None

security = HTTPBearer()
jwks_client = jwt.PyJWKClient(SUPABASE_JWKS_URL, cache_keys=True)

async def get_current_user(credentials: Annotated[HTTPAuthorizationCredentials, Security(security)]) -> dict:
    if ENVIRONMENT == "test":
        return {"payload": {"sub": "test-user-123", "aud": "authenticated"}, "token": "dummy-token"}
    
    token = credentials.credentials
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            key=signing_key.key,
            algorithms=["ES256", "RS256"],
            audience="authenticated",
            leeway=timedelta(seconds=10)  # Tolera hasta 10s de desincronización de reloj
        )
        return {"payload": payload, "token": token}
        
    except jwt.ExpiredSignatureError as e:
        print(f"[AUTH DEBUG] Token expirado: {str(e)}")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidAudienceError as e:
        print(f"[AUTH DEBUG] Audiencia inválida: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid audience")
    except jwt.InvalidTokenError as e:
        print(f"[AUTH DEBUG] Token inválido ({type(e).__name__}): {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        print(f"[AUTH DEBUG] Error interno ({type(e).__name__}): {str(e)}")
        raise HTTPException(status_code=500, detail="Internal authentication error")

@app.post("/api/generate")
@limiter.limit("10/minute")
async def generate_keys(request: Request, auth_data: dict = Depends(get_current_user)):
    try:
        payload = auth_data["payload"]
        token = auth_data["token"]
        
        user_id = payload.get("sub")
        email = payload.get("email")  # Extraemos el email del token
        if not user_id:
            raise HTTPException(status_code=401, detail="Token missing subject claim")
            
        pk, sk = keygen()
        
        pk_b64 = base64.b64encode(pk).decode('utf-8')
        sk_b64 = base64.b64encode(sk).decode('utf-8')
        
        data = {
            "user_id": user_id,
            "email": email,      # Guardamos el email para búsquedas en verificación
            "public_key": pk_b64,
            "private_key": sk_b64
        }
        
        # INYECCIÓN DEL CONTEXTO DE SEGURIDAD PARA EL RLS
        options = ClientOptions(headers={"Authorization": f"Bearer {token}"})
        user_supabase = create_client(SUPABASE_URL, SUPABASE_KEY, options=options)
        
        # Inserción usando el cliente efímero
        user_supabase.table("crypto_identities").upsert(data).execute()
        
        return {"status": "success", "message": "Keys generated"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Helper para procesar hashes recibidos en hex de 64 caracteres o Base64
def parse_hash_to_bytes(hash_str: str) -> bytes:
    clean_hash = hash_str.strip()
    if len(clean_hash) == 64:
        try:
            return bytes.fromhex(clean_hash)
        except ValueError:
            pass
    try:
        decoded = base64.b64decode(clean_hash)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    raise HTTPException(
        status_code=400,
        detail="Invalid document_hash format. Must be a 64-character hex string or 32-byte Base64 string."
    )

# --- Esquemas Pydantic formales para peticiones JSON ---

class SignHashRequest(BaseModel):
    document_hash: str = Field(
        ...,
        description="Hash SHA-256 en formato hexadecimal (64 caracteres) o Base64 (32 bytes)"
    )

class VerifyHashRequest(BaseModel):
    document_hash: str = Field(..., description="Hash SHA-256 del documento")
    signature_b64: str = Field(..., description="Firma digital ML-DSA en Base64")
    public_key: str = Field(..., description="Clave pública ML-DSA del firmante en Base64")

class SignatureValidationItem(BaseModel):
    layer: int
    document_hash: str  # Hexadecimal SHA-256
    signature_hex: str  # Hexadecimal de la firma
    signer_id: str      # UUID del firmante

class BatchVerifyRequest(BaseModel):
    validations: List[SignatureValidationItem]

# --- Clases de Dominio e Inyección de Dependencias para Entradas Híbridas ---

class SignPayload:
    """Contenedor de datos de entrada desacoplado para /api/sign."""
    def __init__(self, document_hash: Optional[str] = None, file_bytes: Optional[bytes] = None):
        self.document_hash = document_hash
        self.file_bytes = file_bytes

async def get_sign_payload(request: Request) -> SignPayload:
    """
    Dependencia limpia para extraer datos de /api/sign tanto si vienen por
    JSON como por multipart/form-data, manteniendo estricta retrocompatibilidad.
    """
    content_type = request.headers.get("content-type", "").lower()

    # 1. Petición JSON puro
    if "application/json" in content_type:
        try:
            body = await request.json()
            validated = SignHashRequest.model_validate(body)
            return SignPayload(document_hash=validated.document_hash)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid JSON payload: {str(e)}")

    # 2. Petición multipart/form-data o form-urlencoded
    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        file_item = form.get("file")
        doc_hash = form.get("document_hash")

        file_bytes = None
        if hasattr(file_item, "read"):
            file_bytes = await file_item.read()
        elif isinstance(file_item, bytes):
            file_bytes = file_item

        target_hash = str(doc_hash).strip() if (doc_hash is not None and not hasattr(doc_hash, "read")) else None
        if not target_hash and not file_bytes:
            raise HTTPException(status_code=400, detail="Either 'document_hash' or 'file' must be provided.")

        return SignPayload(document_hash=target_hash, file_bytes=file_bytes)

    # 3. Fallback defensivo para clientes con Content-Type ausente o alternativo
    try:
        body = await request.json()
        if isinstance(body, dict) and "document_hash" in body:
            validated = SignHashRequest.model_validate(body)
            return SignPayload(document_hash=validated.document_hash)
    except Exception:
        pass

    try:
        form = await request.form()
        file_item = form.get("file")
        doc_hash = form.get("document_hash")
        file_bytes = await file_item.read() if hasattr(file_item, "read") else None
        target_hash = str(doc_hash).strip() if (doc_hash is not None and not hasattr(doc_hash, "read")) else None
        if target_hash or file_bytes:
            return SignPayload(document_hash=target_hash, file_bytes=file_bytes)
    except Exception:
        pass

    raise HTTPException(status_code=400, detail="Either 'document_hash' or 'file' must be provided.")


class VerifyPayload:
    """Contenedor de datos de entrada desacoplado para /api/verify."""
    def __init__(
        self,
        public_key_b64: str,
        document_hash: Optional[str] = None,
        signature_bytes: Optional[bytes] = None,
        file_bytes: Optional[bytes] = None
    ):
        self.public_key_b64 = public_key_b64
        self.document_hash = document_hash
        self.signature_bytes = signature_bytes
        self.file_bytes = file_bytes

async def get_verify_payload(request: Request) -> VerifyPayload:
    """
    Dependencia limpia para extraer datos de /api/verify tanto si vienen por
    JSON como por multipart/form-data, manteniendo estricta retrocompatibilidad.
    """
    content_type = request.headers.get("content-type", "").lower()

    # 1. Petición JSON puro
    if "application/json" in content_type:
        try:
            body = await request.json()
            validated = VerifyHashRequest.model_validate(body)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid JSON payload: {str(e)}")

        if not validated.public_key:
            raise HTTPException(status_code=400, detail="Missing public_key")
        if not validated.signature_b64:
            raise HTTPException(status_code=400, detail="Missing signature or signature_b64")
        if not validated.document_hash:
            raise HTTPException(status_code=400, detail="Either 'document_hash' or 'file' must be provided.")

        try:
            sig_bytes = base64.b64decode(validated.signature_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid Base64 signature_b64")

        return VerifyPayload(
            public_key_b64=validated.public_key,
            document_hash=validated.document_hash,
            signature_bytes=sig_bytes
        )

    # 2. Petición multipart/form-data o form-urlencoded
    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        public_key = form.get("public_key")
        document_hash = form.get("document_hash")
        signature_b64 = form.get("signature_b64")
        file_item = form.get("file")
        sig_item = form.get("signature")

        target_pk = str(public_key).strip() if (public_key is not None and not hasattr(public_key, "read")) else None
        target_hash = str(document_hash).strip() if (document_hash is not None and not hasattr(document_hash, "read")) else None
        target_sig_b64 = str(signature_b64).strip() if (signature_b64 is not None and not hasattr(signature_b64, "read")) else None

        if not target_pk:
            raise HTTPException(status_code=400, detail="Missing public_key")

        sig_bytes = None
        if target_sig_b64:
            try:
                sig_bytes = base64.b64decode(target_sig_b64)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid Base64 signature_b64")
        elif hasattr(sig_item, "read"):
            sig_bytes = await sig_item.read()
        elif isinstance(sig_item, bytes):
            sig_bytes = sig_item
        else:
            raise HTTPException(status_code=400, detail="Missing signature or signature_b64")

        file_bytes = None
        if hasattr(file_item, "read"):
            file_bytes = await file_item.read()
        elif isinstance(file_item, bytes):
            file_bytes = file_item

        if not target_hash and not file_bytes:
            raise HTTPException(status_code=400, detail="Either 'document_hash' or 'file' must be provided.")

        return VerifyPayload(
            public_key_b64=target_pk,
            document_hash=target_hash,
            signature_bytes=sig_bytes,
            file_bytes=file_bytes
        )

    # 3. Fallback defensivo JSON
    try:
        body = await request.json()
        validated = VerifyHashRequest.model_validate(body)
        sig_bytes = base64.b64decode(validated.signature_b64)
        return VerifyPayload(
            public_key_b64=validated.public_key,
            document_hash=validated.document_hash,
            signature_bytes=sig_bytes
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Missing required verification parameters or invalid format")


# --- Configuración OpenAPI para Documentación Interactiva en Swagger UI ---

sign_openapi_extra = {
    "requestBody": {
        "content": {
            "application/json": {
                "schema": SignHashRequest.model_json_schema()
            },
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "file": {
                            "type": "string",
                            "format": "binary",
                            "description": "Documento PDF a firmar digitalmente"
                        },
                        "document_hash": {
                            "type": "string",
                            "description": "Hash hexadecimal de 64 caracteres o Base64 de 32 bytes (alternativa a subir archivo)"
                        }
                    }
                }
            }
        }
    }
}

verify_openapi_extra = {
    "requestBody": {
        "content": {
            "application/json": {
                "schema": VerifyHashRequest.model_json_schema()
            },
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "public_key": {
                            "type": "string",
                            "description": "Clave pública del firmante en Base64"
                        },
                        "document_hash": {
                            "type": "string",
                            "description": "Hash SHA-256 del documento"
                        },
                        "signature_b64": {
                            "type": "string",
                            "description": "Firma digital en Base64"
                        },
                        "file": {
                            "type": "string",
                            "format": "binary",
                            "description": "Archivo PDF original"
                        },
                        "signature": {
                            "type": "string",
                            "format": "binary",
                            "description": "Archivo binario de firma (.sig)"
                        }
                    },
                    "required": ["public_key"]
                }
            }
        }
    }
}


@app.post("/api/sign", openapi_extra=sign_openapi_extra)
@limiter.limit("10/minute")
async def sign_document(
    request: Request,
    payload: SignPayload = Depends(get_sign_payload),
    auth_data: dict = Depends(get_current_user)
):
    try:
        user_id = auth_data["payload"].get("sub")
        token = auth_data["token"]
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Token missing subject claim")
            
        # Inyecta seguridad: cliente autenticado de Supabase para RLS
        options = ClientOptions(headers={"Authorization": f"Bearer {token}"})
        user_supabase = create_client(SUPABASE_URL, SUPABASE_KEY, options=options)
        
        res = user_supabase.table("crypto_identities").select("private_key").eq("user_id", user_id).single().execute()
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
            
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
        return {"signature_b64": signature_b64}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"[SIGN ERROR]: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/verify", openapi_extra=verify_openapi_extra)
@limiter.limit("10/minute")
async def verify_document(
    request: Request,
    payload: VerifyPayload = Depends(get_verify_payload)
):
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
                ctx=b"Q-Proof"
            )
        elif payload.file_bytes:
            is_valid = hash_verify(
                pk=pk_bytes,
                M=payload.file_bytes,
                sigma=payload.signature_bytes,
                ph_algo="SHA-256",
                ctx=b"Q-Proof"
            )
        else:
            raise HTTPException(status_code=400, detail="Either 'document_hash' or 'file' must be provided.")

        return {"is_valid": is_valid}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[VERIFY ERROR]: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/verify-batch")
@limiter.limit("10/minute")
async def verify_batch(request: Request, body: BatchVerifyRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database client not configured")

    # Optimización Anti N+1: Extraer signer_ids únicos y consultar en lote
    unique_signer_ids = list({item.signer_id for item in body.validations if item.signer_id})
    identities_map = {}

    if unique_signer_ids:
        try:
            res = supabase.table("crypto_identities").select("user_id, public_key").in_("user_id", unique_signer_ids).execute()
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
                ctx=b"Q-Proof"
            )
            results.append({"layer": item.layer, "is_valid": bool(is_valid)})
        except Exception as e:
            print(f"[VERIFY BATCH ERROR] Layer {item.layer}: {str(e)}")
            results.append({"layer": item.layer, "is_valid": False})

    return {"results": results}


if __name__ == "__main__":
    import uvicorn
    # Si se ejecuta directamente el archivo, asegurar que la raíz del proyecto esté en sys.path
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)