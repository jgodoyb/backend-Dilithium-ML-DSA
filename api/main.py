import os
import sys

# Permitir importar módulos desde el directorio raíz (como 'mldsa')
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import base64
import jwt
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()  # Cargar .env ANTES de cualquier os.environ.get()
from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, Security, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client, ClientOptions
from typing import Annotated

from mldsa.mldsa import keygen, hash_sign, hash_verify

app = FastAPI()

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
            algorithms=["ES256", "RS256"], #Mirar esto
            audience="authenticated",
            leeway=timedelta(seconds=10)  # Tolera hasta 10s de desincronización de reloj
        )
        # DEVOLVEMOS AMBAS COSAS AQUÍ
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
async def generate_keys(auth_data: dict = Depends(get_current_user)):
    try:
        payload = auth_data["payload"]
        token = auth_data["token"]
        
        user_id = payload.get("sub")
        email = payload.get("email") # Extraemos el email del token
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

@app.post("/api/sign")
async def sign_document(
    file: UploadFile = File(...),
    token_payload: dict = Depends(get_current_user)
):
    try:
        user_id = token_payload["payload"].get("sub")
        token = token_payload["token"]
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Token missing subject claim")
            
        # Inyecta seguridad: cliente autenticado de Supabase para RLS
        options = ClientOptions(headers={"Authorization": f"Bearer {token}"})
        user_supabase = create_client(SUPABASE_URL, SUPABASE_KEY, options=options)
        
        # Obtener clave de forma segura del servidor
        res = user_supabase.table("crypto_identities").select("private_key").eq("user_id", user_id).single().execute()
        if not res.data or "private_key" not in res.data:
            raise HTTPException(status_code=404, detail="Private key not found")
            
        private_key = res.data["private_key"]
        
        # Decodificamos la clave obtenida localmente
        sk_bytes = base64.b64decode(private_key)
        
        pdf_bytes = await file.read()
        
        # Generar firma
        signature_bytes = hash_sign(sk=sk_bytes, M=pdf_bytes, ph_algo="SHA-256", ctx=b"Q-Proof")
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
        
        return {"signature_b64": signature_b64}
        
    except Exception as e:
        print(f"[SIGN ERROR]: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/verify")
@limiter.limit("10/minute")
async def verify_document(
    request: Request,
    file: UploadFile = File(...),
    signature: UploadFile = File(...), # Recibe el archivo .sig
    public_key: str = Form(...)        # Recibe la clave del autor desde el front
):
    try:
        # Decodificamos la clave pública (Base64 -> Bytes)
        pk_bytes = base64.b64decode(public_key)
        
        # Leemos la firma (Bytes del archivo .sig)
        signature_bytes = await signature.read()
        
        # Leemos el PDF
        pdf_bytes = await file.read()
        
        # Verificar integridad
        is_valid = hash_verify(pk=pk_bytes, M=pdf_bytes, sigma=signature_bytes, ph_algo="SHA-256", ctx=b"Q-Proof")
        
        return {"is_valid": is_valid}
        
    except Exception as e:
        print(f"[VERIFY ERROR]: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)