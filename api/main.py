"""Q-Proof Unified Post-Quantum Cryptography API.

Servicio REST de producción de alta disponibilidad que unifica:
- Firmas digitales post-cuánticas ML-DSA (FIPS 204)
- Cifrado híbrido autenticado ML-KEM (FIPS 203) + AES-256-GCM
- Gestión unificada de identidad criptográfica con Supabase y RLS
"""

import os
import sys
from pathlib import Path

# Asegurar que el directorio raíz del proyecto esté en sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv

load_dotenv()

from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api.dependencies import (
    ClientOptions,
    ENVIRONMENT,
    SUPABASE_KEY,
    SUPABASE_URL,
    create_client,
    get_current_user,
    limiter,
    supabase,
)
from api.routers import encryption_router, identity_router, signatures_router

# ==============================================================================
# Instanciación y Metadatos Formales de OpenAPI
# ==============================================================================

app = FastAPI(
    title="Q-Proof Unified Post-Quantum Cryptography API",
    description="""
### API Criptográfica Post-Cuántica Unificada (FIPS 204 & FIPS 203)

Servicio REST de producción que proporciona primitivas post-cuánticas completas:
- **Firmas Digitales (ML-DSA / FIPS 204)**: Generación, firma digital (pura y pre-hash SHA-256) y verificación de documentos y firmas PAdES multicapa.
- **Cifrado Híbrido Autenticado (ML-KEM / FIPS 203 + AES-256-GCM)**: Encapsulación post-cuántica y cifrado simétrico autenticado (niveles 512, 768 y 1024).
- **Gestión de Identidades Criptográficas**: Generación y almacenamiento seguro en Supabase con Row Level Security (RLS).
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ==============================================================================
# Configuración de Rate Limiting
# ==============================================================================

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ==============================================================================
# Manejadores Globales de Excepciones Criptográficas
# ==============================================================================

@app.exception_handler(InvalidTag)
async def invalid_tag_exception_handler(request: Request, exc: InvalidTag):
    """Captura fallos de verificación de integridad en AES-GCM o manipulación de cápsula."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": "Decryption failed: integrity check failed"},
    )


@app.exception_handler(ValueError)
async def value_error_exception_handler(request: Request, exc: ValueError):
    """Captura validaciones matemáticas y de formato criptográfico."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


# ==============================================================================
# Configuración Dinámica de CORS
# ==============================================================================

FRONTEND_URL = os.environ.get("FRONTEND_URL", "")
env_origins = [
    origin.strip().rstrip("/")
    for origin in FRONTEND_URL.split(",")
    if origin.strip()
]

if ENVIRONMENT == "production":
    default_prod_origins = [
        "https://www.qproofsystems.es",
        "https://qproofsystems.es",
        "https://front-dilithium-ml-dsa.vercel.app",
    ]
    allowed_origins = list(dict.fromkeys(default_prod_origins + env_origins))
    allowed_regex = None
else:
    default_dev_origins = [
        "http://localhost:8080",
        "http://localhost:5173",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    allowed_origins = list(dict.fromkeys(default_dev_origins + env_origins))
    allowed_regex = r"http://(localhost|127\.0\.0\.1):\d+"

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=allowed_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# Registro de Routers Modulares
# ==============================================================================

app.include_router(identity_router)
app.include_router(signatures_router)
app.include_router(encryption_router)

# ==============================================================================
# Endpoint de Diagnóstico y Estado
# ==============================================================================

@app.get("/", tags=["Diagnóstico & Estado"])
async def root():
    """Reporta el estado operativo de los estándares criptográficos soportados (ML-DSA FIPS 204 y ML-KEM FIPS 203)."""
    return {
        "status": "online",
        "service": "Q-Proof Unified Post-Quantum Cryptography API",
        "version": "1.0.0",
        "standards": {
            "signatures": "ML-DSA (FIPS 204)",
            "key_exchange": "ML-KEM (FIPS 203)",
            "symmetric_cipher": "AES-256-GCM",
        },
        "supported_kem_levels": [512, 768, 1024],
        "message": "Dilithium ML-DSA (FIPS 204) and Kyber ML-KEM (FIPS 203) API is operational",
    }


# ==============================================================================
# Punto de Entrada Principal (Uvicorn)
# ==============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)