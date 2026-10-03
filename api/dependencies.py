"""Dependencias globales y configuración de seguridad para la API Q-Proof.

Gestiona clientes de infraestructura (Supabase, SlowAPI Limiter, JWKS Client)
y la dependencia de autenticación de usuarios get_current_user para evitar
importaciones circulares entre routers y main.
"""

import os
import sys
from pathlib import Path
from datetime import timedelta
from typing import Annotated, Optional

# Asegurar que el directorio raíz del proyecto esté en sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import jwt
from dotenv import load_dotenv

load_dotenv()

from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter
from slowapi.util import get_remote_address

try:
    from supabase import create_client, Client, ClientOptions
except Exception:
    create_client = None
    Client = None
    ClientOptions = None

# ==============================================================================
# Configuración de Entorno y Rate Limiting
# ==============================================================================

ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
limiter = Limiter(key_func=get_remote_address, enabled=RATE_LIMIT_ENABLED)

# ==============================================================================
# Configuración del Cliente Supabase y Claves JWKS
# ==============================================================================

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
SUPABASE_JWKS_URL = os.environ.get("SUPABASE_JWKS_URL", "")

if create_client and SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase: Optional[Client] = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"[SUPABASE INIT ERROR]: {e}")
        supabase = None
else:
    supabase = None

security = HTTPBearer()
jwks_client = jwt.PyJWKClient(SUPABASE_JWKS_URL, cache_keys=True) if SUPABASE_JWKS_URL else None


def get_shared_supabase() -> Optional[Client]:
    """Obtiene el cliente global de Supabase, respetando mocks inyectados en api.main o en este módulo."""
    main_mod = sys.modules.get("api.main")
    if main_mod and hasattr(main_mod, "supabase") and main_mod.supabase is not None:
        return main_mod.supabase
    return supabase


def get_supabase_client(token: Optional[str] = None):
    """Crea o retorna un cliente Supabase autenticado con el token Bearer para RLS."""
    main_mod = sys.modules.get("api.main")
    fn = getattr(main_mod, "create_client", None) or create_client
    opts_cls = getattr(main_mod, "ClientOptions", None) or ClientOptions

    if fn is None:
        return None

    if token and opts_cls:
        options = opts_cls(headers={"Authorization": f"Bearer {token}"})
        return fn(SUPABASE_URL, SUPABASE_KEY, options=options)
    return fn(SUPABASE_URL, SUPABASE_KEY)


# ==============================================================================
# Dependencia de Autenticación de Usuarios
# ==============================================================================

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(security)]
) -> dict:
    """Verifica el token JWT del usuario contra el JWKS de Supabase.

    Permite bypass para pruebas si ENVIRONMENT == 'test'.
    """
    current_env = os.environ.get("ENVIRONMENT", ENVIRONMENT).lower()
    if current_env == "test":
        return {
            "payload": {"sub": "test-user-123", "aud": "authenticated", "email": "test@qproof.com"},
            "token": "dummy-token",
        }

    token = credentials.credentials
    try:
        if not jwks_client:
            raise HTTPException(status_code=500, detail="JWKS client not configured")

        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            key=signing_key.key,
            algorithms=["ES256", "RS256"],
            audience="authenticated",
            leeway=timedelta(seconds=10),
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
