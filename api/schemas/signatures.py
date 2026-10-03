"""Esquemas Pydantic y utilidades de carga útil para firmas digitales ML-DSA (FIPS 204)."""

import base64
from typing import List, Optional
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field


# ==============================================================================
# Helpers de Procesamiento de Hashes
# ==============================================================================

def parse_hash_to_bytes(hash_str: str) -> bytes:
    """Procesa hashes recibidos en formato hexadecimal de 64 caracteres o Base64 de 32 bytes."""
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


# ==============================================================================
# Modelos Pydantic para Peticiones JSON
# ==============================================================================

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


# ==============================================================================
# Clases de Dominio e Inyección de Dependencias para Entradas Híbridas
# ==============================================================================

class SignPayload:
    """Contenedor de datos de entrada desacoplado para /api/sign."""
    def __init__(self, document_hash: Optional[str] = None, file_bytes: Optional[bytes] = None):
        self.document_hash = document_hash
        self.file_bytes = file_bytes


async def get_sign_payload(request: Request) -> SignPayload:
    """Dependencia limpia para extraer datos de /api/sign tanto si vienen por
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
    """Dependencia limpia para extraer datos de /api/verify tanto si vienen por
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


# ==============================================================================
# Configuración OpenAPI para Documentación Interactiva en Swagger UI
# ==============================================================================

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
